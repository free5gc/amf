package context

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/mohae/deepcopy"
	"github.com/sirupsen/logrus"

	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/ngap/ie"
	"github.com/free5gc/openapi/models"
)

type RelAction int

const (
	RanUeNgapIdUnspecified int64 = 0xffffffff
)

const (
	UeContextN2NormalRelease RelAction = iota
	UeContextReleaseHandover
	UeContextReleaseUeContext
	UeContextReleaseSupersededContext
)

type RanUe struct {
	/* UE identity*/
	RanUeNgapId int64
	AmfUeNgapId int64

	/* HandOver Info*/
	HandOverType        ie.HandoverType
	HandOverStartTime   time.Time
	SuccessPduSessionId []int32
	SourceUe            *RanUe
	TargetUe            *RanUe

	/* UserLocation*/
	Tai      models.Tai
	Location models.UserLocation
	/* context about udm */
	SupportVoPSn3gpp  bool
	SupportVoPS       bool
	SupportedFeatures string
	LastActTime       *time.Time

	/* Related Context*/
	AmfUe        *AmfUe
	Ran          *AmfRan
	HoldingAmfUe *AmfUe // The AmfUe that is already exist (CM-Idle, Re-Registration)

	/* Routing ID */
	RoutingID string
	/* Trace Recording Session Reference */
	Trsr string
	/* Ue Context Release Action */
	ReleaseAction RelAction
	/* context used for AMF Re-allocation procedure */
	OldAmfName            string
	InitialUEMessage      []byte
	RRCEstablishmentCause string // Received from initial ue message; pattern: ^[0-9a-fA-F]+$
	UeContextRequest      bool   // Receive UEContextRequest IE from RAN

	/* send initial context setup request or not*/
	InitialContextSetup bool

	/* logger */
	Log *logrus.Entry
}

func (ranUe *RanUe) Remove() error {
	if ranUe == nil {
		return fmt.Errorf("RanUe not found in RemoveRanUe")
	}
	ran := ranUe.Ran
	if ran == nil {
		return fmt.Errorf("RanUe not found in Ran")
	}
	if ranUe.AmfUe != nil {
		ranUe.AmfUe.DetachRanUe(ran.AnType)
		ranUe.DetachAmfUe()
	}

	ran.RanUeList.Delete(ranUe.RanUeNgapId)

	self := GetSelf()
	self.RanUePool.Delete(ranUe.AmfUeNgapId)
	amfUeNGAPIDGenerator.FreeID(ranUe.AmfUeNgapId)
	return nil
}

func (ranUe *RanUe) DetachAmfUe() {
	ranUe.AmfUe = nil
}

func (ranUe *RanUe) SwitchToRan(newRan *AmfRan, ranUeNgapId int64) error {
	if ranUe == nil {
		return fmt.Errorf("ranUe is nil")
	}

	if newRan == nil {
		return fmt.Errorf("newRan is nil")
	}

	oldRan := ranUe.Ran

	// remove ranUe from oldRan
	oldRan.RanUeList.Delete(ranUe.RanUeNgapId)

	// add ranUe to newRan
	newRan.RanUeList.Store(ranUeNgapId, ranUe)

	// switch to newRan
	ranUe.Ran = newRan
	ranUe.RanUeNgapId = ranUeNgapId

	// update log information
	ranUe.UpdateLogFields()

	logger.CtxLog.Infof("RanUe[RanUeNgapID: %d] Switch to new Ran[Name: %s]", ranUe.RanUeNgapId, ranUe.Ran.Name)
	return nil
}

func (ranUe *RanUe) UpdateLogFields() {
	if ranUe.Ran != nil && ranUe.Ran.Conn != nil {
		addr := ranUe.Ran.Conn.RemoteAddr()
		if addr != nil {
			ranUe.Log = ranUe.Log.WithField(logger.FieldRanAddr, addr.String())
		} else {
			ranUe.Log = ranUe.Log.WithField(logger.FieldRanAddr, "(nil)")
		}

		anTypeStr := ""
		switch ranUe.Ran.AnType {
		case models.AccessType_3_GPP_ACCESS:
			anTypeStr = "3GPP"
		case models.AccessType_NON_3_GPP_ACCESS:
			anTypeStr = "Non3GPP"
		}
		ranUe.Log = ranUe.Log.WithField(logger.FieldAmfUeNgapID,
			fmt.Sprintf("RU:%d,AU:%d(%s)", ranUe.RanUeNgapId, ranUe.AmfUeNgapId, anTypeStr))
	} else {
		ranUe.Log = ranUe.Log.WithField(logger.FieldRanAddr, "no ran conn")
		ranUe.Log = ranUe.Log.WithField(logger.FieldAmfUeNgapID, "RU:,AU:")
	}
}

func (ranUe *RanUe) UpdateLocation(userLocationInformation *ie.UserLocationInformation) {
	if userLocationInformation == nil {
		return
	}

	switch location := userLocationInformation.Choice.(type) {
	case *ie.UserLocationInformationEUTRA:
		ranUe.updateEutraLocation(location)
	case *ie.UserLocationInformationNR:
		ranUe.updateNRLocation(location)
	case *ie.UserLocationInformationN3IWF:
		ranUe.updateN3gaLocation(location.IPAddress, location.PortNumber)
	case *ie.ProtocolIESingleContainerUserLocationInformationExtIEs:
		extensions := location.UserLocationInformationExtIEs
		switch {
		case extensions.UserLocationInformationTNGF != nil:
			entry := extensions.UserLocationInformationTNGF
			ranUe.updateN3gaLocation(entry.IPAddress, entry.PortNumber)
		case extensions.UserLocationInformationTWIF != nil:
			entry := extensions.UserLocationInformationTWIF
			ranUe.updateN3gaLocation(entry.IPAddress, entry.PortNumber)
		case extensions.UserLocationInformationWAGF != nil:
			ranUe.Log.Debug("W-AGF user location is not mapped to an N3GA location")
		}
	default:
		ranUe.Log.Warnf("Unsupported user location choice %T", userLocationInformation.Choice)
	}
}

func (ranUe *RanUe) updateEutraLocation(location *ie.UserLocationInformationEUTRA) {
	if location == nil || location.TAI == nil || location.EUTRACGI == nil {
		return
	}
	if ranUe.Location.EutraLocation == nil {
		ranUe.Location.EutraLocation = new(models.EutraLocation)
	}

	tai := models.Tai{
		PlmnId: plmnIdentityToModels(location.TAI.PLMNIdentity),
	}
	if location.TAI.TAC != nil {
		tai.Tac = hex.EncodeToString(location.TAI.TAC.Value)
	}
	ranUe.Location.EutraLocation.Tai = &tai
	ranUe.Tai = tai

	ecgi := &models.Ecgi{PlmnId: plmnIdentityToModels(location.EUTRACGI.PLMNIdentity)}
	if location.EUTRACGI.EUTRACellIdentity != nil {
		ecgi.EutraCellId = bitStringToHex(location.EUTRACGI.EUTRACellIdentity.Value)
	}
	ranUe.Location.EutraLocation.Ecgi = ecgi
	ranUe.Location.EutraLocation.UeLocationTimestamp = locationTimestamp()
	if location.TimeStamp != nil {
		ranUe.Location.EutraLocation.AgeOfLocationInformation = timestampToInt32(location.TimeStamp)
	}
	ranUe.syncAmfUeLocation()
}

func (ranUe *RanUe) updateNRLocation(location *ie.UserLocationInformationNR) {
	if location == nil || location.TAI == nil || location.NRCGI == nil {
		return
	}
	if ranUe.Location.NrLocation == nil {
		ranUe.Location.NrLocation = new(models.NrLocation)
	}

	tai := models.Tai{
		PlmnId: plmnIdentityToModels(location.TAI.PLMNIdentity),
	}
	if location.TAI.TAC != nil {
		tai.Tac = hex.EncodeToString(location.TAI.TAC.Value)
	}
	ranUe.Location.NrLocation.Tai = &tai
	ranUe.Tai = tai

	ncgi := &models.Ncgi{PlmnId: plmnIdentityToModels(location.NRCGI.PLMNIdentity)}
	if location.NRCGI.NRCellIdentity != nil {
		ncgi.NrCellId = bitStringToHex(location.NRCGI.NRCellIdentity.Value)
	}
	ranUe.Location.NrLocation.Ncgi = ncgi
	ranUe.Location.NrLocation.UeLocationTimestamp = locationTimestamp()
	if location.TimeStamp != nil {
		ranUe.Location.NrLocation.AgeOfLocationInformation = timestampToInt32(location.TimeStamp)
	}
	ranUe.syncAmfUeLocation()
}

func (ranUe *RanUe) updateN3gaLocation(address *ie.TransportLayerAddress, port *ie.PortNumber) {
	if address == nil {
		return
	}
	if ranUe.Location.N3gaLocation == nil {
		ranUe.Location.N3gaLocation = new(models.N3gaLocation)
	}

	ranUe.Location.N3gaLocation.UeIpv4Addr, ranUe.Location.N3gaLocation.UeIpv6Addr = ipAddressToString(address)
	if port != nil && len(port.Value) == 2 {
		ranUe.Location.N3gaLocation.PortNumber = int32(binary.BigEndian.Uint16(port.Value))
	}
	amfSelf := GetSelf()
	if len(amfSelf.SupportTaiLists) == 0 {
		return
	}
	ranUe.Location.N3gaLocation.N3gppTai = &models.Tai{
		PlmnId: amfSelf.SupportTaiLists[0].PlmnId,
		Tac:    amfSelf.SupportTaiLists[0].Tac,
	}
	ranUe.Tai = deepcopy.Copy(*ranUe.Location.N3gaLocation.N3gppTai).(models.Tai)
	ranUe.syncAmfUeLocation()
}

func (ranUe *RanUe) syncAmfUeLocation() {
	if ranUe.AmfUe == nil {
		return
	}
	if ranUe.AmfUe.Tai != ranUe.Tai {
		ranUe.AmfUe.LocationChanged = true
	}
	ranUe.AmfUe.Location = deepcopy.Copy(ranUe.Location).(models.UserLocation)
	ranUe.AmfUe.Tai = deepcopy.Copy(ranUe.Tai).(models.Tai)
}

func locationTimestamp() *time.Time {
	now := time.Now().UTC()
	return &now
}

func timestampToInt32(timestamp *ie.TimeStamp) int32 {
	if timestamp == nil || len(timestamp.Value) != 4 {
		return 0
	}
	return int32(binary.BigEndian.Uint32(timestamp.Value))
}

func ipAddressToString(address *ie.TransportLayerAddress) (ipv4, ipv6 string) {
	if address == nil {
		return "", ""
	}
	bytes := address.Value.Bytes
	switch address.Value.BitLength {
	case 32:
		if len(bytes) >= net.IPv4len {
			return net.IPv4(bytes[0], bytes[1], bytes[2], bytes[3]).String(), ""
		}
	case 128:
		if len(bytes) >= net.IPv6len {
			return "", net.IP(bytes[:net.IPv6len]).String()
		}
	case 160:
		if len(bytes) >= net.IPv4len+net.IPv6len {
			return net.IPv4(bytes[0], bytes[1], bytes[2], bytes[3]).String(),
				net.IP(bytes[net.IPv4len : net.IPv4len+net.IPv6len]).String()
		}
	}
	return "", ""
}
