package context

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/ngap/aper"
	"github.com/free5gc/ngap/ie"
	"github.com/free5gc/openapi/models"
)

const (
	RanPresentGNbId   = 1
	RanPresentNgeNbId = 2
	RanPresentN3IwfId = 3
	RanPresentTngfId  = 4
	RanPresentTwifId  = 5
	RanPresentWagfId  = 6
)

type AmfRan struct {
	RanPresent int
	RanId      *models.GlobalRanNodeId
	Name       string
	AnType     models.AccessType
	/* socket Connect*/
	Conn net.Conn
	/* Supported TA List */
	SupportedTAList []SupportedTAI

	/* RAN UE List */
	RanUeList sync.Map // RanUeNgapId as key

	/* logger */
	Log *logrus.Entry
}

type SupportedTAI struct {
	Tai        models.Tai
	SNssaiList []models.Snssai
}

func NewSupportedTAI() (tai SupportedTAI) {
	tai.SNssaiList = make([]models.Snssai, 0, MaxNumOfSlice)
	return
}

func (ran *AmfRan) Remove() {
	ran.Log.Infof("Remove RAN Context[ID: %+v]", ran.RanID())
	ran.RemoveAllRanUe(true)
	GetSelf().DeleteAmfRan(ran.Conn)
}

func (ran *AmfRan) NewRanUe(ranUeNgapID int64) (*RanUe, error) {
	ranUe := RanUe{}
	self := GetSelf()
	amfUeNgapID, err := self.AllocateAmfUeNgapID()
	if err != nil {
		return nil, fmt.Errorf("allocate AMF UE NGAP ID error: %+v", err)
	}
	ranUe.AmfUeNgapId = amfUeNgapID
	ranUe.RanUeNgapId = ranUeNgapID
	ranUe.Ran = ran
	ranUe.Log = ran.Log
	ranUe.ClearHoldingAmfUe()
	ranUe.UpdateLogFields()

	if ranUeNgapID != RanUeNgapIdUnspecified {
		// store to RanUeList only when RANUENGAPID is specified
		// (otherwise, will be stored only in amfContext.RanUePool)
		ran.RanUeList.Store(ranUeNgapID, &ranUe)
	}
	self.RanUePool.Store(ranUe.AmfUeNgapId, &ranUe)
	ranUe.Log.Infof("New RanUe [RanUeNgapID:%d][AmfUeNgapID:%d]", ranUe.RanUeNgapId, ranUe.AmfUeNgapId)
	return &ranUe, nil
}

func (ran *AmfRan) RemoveAllRanUe(removeAmfUe bool) {
	// Using revered removal since ranUe.Remove() will also modify the slice r.RanUeList
	ran.RanUeList.Range(func(k, v interface{}) bool {
		ranUe := v.(*RanUe)
		if err := ranUe.Remove(); err != nil {
			logger.CtxLog.Errorf("Remove RanUe error: %v", err)
		}
		return true
	})
}

func (ran *AmfRan) RanUeFindByRanUeNgapID(ranUeNgapID int64) *RanUe {
	if value, ok := ran.RanUeList.Load(ranUeNgapID); ok {
		return value.(*RanUe)
	}
	return nil
}

func (ran *AmfRan) FindRanUeByAmfUeNgapID(amfUeNgapID int64) *RanUe {
	var ru *RanUe
	ran.RanUeList.Range(func(k, v interface{}) bool {
		ranUe := v.(*RanUe)
		if ranUe.AmfUeNgapId == amfUeNgapID {
			ru = ranUe
			return false
		}
		return true
	})
	return ru
}

func (ran *AmfRan) SetRanId(ranNodeID *ie.GlobalRANNodeID) {
	if ranNodeID == nil {
		ran.Log.Warn("GlobalRANNodeID is nil")
		return
	}

	var ranID models.GlobalRanNodeId
	switch node := ranNodeID.Choice.(type) {
	case *ie.GlobalGNBID:
		ran.RanPresent = RanPresentGNbId
		ran.AnType = models.AccessType_3_GPP_ACCESS
		ranID.PlmnId = plmnIdentityToModels(node.PLMNIdentity)
		if node.GNBID != nil {
			if gnbID, ok := node.GNBID.Choice.(*ie.GNBIDForGNBID); ok {
				ranID.GNbId = &models.GNbId{
					BitLength: int32(gnbID.Value.BitLength),
					GNBValue:  bitStringToHex(gnbID.Value),
				}
			}
		}
	case *ie.GlobalNgENBID:
		ran.RanPresent = RanPresentNgeNbId
		ran.AnType = models.AccessType_3_GPP_ACCESS
		ranID.PlmnId = plmnIdentityToModels(node.PLMNIdentity)
		if node.NgENBID != nil {
			switch enbID := node.NgENBID.Choice.(type) {
			case *ie.MacroNgENBIDForNgENBID:
				ranID.NgeNbId = "MacroNGeNB-" + bitStringToHex(enbID.Value)
			case *ie.ShortMacroNgENBIDForNgENBID:
				ranID.NgeNbId = "SMacroNGeNB-" + bitStringToHex(enbID.Value)
			case *ie.LongMacroNgENBIDForNgENBID:
				ranID.NgeNbId = "LMacroNGeNB-" + bitStringToHex(enbID.Value)
			}
		}
	case *ie.GlobalN3IWFID:
		ran.RanPresent = RanPresentN3IwfId
		ran.AnType = models.AccessType_NON_3_GPP_ACCESS
		ranID.PlmnId = plmnIdentityToModels(node.PLMNIdentity)
		if node.N3IWFID != nil {
			if n3iwfID, ok := node.N3IWFID.Choice.(*ie.N3IWFIDForN3IWFID); ok {
				ranID.N3IwfId = bitStringToHex(n3iwfID.Value)
			}
		}
	case *ie.ProtocolIESingleContainerGlobalRANNodeIDExtIEs:
		ran.AnType = models.AccessType_NON_3_GPP_ACCESS
		ext := node.GlobalRANNodeIDExtIEs
		switch {
		case ext.GlobalTNGFID != nil:
			ran.RanPresent = RanPresentTngfId
			ranID.PlmnId = plmnIdentityToModels(ext.GlobalTNGFID.PLMNIdentity)
			if ext.GlobalTNGFID.TNGFID != nil {
				if id, ok := ext.GlobalTNGFID.TNGFID.Choice.(*ie.TNGFIDForTNGFID); ok {
					ranID.TngfId = bitStringToHex(id.Value)
				}
			}
		case ext.GlobalTWIFID != nil:
			ran.RanPresent = RanPresentTwifId
			ranID.PlmnId = plmnIdentityToModels(ext.GlobalTWIFID.PLMNIdentity)
			if ext.GlobalTWIFID.TWIFID != nil {
				if id, ok := ext.GlobalTWIFID.TWIFID.Choice.(*ie.TWIFIDForTWIFID); ok {
					ranID.TwifId = bitStringToHex(id.Value)
				}
			}
		case ext.GlobalWAGFID != nil:
			ran.RanPresent = RanPresentWagfId
			ranID.PlmnId = plmnIdentityToModels(ext.GlobalWAGFID.PLMNIdentity)
			if ext.GlobalWAGFID.WAGFID != nil {
				if id, ok := ext.GlobalWAGFID.WAGFID.Choice.(*ie.WAGFIDForWAGFID); ok {
					ranID.WagfId = bitStringToHex(id.Value)
				}
			}
		default:
			ran.Log.Warn("Unsupported GlobalRANNodeID extension")
			return
		}
	default:
		ran.Log.Warnf("Unsupported GlobalRANNodeID choice %T", ranNodeID.Choice)
		return
	}

	ran.RanId = &ranID
}

func plmnIdentityToModels(plmnIdentity *ie.PLMNIdentity) *models.PlmnId {
	if plmnIdentity == nil || len(plmnIdentity.Value) != 3 {
		return nil
	}
	digits := strings.Split(hex.EncodeToString(plmnIdentity.Value), "")
	plmnID := &models.PlmnId{
		Mcc: digits[1] + digits[0] + digits[3],
	}
	if digits[2] == "f" {
		plmnID.Mnc = digits[5] + digits[4]
	} else {
		plmnID.Mnc = digits[2] + digits[5] + digits[4]
	}
	return plmnID
}

func bitStringToHex(bitString aper.BitString) string {
	hexString := hex.EncodeToString(bitString.Bytes)
	hexLength := (bitString.BitLength + 3) / 4
	if int(hexLength) > len(hexString) {
		return ""
	}
	return hexString[:hexLength]
}

func (ran *AmfRan) RanID() string {
	switch ran.RanPresent {
	case RanPresentGNbId:
		return fmt.Sprintf("<PlmnID: %+v, GNbID: %s>", *ran.RanId.PlmnId, ran.RanId.GNbId.GNBValue)
	case RanPresentN3IwfId:
		return fmt.Sprintf("<PlmnID: %+v, N3IwfID: %s>", *ran.RanId.PlmnId, ran.RanId.N3IwfId)
	case RanPresentNgeNbId:
		return fmt.Sprintf("<PlmnID: %+v, NgeNbID: %s>", *ran.RanId.PlmnId, ran.RanId.NgeNbId)
	default:
		return ""
	}
}

func (ran *AmfRan) UeRatType() models.RatType {
	// In TS 23.501 5.3.2.3
	// For 3GPP access the AMF determines the RAT type the UE is camping on based
	// on the Global RAN Node IDs associated with the N2 interface and
	// additionally the Tracking Area indicated by NG-RAN
	switch ran.RanPresent {
	case RanPresentGNbId:
		return models.RatType_NR
	case RanPresentNgeNbId:
		return models.RatType_NR
	case RanPresentN3IwfId:
		return models.RatType_VIRTUAL
	case RanPresentTngfId:
		return models.RatType_TRUSTED_N3_GA
	case RanPresentTwifId:
		return models.RatType_TRUSTED_N3_GA
	case RanPresentWagfId:
		return models.RatType_WIRELINE
	default:
		return models.RatType_NR
	}
}
