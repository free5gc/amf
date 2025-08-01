package nas

import (
	"fmt"

	amf_context "github.com/free5gc/amf/internal/context"
	gmm_common "github.com/free5gc/amf/internal/gmm/common"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/amf/internal/nas/nas_security"
	"github.com/free5gc/nas"
	nas_metrics "github.com/free5gc/util/metrics/nas"
)

func HandleNAS(ranUe *amf_context.RanUe, procedureCode int64, nasPdu []byte, initialMessage bool) {
	isNasMsgRcv := false
	metricCause := ""
	nasMsg := nas.NewMessage()
	// The closure here is for not having to add a deep copy func for the nas.Message type.
	defer func() {
		nas_metrics.IncrMetricsRcvNasMsg(nasMsg, &isNasMsgRcv, &metricCause)
	}()

	amfSelf := amf_context.GetSelf()

	if ranUe == nil {
		metricCause = nas_metrics.RAN_UE_NIL_ERR
		logger.NasLog.Error("RanUe is nil")
		return
	}

	if nasPdu == nil {
		metricCause = nas_metrics.NAS_PDU_NIL_ERR
		ranUe.Log.Error("nasPdu is nil")
		return
	}

	if ranUe.AmfUe == nil {
		// Only the New created RanUE will have no AmfUe in it

		if ranUe.HoldingAmfUe != nil && !ranUe.HoldingAmfUe.CmConnect(ranUe.Ran.AnType) {
			// If the UE is CM-IDLE, there is no RanUE in AmfUe, so here we attach new RanUe to AmfUe.
			gmm_common.AttachRanUeToAmfUeAndReleaseOldIfAny(ranUe.HoldingAmfUe, ranUe)
			ranUe.HoldingAmfUe = nil
		} else {
			// Assume we have an existing UE context in CM-CONNECTED state. (RanUe <-> AmfUe)
			// We will release it if the new UE context has a valid security context(Authenticated) in line 50.
			ranUe.AmfUe = amfSelf.NewAmfUe("")
			gmm_common.AttachRanUeToAmfUeAndReleaseOldIfAny(ranUe.AmfUe, ranUe)
		}
	}

	msg, integrityProtected, err := nas_security.Decode(ranUe.AmfUe, ranUe.Ran.AnType, nasPdu, initialMessage)
	if err != nil {
		metricCause = nas_metrics.DECODE_NAS_MSG_ERR
		ranUe.AmfUe.NASLog.Errorln(err)
		return
	}

	nasMsg = msg

	ranUe.AmfUe.NasPduValue = nasPdu
	ranUe.AmfUe.MacFailed = !integrityProtected

	if ranUe.AmfUe.SecurityContextIsValid() && ranUe.HoldingAmfUe != nil {
		gmm_common.ClearHoldingRanUe(ranUe.HoldingAmfUe.RanUe[ranUe.Ran.AnType])
		ranUe.HoldingAmfUe = nil
	}

	isNasMsgRcv = true

	if errDispatch := Dispatch(ranUe.AmfUe, ranUe.Ran.AnType, procedureCode, msg); errDispatch != nil {
		ranUe.AmfUe.NASLog.Errorf("Handle NAS Error: %v", errDispatch)
		isNasMsgRcv = false
	}
}

// Get5GSMobileIdentityFromNASPDU is used to find MobileIdentity from plain nas
// return value is: mobileId, mobileIdType, err
func GetNas5GSMobileIdentity(gmmMessage *nas.GmmMessage) (string, string, error) {
	var err error
	var mobileId, mobileIdType string

	if gmmMessage.GmmHeader.GetMessageType() == nas.MsgTypeRegistrationRequest {
		mobileId, mobileIdType, err = gmmMessage.RegistrationRequest.MobileIdentity5GS.GetMobileIdentity()
	} else if gmmMessage.GmmHeader.GetMessageType() == nas.MsgTypeServiceRequest {
		mobileId, mobileIdType, err = gmmMessage.ServiceRequest.TMSI5GS.Get5GSTMSI()
	} else {
		err = fmt.Errorf("gmmMessageType: [%d] is not RegistrationRequest or ServiceRequest",
			gmmMessage.GmmHeader.GetMessageType())
	}
	return mobileId, mobileIdType, err
}
