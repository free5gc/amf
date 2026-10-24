package nas

import (
	"fmt"

	amf_context "github.com/free5gc/amf/internal/context"
	gmm_common "github.com/free5gc/amf/internal/gmm/common"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/amf/internal/nas/nas_security"
	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	nas_metrics "github.com/free5gc/util/metrics/nas"
)

func HandleNAS(ranUe *amf_context.RanUe, procedureCode int64, nasPdu []byte, initialMessage bool) {
	isNasMsgRcv := false
	metricCause := ""
	var nasMsg message.Message
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

	// Read ranUe.AmfUe once: a release handled by another NGAP worker
	// (removeRanUeByInvalidId, AttachRanUeToAmfUeAndReleaseOldIfAny) can detach
	// it at any time, so every use below goes through this snapshot.
	amfUe := ranUe.GetAmfUe()
	if amfUe == nil {
		// Only the New created RanUE will have no AmfUe in it

		holdingAmfUe := ranUe.GetHoldingAmfUe()
		if holdingAmfUe != nil && !holdingAmfUe.CmConnect(ranUe.Ran.AnType) {
			// If the UE is CM-IDLE, there is no RanUE in AmfUe, so here we attach new RanUe to AmfUe.
			amfUe = holdingAmfUe
			gmm_common.AttachRanUeToAmfUeAndReleaseOldIfAny(amfUe, ranUe)
			ranUe.ClearHoldingAmfUe()
		} else {
			// Assume we have an existing UE context in CM-CONNECTED state. (RanUe <-> AmfUe)
			// We will release it if the new UE context has a valid security context(Authenticated) in line 50.
			amfUe = amfSelf.NewAmfUe("")
			gmm_common.AttachRanUeToAmfUeAndReleaseOldIfAny(amfUe, ranUe)
		}
	}

	msg, integrityProtected, err := nas_security.Decode(amfUe, ranUe.Ran.AnType, nasPdu, initialMessage)
	if err != nil {
		metricCause = nas_metrics.DECODE_NAS_MSG_ERR
		amfUe.NASLog.Errorln(err)
		return
	}

	nasMsg = msg

	amfUe.NasPduValue = nasPdu
	amfUe.MacFailed = !integrityProtected

	if amfUe.SecurityContextIsValid() {
		if holdingAmfUe := ranUe.GetHoldingAmfUe(); holdingAmfUe != nil {
			gmm_common.ClearHoldingRanUe(holdingAmfUe.GetRanUe(ranUe.Ran.AnType))
			ranUe.ClearHoldingAmfUe()
		}
	}

	isNasMsgRcv = true

	if errDispatch := Dispatch(amfUe, ranUe.Ran.AnType, procedureCode, msg); errDispatch != nil {
		amfUe.NASLog.Errorf("Handle NAS Error: %v", errDispatch)
		isNasMsgRcv = false
	}
}

// Get5GSMobileIdentityFromNASPDU is used to find MobileIdentity from plain nas
// return value is: mobileId, mobileIdType, err
func GetNas5GSMobileIdentity(gmmMessage message.Message) (string, string, error) {
	var mobileIdentity *ie.MobileId5GS
	switch msg := gmmMessage.(type) {
	case *message.RegReq:
		mobileIdentity = msg.MobileId5GS
	case *message.SvcReq:
		mobileIdentity = msg.TMSI5GS
	default:
		if gmmMessage == nil {
			return "", "", fmt.Errorf("GMM message is nil")
		}
		return "", "", fmt.Errorf(
			"GMM message type [%d] is not RegistrationRequest or ServiceRequest",
			gmmMessage.MsgType(),
		)
	}
	if mobileIdentity == nil {
		return "", "", fmt.Errorf("GMM message has no 5GS mobile identity")
	}
	return mobileIdentity.IdStr(), ie.IdType5GSStr(mobileIdentity.TypeOfId), nil
}
