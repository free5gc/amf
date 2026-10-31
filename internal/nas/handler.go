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

	// Track the AmfUe created during this call for cleanup on NAS decode failure.
	var newlyCreatedUe *amf_context.AmfUe

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
			// We will release it if the new UE context has a valid security context(Authenticated) after NAS decoding.
			newlyCreatedUe = amfSelf.NewAmfUe("")
			ranUe.AmfUe = newlyCreatedUe
			gmm_common.AttachRanUeToAmfUeAndReleaseOldIfAny(ranUe.AmfUe, ranUe)
		}
	}

	msg, integrityProtected, err := nas_security.Decode(ranUe.AmfUe, ranUe.Ran.AnType, nasPdu, initialMessage)
	if err != nil {
		metricCause = nas_metrics.DECODE_NAS_MSG_ERR
		ranUe.AmfUe.NASLog.Errorln(err)

		if newlyCreatedUe != nil {
			accessType := ranUe.Ran.AnType

			// Verify the associations before cleaning up the newly created AmfUe.
			if ranUe.AmfUe == newlyCreatedUe &&
				newlyCreatedUe.RanUe[accessType] == ranUe {

				// Detach both associations to preserve the existing RanUe.
				newlyCreatedUe.DetachRanUe(accessType)
				ranUe.DetachAmfUe()

				// Release resources allocated for the newly created AmfUe.
				newlyCreatedUe.Remove()
			} else {
				ranUe.Log.Error("Failed to clean up newly created AmfUe: unexpected RanUe association")
			}
		}

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
