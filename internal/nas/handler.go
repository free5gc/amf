package nas

import (
	"fmt"

	amf_context "github.com/free5gc/amf/internal/context"
	gmm_common "github.com/free5gc/amf/internal/gmm/common"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/amf/internal/nas/nas_security"
	"github.com/free5gc/nas"
)

func HandleNAS(ranUe *amf_context.RanUe, procedureCode int64, nasPdu []byte, initialMessage bool) {
	amfSelf := amf_context.GetSelf()

	if ranUe == nil {
		logger.NasLog.Error("RanUe is nil")
		return
	}

	if nasPdu == nil {
		ranUe.Log.Error("nasPdu is nil")
		return
	}

	if ranUe.AmfUe == nil {
		if ranUe.FindAmfUe != nil && !ranUe.FindAmfUe.CmConnect(ranUe.Ran.AnType) {
			// models.CmState_IDLE
			gmm_common.ClearHoldingRanUe(ranUe.FindAmfUe.RanUe[ranUe.Ran.AnType])

			ranUe.AmfUe = ranUe.FindAmfUe
			gmm_common.AttachRanUeToAmfUeAndReleaseOldIfAny(ranUe.AmfUe, ranUe)
			ranUe.FindAmfUe = nil
		} else {
			// New AmfUe
			ranUe.AmfUe = amfSelf.NewAmfUe("")
			gmm_common.AttachRanUeToAmfUeAndReleaseOldIfAny(ranUe.AmfUe, ranUe)
		}
	}

	msg, integrityProtected, err := nas_security.Decode(ranUe.AmfUe, ranUe.Ran.AnType, nasPdu, initialMessage)
	if err != nil {
		ranUe.AmfUe.NASLog.Errorln(err)
		return
	}
	ranUe.AmfUe.NasPduValue = nasPdu
	ranUe.AmfUe.MacFailed = !integrityProtected

	if ranUe.AmfUe.SecurityContextIsValid() && ranUe.FindAmfUe != nil {
		gmm_common.ClearHoldingRanUe(ranUe.FindAmfUe.RanUe[ranUe.Ran.AnType])
		ranUe.FindAmfUe = nil
	}

	if errDispatch := Dispatch(ranUe.AmfUe, ranUe.Ran.AnType, procedureCode, msg); errDispatch != nil {
		ranUe.AmfUe.NASLog.Errorf("Handle NAS Error: %v", errDispatch)
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
