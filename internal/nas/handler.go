package nas

import (
	"github.com/free5gc/amf/internal/context"
	gmm_common "github.com/free5gc/amf/internal/gmm/common"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/amf/internal/nas/nas_security"
)

func HandleNAS(ue *context.RanUe, procedureCode int64, nasPdu []byte, initialMessage bool) {
	amfSelf := context.AMF_Self()

	if ue == nil {
		logger.NasLog.Error("RanUe is nil")
		return
	}

	if nasPdu == nil {
		ue.Log.Error("nasPdu is nil")
		return
	}

	if ue.AmfUe == nil {
		ue.AmfUe = amfSelf.NewAmfUe("")
		gmm_common.AttachRanUeToAmfUeAndReleaseOldIfAny(ue.AmfUe, ue)
	}

	msg, integrityProtected, err := nas_security.Decode(ue.AmfUe, ue.Ran.AnType, nasPdu, initialMessage)
	if err != nil {
		ue.AmfUe.NASLog.Errorln(err)
		return
	}
	ue.AmfUe.MacFailed = !integrityProtected

	if err := Dispatch(ue.AmfUe, ue.Ran.AnType, procedureCode, msg); err != nil {
		ue.AmfUe.NASLog.Errorf("Handle NAS Error: %v", err)
	}
}
