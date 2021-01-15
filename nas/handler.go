package nas

import (
	"free5gc/src/amf/context"
	"free5gc/src/amf/logger"
	"free5gc/src/amf/nas/nas_security"
)

func HandleNAS(ue *context.RanUe, procedureCode int64, nasPdu []byte) {
	amfSelf := context.AMF_Self()

	if ue == nil {
		logger.NasLog.Error("RanUe is nil")
		return
	}

	if nasPdu == nil {
		logger.NasLog.Error("nasPdu is nil")
		return
	}

	if ue.AmfUe == nil {
		ue.AmfUe = amfSelf.NewAmfUe("")
		ue.AmfUe.AttachRanUe(ue)
	}

	msg, err := nas_security.Decode(ue.AmfUe, ue.Ran.AnType, nasPdu)
	if err != nil {
		logger.NasLog.Errorln(err)
		return
	}

	if err := Dispatch(ue.AmfUe, ue.Ran.AnType, procedureCode, msg); err != nil {
		logger.NgapLog.Errorf("Handle NAS Error: %v", err)
	}
}
