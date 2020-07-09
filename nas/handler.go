package nas

import (
	"free5gc/lib/nas"
	"free5gc/src/amf/context"
	"free5gc/src/amf/gmm"
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

	var msg *nas.Message

	if ue.AmfUe == nil {
		ue.AmfUe = amfSelf.NewAmfUe("")
		if err := gmm.InitAmfUeSm(ue.AmfUe); err != nil {
			logger.NgapLog.Errorf("InitAmfUeSm error: %v", err.Error())
			return
		}
		ue.AmfUe.AttachRanUe(ue)
	}

	msg, err := nas_security.Decode(ue.AmfUe, ue.Ran.AnType, nas.GetSecurityHeaderType(nasPdu)&0x0f, nasPdu)
	if err != nil {
		logger.NasLog.Error(err.Error())
		return
	}

	if err := Dispatch(ue.AmfUe, ue.Ran.AnType, procedureCode, msg); err != nil {
		logger.NgapLog.Errorf("Handle NAS Error: %v", err)
	}
}
