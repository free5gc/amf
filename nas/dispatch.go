package nas

import (
	"fmt"
	"free5gc/lib/fsm"
	"free5gc/lib/nas"
	"free5gc/lib/openapi/models"
	"free5gc/src/amf/context"
	"free5gc/src/amf/gmm"
	"free5gc/src/amf/logger"
)

func Dispatch(ue *context.AmfUe, anType models.AccessType, procedureCode int64, msg *nas.Message) error {
	if msg.GmmMessage != nil {
		args := make(fsm.Args)
		args[gmm.AMF_UE] = ue
		args[gmm.NAS_MESSAGE] = msg
		args[gmm.PROCEDURE_CODE] = procedureCode
		return ue.Sm[anType].SendEvent(gmm.EVENT_GMM_MESSAGE, args)
	} else if msg.GsmMessage != nil {
		logger.NasLog.Warn("GSM Message should include in GMM Message")
	} else {
		return fmt.Errorf("Nas Payload is Empty")
	}
	return nil
}
