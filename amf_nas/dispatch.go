package amf_nas

import (
	"fmt"
	"gofree5gc/lib/fsm"
	"gofree5gc/lib/nas"
	"gofree5gc/lib/openapi/models"
	"gofree5gc/src/amf/amf_context"
	"gofree5gc/src/amf/gmm/gmm_event"
	"gofree5gc/src/amf/logger"
)

func Dispatch(ue *amf_context.AmfUe, anType models.AccessType, procedureCode int64, msg *nas.Message) error {
	if msg.GmmMessage != nil {
		args := make(fsm.Args)
		args[gmm_event.AMF_UE] = ue
		args[gmm_event.GMM_MESSAGE] = msg.GmmMessage
		args[gmm_event.PROCEDURE_CODE] = procedureCode
		return ue.Sm[anType].SendEvent(gmm_event.EVENT_GMM_MESSAGE, args)
	} else if msg.GsmMessage != nil {
		logger.NasLog.Warn("GSM Message should include in GMM Message")
	} else {
		return fmt.Errorf("Nas Payload is Empty")
	}
	return nil
}

// TODO: uncomment them
// temporary comment these two function to pass linter check
// func gmmDispatch(ue *amf_context.AmfUe, message *nas.GmmMessage) error {
// 	switch message.GmmHeader.GetMessageType() {
// 	case nas.MsgTypeULNASTransport:
// 		// return HandleULNASTransport(ue, message.ULNASTransport)
// 	}
// 	return nil
// }

// func gsmDispatch(ue *amf_context.AmfUe, message *nas.GsmMessage) error {
// 	switch message.GsmHeader.GetMessageType() {

// 	}
// 	return nil
// }
