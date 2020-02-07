package amf_handler_test

import (
	"gofree5gc/lib/CommonConsumerTestData/AMF/TestAmf"
	"gofree5gc/lib/ngap"
	"gofree5gc/lib/openapi/models"
	"gofree5gc/src/amf/amf_handler"
	"gofree5gc/src/amf/amf_handler/amf_message"
	"gofree5gc/src/amf/amf_ngap"
	"gofree5gc/src/test/ngapTestpacket"
	"testing"
	"time"
)

func TestHandler(t *testing.T) {
	go amf_handler.Handle()
	TestAmf.SctpSever()
	TestAmf.AmfInit()
	TestAmf.SctpConnectToServer(models.AccessType__3_GPP_ACCESS)
	message := ngapTestpacket.BuildNGSetupRequest()
	ngapMsg, err := ngap.Encoder(message)
	if err != nil {
		amf_ngap.Ngaplog.Errorln(err)
	}
	msg := amf_message.HandlerMessage{}
	msg.Event = amf_message.EventNGAPMessage
	msg.NgapAddr = TestAmf.Laddr.String()
	msg.Value = ngapMsg
	amf_message.SendMessage(msg)

	time.Sleep(100 * time.Millisecond)

}
