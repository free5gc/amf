package amf_consumer_test

import (
	"github.com/stretchr/testify/assert"
	"gofree5gc/lib/CommonConsumerTestData/AMF/TestAmf"
	"gofree5gc/lib/CommonConsumerTestData/AMF/TestComm"
	"gofree5gc/lib/http2_util"
	"gofree5gc/lib/ngap/ngapType"
	"gofree5gc/lib/openapi/models"
	"gofree5gc/src/amf/Communication"
	"gofree5gc/src/amf/amf_consumer"
	"gofree5gc/src/amf/amf_context"
	"gofree5gc/src/amf/amf_handler"
	"gofree5gc/src/amf/gmm"
	"testing"
	"time"
)

func TestCreateUEContextRequest(t *testing.T) {
	if len(TestAmf.TestAmf.UePool) == 0 {
		go func() {
			router := Communication.NewRouter()
			server, err := http2_util.NewServer(":29518", TestAmf.AmfLogPath, router)
			if err == nil && server != nil {
				err = server.ListenAndServeTLS(TestAmf.AmfPemPath, TestAmf.AmfKeyPath)
			}
			assert.True(t, err == nil)
		}()

		go amf_handler.Handle()
		TestAmf.AmfInit()
		time.Sleep(100 * time.Millisecond)
	}

	/* init ue info*/
	ue := TestAmf.TestAmf.UePool["imsi-2089300007487"]

	ueContextCreateData := TestComm.ConsumerAMFCreateUEContextRequsetTable[TestComm.CreateUEContext201]
	ueContextCreatedData, problemDetails, err := amf_consumer.CreateUEContextRequest(ue, "https://localhost:29518", *ueContextCreateData.JsonData)
	if err != nil {
		t.Error(err)
	} else if problemDetails != nil {
		t.Errorf("Create Ue Context Request Failed: %+v", problemDetails)
	} else {
		t.Logf("response[UeContextCreatedData]: %+v", ueContextCreatedData)
	}
}

func TestReleaseUEContextRequest(t *testing.T) {
	if len(TestAmf.TestAmf.UePool) == 0 {
		TestCreateUEContextRequest(t)
	}

	/* init ue info*/
	self := amf_context.AMF_Self()
	supi := "imsi-0010202"
	ue := self.NewAmfUe(supi)
	if err := gmm.InitAmfUeSm(ue); err != nil {
		t.Errorf("InitAmfUeSm error: %v", err)
	}
	ue.Supi = "imsi-111222"

	ue = TestAmf.TestAmf.UePool["imsi-2089300007487"]
	ngapCause := models.NgApCause{
		Group: int32(ngapType.CausePresentProtocol),
		Value: int32(ngapType.CauseProtocolPresentUnspecified),
	}
	problemDetails, err := amf_consumer.ReleaseUEContextRequest(ue, "https://localhost:29518", ngapCause)
	if err != nil {
		t.Error(err)
	} else if problemDetails != nil {
		t.Errorf("Release Ue Context Request Failed: %+v", problemDetails)
	}
}
