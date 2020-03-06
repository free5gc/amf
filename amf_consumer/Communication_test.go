package amf_consumer_test

import (
	"github.com/stretchr/testify/assert"
	"gofree5gc/lib/CommonConsumerTestData/AMF/TestAmf"
	"gofree5gc/lib/CommonConsumerTestData/AMF/TestComm"
	"gofree5gc/lib/http2_util"
	// "gofree5gc/lib/nas/nasMessage"
	// "gofree5gc/lib/nas/nasTestpacket"
	// "gofree5gc/lib/nas/nasType"
	"gofree5gc/lib/openapi/models"
	"gofree5gc/src/amf/Communication"
	"gofree5gc/src/amf/amf_consumer"
	"gofree5gc/src/amf/amf_context"
	"gofree5gc/src/amf/amf_handler"
	"testing"
	"time"
)

func sendCreateUEContextRequestAndPrintResult(t *testing.T, ue *amf_context.AmfUe, request models.CreateUeContextRequest) {
	ueContextCreatedData, problemDetails, err := amf_consumer.CreateUEContextRequest(ue, "https://localhost:29518", *request.JsonData)
	if err != nil {
		t.Error(err)
	} else if problemDetails != nil {
		t.Errorf("Create Ue Context Request Failed: %+v", problemDetails)
	} else {
		t.Logf("response[UeContextCreatedData]: %+v", ueContextCreatedData)
	}
}

func TestCreateUEContextRequest(t *testing.T) {
	nrfInit()

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
	sendCreateUEContextRequestAndPrintResult(t, ue, ueContextCreateData)
}
