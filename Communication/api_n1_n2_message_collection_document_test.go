/*
 * Namf_Communication
 *
 * AMF Communication Service
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package Communication

import (
	"context"
	"crypto/tls"
	"github.com/stretchr/testify/assert"
	"gofree5gc/lib/CommonConsumerTestData/AMF/TestAmf"
	"gofree5gc/lib/CommonConsumerTestData/AMF/TestComm"
	"gofree5gc/lib/Namf_Communication"
	"gofree5gc/lib/http2_util"
	"gofree5gc/lib/nas/nasMessage"
	"gofree5gc/lib/nas/nasTestpacket"
	"gofree5gc/lib/openapi/common"
	"gofree5gc/lib/openapi/models"
	"gofree5gc/src/amf/amf_context"
	"gofree5gc/src/amf/amf_handler"
	"gofree5gc/src/amf/amf_producer/amf_producer_callback"
	"gofree5gc/src/amf/amf_util"
	"gofree5gc/src/amf/gmm/gmm_state"
	"golang.org/x/net/http2"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"testing"
	"time"
)

// var testAmf = amf_context.AMF_Self()
// var config = spew.ConfigState{
// 	DisablePointerAddresses: true,
// 	Indent:                  "\t",
// }

// func TestAmf() {
// 	supi := "imsi-2089300007487"
// 	ue := testAmf.NewAmfUe(supi)
// 	ue.GroupID = "12121212-208-93-01010101"

// 	ue.CmInfoList[models.AccessType__3_GPP_ACCESS] = models.CmState_CONNECTED
// 	ue.RmInfoList[models.AccessType__3_GPP_ACCESS] = models.RmState_REGISTERED
// 	ue.RatType = models.RatType_NR
// 	ue.SmContextList[10] = &amf_context.SmContext{
// 		PduSessionContext: &models.PduSessionContext{
// 			AccessType: models.AccessType_NON_3_GPP_ACCESS,
// 		},
// 	}
// 	var testConn net.Conn
// 	ran := testAmf.NewAmfRan(testConn)
// 	ran.AnType = models.AccessType__3_GPP_ACCESS
// 	ranUe := ran.NewRanUe()
// 	ue.AttachRanUe(ranUe)
// }

func sendRequestAndPrintResult(client *Namf_Communication.APIClient, supi string, request models.N1N2MessageTransferRequest) {
	n1N2MessageTransferResponse, httpResponse, err := client.N1N2MessageCollectionDocumentApi.N1N2MessageTransfer(context.Background(), supi, request)
	if err != nil {
		if httpResponse == nil {
			log.Panic(err)
		} else if err.Error() != httpResponse.Status {
			log.Panic(err)
		} else if httpResponse.StatusCode == 504 || httpResponse.StatusCode == 409 {
			var transferError models.N1N2MessageTransferError
			transferError = err.(common.GenericOpenAPIError).Model().(models.N1N2MessageTransferError)
			TestAmf.Config.Dump(transferError)
		} else {
			var probelmDetail models.ProblemDetails
			probelmDetail = err.(common.GenericOpenAPIError).Model().(models.ProblemDetails)
			TestAmf.Config.Dump(probelmDetail)
		}
	} else {
		TestAmf.Config.Dump(n1N2MessageTransferResponse)
	}

}
func TestN1N2MessageTransfer(t *testing.T) {
	go func() {
		router := NewRouter()
		server, err := http2_util.NewServer(":29518", TestAmf.AmfLogPath, router)
		if err == nil && server != nil {
			err = server.ListenAndServeTLS(TestAmf.AmfPemPath, TestAmf.AmfKeyPath)
			assert.True(t, err == nil, err.Error())
		}
	}()
	go amf_handler.Handle()
	TestAmf.AmfInit()
	TestAmf.SctpSever()
	TestAmf.SctpConnectToServer(models.AccessType__3_GPP_ACCESS)

	time.Sleep(100 * time.Millisecond)
	configuration := Namf_Communication.NewConfiguration()
	configuration.SetBasePath("https://localhost:29518")
	client := Namf_Communication.NewAPIClient(configuration)

	/* init ue info*/
	ue := TestAmf.TestAmf.UePool["imsi-2089300007487"]
	err := ue.Sm[models.AccessType__3_GPP_ACCESS].Transfer(gmm_state.REGISTERED, nil)
	assert.True(t, err == nil)
	ue.SmContextList[10] = &amf_context.SmContext{
		PduSessionContext: &models.PduSessionContext{
			AccessType: models.AccessType__3_GPP_ACCESS,
		},
	}
	ue.RegistrationArea[models.AccessType__3_GPP_ACCESS] = []models.Tai{
		{
			PlmnId: &models.PlmnId{
				Mcc: "208",
				Mnc: "93",
			},
			Tac: "000001",
		},
	}

	// tmp := []byte("123")
	tmp := nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(10, nasMessage.ULNASTransportRequestTypeInitialRequest, "", nil)

	// CM_CONNECT
	var n1N2MessageTransferRequest models.N1N2MessageTransferRequest
	n1N2MessageTransferRequest.JsonData = TestComm.ConsumerAMFN1N2MessageTransferRequsetTable[TestComm.PDU_SETUP_REQ]
	n1N2MessageTransferRequest.BinaryDataN1Message = tmp
	n1N2MessageTransferRequest.BinaryDataN2Information = tmp
	// 200 N1_N2_TRANSFER_INITIATED
	sendRequestAndPrintResult(client, ue.Supi, n1N2MessageTransferRequest)
	time.Sleep(50 * time.Millisecond)

	// 202 ATTEMPTING_TO_REACH_UE (Failure Notification)
	// CM_IDLE
	for anType, ranUe := range ue.RanUe {
		ranUe.Remove()
		ue.DetachRanUe(anType)
	}
	n1N2MessageTransferRequest.BinaryDataN2Information = nil
	n1N2MessageTransferRequest.JsonData = TestComm.ConsumerAMFN1N2MessageTransferRequsetTable[TestComm.FAIL_NOTI]
	sendRequestAndPrintResult(client, ue.Supi, n1N2MessageTransferRequest)
	// 409 HIGHER_PRIORITY_REQUEST_ONGOING
	sendRequestAndPrintResult(client, ue.Supi, n1N2MessageTransferRequest)

	amf_util.ClearT3513(ue)

	// 504 UE_NOT_REACHABLE
	err = ue.Sm[models.AccessType__3_GPP_ACCESS].Transfer(gmm_state.DE_REGISTERED, nil)
	assert.True(t, err == nil)
	sendRequestAndPrintResult(client, ue.Supi, n1N2MessageTransferRequest)

	// 200 N1_N2_TRANSFER_INITIATED
	err = ue.Sm[models.AccessType__3_GPP_ACCESS].Transfer(gmm_state.REGISTERED, nil)
	assert.True(t, err == nil)
	n1N2MessageTransferRequest.JsonData = TestComm.ConsumerAMFN1N2MessageTransferRequsetTable[TestComm.SKIP_N1]
	sendRequestAndPrintResult(client, ue.Supi, n1N2MessageTransferRequest)

	// 409 UE_IN_CM_IDLE_STATE
	tmp1 := TestComm.GetPDUSessionResourceReleaseCommandTransfer()
	n1N2MessageTransferRequest.BinaryDataN1Message = nil
	n1N2MessageTransferRequest.BinaryDataN2Information = tmp1
	n1N2MessageTransferRequest.JsonData = TestComm.ConsumerAMFN1N2MessageTransferRequsetTable[TestComm.N2_SmInfo]
	sendRequestAndPrintResult(client, ue.Supi, n1N2MessageTransferRequest)

	// 404 CONTEXT_NOT_FOUND
	sendRequestAndPrintResult(client, "imsi-0010202", n1N2MessageTransferRequest)

}

func TestN1N2MessageTransferStatus(t *testing.T) {
	if len(TestAmf.TestAmf.UePool) == 0 {
		TestN1N2MessageTransfer(t)
	}
	client := &http.Client{}
	client.Transport = &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	req, err := http.NewRequest("GET", "https://localhost:29518/namf-comm/v1/ue-contexts/imsi-2089300007487/n1-n2-messages/1", nil)
	if err != nil {
		t.Error(err)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Error(err)
		return
	}
	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	TestAmf.Config.Dump(string(body))

}

func TestN1N2MessageTransferFailure(t *testing.T) {

	if len(TestAmf.TestAmf.UePool) == 0 {
		TestN1N2MessageTransfer(t)
	}

	go func() {
		keylogFile, err := os.OpenFile(TestAmf.AmfLogPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		assert.True(t, err == nil)
		server := http.Server{
			Addr: ":8082",
			TLSConfig: &tls.Config{
				KeyLogWriter: keylogFile,
			},
		}
		http2.ConfigureServer(&server, nil)
		http.HandleFunc("/n1n2MessageError", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		err = server.ListenAndServeTLS(TestAmf.AmfPemPath, TestAmf.AmfKeyPath)
		assert.True(t, err == nil)
	}()
	time.Sleep(100 * time.Millisecond)
	ue := TestAmf.TestAmf.UePool["imsi-2089300007487"]
	TestAmf.Config.Dump(ue.N1N2Message)
	amf_producer_callback.SendN1N2TransferFailureNotification(ue, models.N1N2MessageTransferCause_UE_NOT_RESPONDING)
	TestAmf.Config.Dump(ue.N1N2Message)
}
