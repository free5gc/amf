package communication_test

import (
	"context"
	"crypto/tls"
	"free5gc/lib/CommonConsumerTestData/AMF/TestAmf"
	"free5gc/lib/CommonConsumerTestData/AMF/TestComm"
	"free5gc/lib/http2_util"
	Namf_Communication_Client "free5gc/lib/openapi/Namf_Communication"
	"free5gc/lib/openapi/models"
	Namf_Communication_Server "free5gc/src/amf/communication"
	"free5gc/src/amf/handler"
	"free5gc/src/amf/producer/callback"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/http2"
	"net/http"
	"os"
	"testing"
	"time"
)

func sendAMFStatusSubscriptionRequestAndPrintResult(t *testing.T, client *Namf_Communication_Client.APIClient, request models.SubscriptionData) {
	aMFStatusSubscription, httpResponse, err := client.SubscriptionsCollectionDocumentApi.AMFStatusChangeSubscribe(context.Background(), request)
	if err != nil {
		if httpResponse == nil {
			t.Error(err)
		} else if err.Error() != httpResponse.Status {
			t.Error(err)
		} else {

		}
	} else {
		TestAmf.Config.Dump(aMFStatusSubscription)
	}
}

func TestAMFStatusChangeSubscribe(t *testing.T) {
	if lengthOfUePool(TestAmf.TestAmf) == 0 {
		go func() {
			router := Namf_Communication_Server.NewRouter()
			server, err := http2_util.NewServer(":29518", TestAmf.AmfLogPath, router)
			if err == nil && server != nil {
				err = server.ListenAndServeTLS(TestAmf.AmfPemPath, TestAmf.AmfKeyPath)
			}
			assert.True(t, err == nil)
		}()

		go handler.Handle()
		TestAmf.AmfInit()
		time.Sleep(100 * time.Millisecond)
	}
	configuration := Namf_Communication_Client.NewConfiguration()
	configuration.SetBasePath("https://localhost:29518")
	client := Namf_Communication_Client.NewAPIClient(configuration)

	subscriptionData := TestComm.ConsumerAMFStatusSubscriptionTable[TestComm.AMFStatusSubscription403]
	sendAMFStatusSubscriptionRequestAndPrintResult(t, client, subscriptionData)

	subscriptionData = TestComm.ConsumerAMFStatusSubscriptionTable[TestComm.AMFStatusSubscription201]
	sendAMFStatusSubscriptionRequestAndPrintResult(t, client, subscriptionData)
}

func TestAMFStatusChangeNotify(t *testing.T) {
	if lengthOfUePool(TestAmf.TestAmf) == 0 {
		TestAMFStatusChangeSubscribe(t)
	}
	time.Sleep(100 * time.Millisecond)
	go func() {
		keylogFile, err := os.OpenFile(TestAmf.AmfLogPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		assert.True(t, err == nil)
		server := http.Server{
			Addr: ":29333",
			TLSConfig: &tls.Config{
				KeyLogWriter: keylogFile,
			},
		}
		http2.ConfigureServer(&server, nil)
		http.HandleFunc("/AMFStatusNotify/", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		err = server.ListenAndServeTLS(TestAmf.AmfPemPath, TestAmf.AmfKeyPath)
		assert.True(t, err == nil)
	}()
	time.Sleep(100 * time.Millisecond)
	guamiList := []models.Guami{
		{
			PlmnId: &models.PlmnId{
				Mcc: "208",
				Mnc: "93",
			},
			AmfId: "cafe00",
		},
	}

	callback.SendAmfStatusChangeNotify((string)(models.StatusChange_AVAILABLE), guamiList)
}
