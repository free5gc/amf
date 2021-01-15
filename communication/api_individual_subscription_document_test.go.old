package communication_test

import (
	"context"
	"free5gc/lib/CommonConsumerTestData/AMF/TestAmf"
	"free5gc/lib/CommonConsumerTestData/AMF/TestComm"
	Namf_Communication_Client "free5gc/lib/openapi/Namf_Communication"
	"free5gc/lib/openapi/models"
	"testing"
)

func sendAMFStatusUnSubscriptionRequestAndPrintResult(t *testing.T, client *Namf_Communication_Client.APIClient, subscriptionId string) {
	httpResponse, err := client.IndividualSubscriptionDocumentApi.AMFStatusChangeUnSubscribe(context.Background(), subscriptionId)
	if err != nil {
		if httpResponse == nil {
			t.Error(err)
		} else if err.Error() != httpResponse.Status {
			t.Error(err)
		} else {

		}
	} else {

	}
}

func sendAMFStatusSubscriptionModfyRequestAndPrintResult(t *testing.T, client *Namf_Communication_Client.APIClient, subscriptionID string, request models.SubscriptionData) {
	aMFStatusSubscription, httpResponse, err := client.IndividualSubscriptionDocumentApi.AMFStatusChangeSubscribeModfy(context.Background(), subscriptionID, request)
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

func TestAMFStatusChangeSubscribeModify(t *testing.T) {
	if lengthOfUePool(TestAmf.TestAmf) == 0 {
		TestAMFStatusChangeSubscribe(t)
	}
	configuration := Namf_Communication_Client.NewConfiguration()
	configuration.SetBasePath("https://localhost:29518")
	client := Namf_Communication_Client.NewAPIClient(configuration)

	subscriptionData := TestComm.ConsumerAMFStatusChangeSubscribeModfyTable[TestComm.AMFStatusSubscriptionModfy403]
	sendAMFStatusSubscriptionModfyRequestAndPrintResult(t, client, "0", subscriptionData)
	//
	subscriptionData = TestComm.ConsumerAMFStatusChangeSubscribeModfyTable[TestComm.AMFStatusSubscriptionModfy200]
	sendAMFStatusSubscriptionModfyRequestAndPrintResult(t, client, "1", subscriptionData)
}

func TestAMFStatusChangeUnSubscribe(t *testing.T) {
	if lengthOfUePool(TestAmf.TestAmf) == 0 {
		TestAMFStatusChangeSubscribe(t)
	}
	configuration := Namf_Communication_Client.NewConfiguration()
	configuration.SetBasePath("https://localhost:29518")
	client := Namf_Communication_Client.NewAPIClient(configuration)

	subscriptionID := TestComm.ConsumerAMFStatusUnSubscriptionTable[TestComm.AMFStatusUnSubscription403]
	sendAMFStatusUnSubscriptionRequestAndPrintResult(t, client, subscriptionID)
	//
	subscriptionID = TestComm.ConsumerAMFStatusUnSubscriptionTable[TestComm.AMFStatusUnSubscription204]
	sendAMFStatusUnSubscriptionRequestAndPrintResult(t, client, subscriptionID)
}
