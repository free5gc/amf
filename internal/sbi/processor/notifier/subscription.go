package callback

import (
	"context"
	"net/url"
	"reflect"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	Namf_Communication "github.com/free5gc/openapi/amf/Comm"
	"github.com/free5gc/openapi/models"
)

func SendAmfStatusChangeNotify(amfStatus string, guamiList []models.Guami) {
	amfSelf := amf_context.GetSelf()

	amfSelf.AMFStatusSubscriptions.Range(func(key, value interface{}) bool {
		subscriptionData := value.(models.Amf_Comm_SubscriptionData)

		configuration := Namf_Communication.NewConfiguration()
		client := Namf_Communication.NewAPIClient(configuration)
		amfStatusNotification := models.Amf_Comm_AmfStatusChangeNotification{}
		amfStatusInfo := models.Amf_Comm_AmfStatusInfo{}

		for _, guami := range guamiList {
			for _, subGumi := range subscriptionData.GuamiList {
				if reflect.DeepEqual(guami, subGumi) {
					// AMF status is available
					amfStatusInfo.GuamiList = append(amfStatusInfo.GuamiList, guami)
				}
			}
		}

		amfStatusInfo = models.Amf_Comm_AmfStatusInfo{
			StatusChange:     (models.Amf_Comm_StatusChange)(amfStatus),
			TargetAmfRemoval: "",
			TargetAmfFailure: "",
		}

		amfStatusNotification.AmfStatusInfoList = append(amfStatusNotification.AmfStatusInfoList, amfStatusInfo)
		uri := subscriptionData.AmfStatusUri
		parsedURI, parseErr := url.Parse(uri)
		if parseErr != nil || parsedURI.Scheme == "" || parsedURI.Host == "" {
			HttpLog.Warnf("SendAmfStatusChangeNotify reject invalid callback URI: %q", uri)
			return true
		}

		amfStatusNotificationReq := Namf_Communication.AmfStatusChangeNotifyRequest{
			RequestBody: &amfStatusNotification,
		}

		logger.ProducerLog.Infof("[AMF] Send Amf Status Change Notify to %s", uri)
		_, err := client.SubscriptionsCollectionCollectionApi.
			AmfStatusChangeNotify(context.Background(), uri, &amfStatusNotificationReq)
		if err != nil {
			HttpLog.Errorln(err.Error())
		}
		return true
	})
}
