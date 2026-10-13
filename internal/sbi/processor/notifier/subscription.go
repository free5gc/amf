package callback

import (
	"fmt"
	"net/url"
	"reflect"
	"strings"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	Namf_Communication "github.com/free5gc/openapi/amf/Comm"
	"github.com/free5gc/openapi/models"
)

const (
	serviceNameNpcfCallback models.Nrf_NFMgmt_ServiceName = "npcf-callback"
	serviceNameNsmfCallback models.Nrf_NFMgmt_ServiceName = "nsmf-callback"
	serviceNameNnefCallback models.Nrf_NFMgmt_ServiceName = "nnef-callback"
)

var callbackServiceTargets = map[models.Nrf_NFMgmt_ServiceName]models.Nrf_NFMgmt_NFType{
	amf_context.ServiceNameNamfCallback: models.Nrf_NFMgmt_NFType_AMF,
	serviceNameNpcfCallback:             models.Nrf_NFMgmt_NFType_PCF,
	serviceNameNsmfCallback:             models.Nrf_NFMgmt_NFType_SMF,
	serviceNameNnefCallback:             models.Nrf_NFMgmt_NFType_NEF,
}

func resolveCallbackTokenTarget(callbackURI string, oauthRequired bool) (
	models.Nrf_NFMgmt_ServiceName, models.Nrf_NFMgmt_NFType, error,
) {
	if !oauthRequired {
		return "", "", nil
	}

	parsedURI, err := url.Parse(callbackURI)
	if err != nil {
		return "", "", fmt.Errorf("parse callback URI: %w", err)
	}
	if parsedURI.Scheme == "" || parsedURI.Host == "" {
		return "", "", fmt.Errorf("callback URI must be absolute: %q", callbackURI)
	}

	escapedPath := strings.TrimPrefix(parsedURI.EscapedPath(), "/")
	serviceSegment, _, _ := strings.Cut(escapedPath, "/")
	serviceName, err := url.PathUnescape(serviceSegment)
	if err != nil {
		return "", "", fmt.Errorf("parse callback service name: %w", err)
	}
	callbackServiceName := models.Nrf_NFMgmt_ServiceName(serviceName)
	targetNFType, known := callbackServiceTargets[callbackServiceName]
	if !known {
		return "", "", fmt.Errorf("unsupported callback service %q", serviceName)
	}

	return callbackServiceName, targetNFType, nil
}

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

		amfStatusNotificationReq := Namf_Communication.AmfStatusChangeNotifyRequest{
			RequestBody: &amfStatusNotification,
		}

		callbackSvcName, targetNFType, resolveErr := resolveCallbackTokenTarget(uri, amfSelf.OAuth2Required)
		if resolveErr != nil {
			HttpLog.Warnf("SendAmfStatusChangeNotify reject callback URI: %v", resolveErr)
			return true
		}

		ctx, pd, err := amfSelf.GetTokenCtx(callbackSvcName, targetNFType)
		if err != nil {
			HttpLog.Warnf("SendAmfStatusChangeNotify get token failed: %+v", pd)
			return false
		}

		logger.ProducerLog.Infof("[AMF] Send Amf Status Change Notify to %s", uri)
		_, err = client.SubscriptionsCollectionCollectionApi.
			AmfStatusChangeNotify(ctx, uri, &amfStatusNotificationReq)
		if err != nil {
			HttpLog.Errorln(err.Error())
		}
		return true
	})
}
