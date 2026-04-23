package callback

import (
	"net/url"
	"reflect"
	"strings"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	Namf_Communication "github.com/free5gc/openapi/amf/Communication"
	"github.com/free5gc/openapi/models"
)

func callbackServiceNfType(svcName string) (models.NrfNfManagementNfType, bool) {
	switch {
	case strings.HasPrefix(svcName, "npcf"):
		return models.NrfNfManagementNfType_PCF, true
	case strings.HasPrefix(svcName, "nsmf"):
		return models.NrfNfManagementNfType_SMF, true
	case strings.HasPrefix(svcName, "nudm"):
		return models.NrfNfManagementNfType_UDM, true
	case strings.HasPrefix(svcName, "nausf"):
		return models.NrfNfManagementNfType_AUSF, true
	case strings.HasPrefix(svcName, "namf"):
		return models.NrfNfManagementNfType_AMF, true
	default:
		return "", false
	}
}

func SendAmfStatusChangeNotify(amfStatus string, guamiList []models.Guami) {
	amfSelf := amf_context.GetSelf()

	amfSelf.AMFStatusSubscriptions.Range(func(key, value interface{}) bool {
		subscriptionData := value.(models.AmfCommunicationSubscriptionData)

		configuration := Namf_Communication.NewConfiguration()
		client := Namf_Communication.NewAPIClient(configuration)
		amfStatusNotification := models.AmfStatusChangeNotification{}
		amfStatusInfo := models.AmfStatusInfo{}

		for _, guami := range guamiList {
			for _, subGumi := range subscriptionData.GuamiList {
				if reflect.DeepEqual(guami, subGumi) {
					// AMF status is available
					amfStatusInfo.GuamiList = append(amfStatusInfo.GuamiList, guami)
				}
			}
		}

		amfStatusInfo = models.AmfStatusInfo{
			StatusChange:     (models.StatusChange)(amfStatus),
			TargetAmfRemoval: "",
			TargetAmfFailure: "",
		}

		amfStatusNotification.AmfStatusInfoList = append(amfStatusNotification.AmfStatusInfoList, amfStatusInfo)
		uri := subscriptionData.AmfStatusUri

		amfStatusNotificationReq := Namf_Communication.AmfStatusChangeNotifyRequest{
			AmfStatusChangeNotification: &amfStatusNotification,
		}

		var callbackSvcName models.ServiceName
		var targetNFType models.NrfNfManagementNfType
		if parsedURI, err := url.Parse(uri); err == nil {
			seg := strings.SplitN(strings.TrimPrefix(parsedURI.Path, "/"), "/", 2)[0]
			if nfType, ok := callbackServiceNfType(seg); ok {
				callbackSvcName = models.ServiceName(seg)
				targetNFType = nfType
			}
		}

		ctx, pd, err := amfSelf.GetTokenCtx(callbackSvcName, targetNFType)
		if err != nil {
			HttpLog.Warnf("SendAmfStatusChangeNotify get token failed: %+v", pd)
			return false
		}

		logger.ProducerLog.Infof("[AMF] Send Amf Status Change Notify to %s", uri)
		_, err = client.IndividualSubscriptionDocumentApi.
			AmfStatusChangeNotify(ctx, uri, &amfStatusNotificationReq)
		if err != nil {
			HttpLog.Errorln(err.Error())
		}
		return true
	})
}
