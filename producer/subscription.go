package producer

import (
	"free5gc/lib/http_wrapper"
	"free5gc/lib/openapi/models"
	"free5gc/src/amf/context"
	"free5gc/src/amf/logger"
	"net/http"
	"reflect"
)

// TS 29.518 5.2.2.5.1
func HandleAMFStatusChangeSubscribeRequest(request *http_wrapper.Request) *http_wrapper.Response {
	logger.CommLog.Info("Handle AMF Status Change Subscribe Request")

	var responseBody models.SubscriptionData
	var problem models.ProblemDetails

	subscriptionData := request.Body.(models.SubscriptionData)
	amfSelf := context.AMF_Self()

	for _, guami := range subscriptionData.GuamiList {
		for _, servedGumi := range amfSelf.ServedGuamiList {
			if reflect.DeepEqual(guami, servedGumi) {
				//AMF status is available
				responseBody.GuamiList = append(responseBody.GuamiList, guami)
			}
		}
	}

	if responseBody.GuamiList != nil {
		newSubscriptionID := amfSelf.NewAMFStatusSubscription(subscriptionData)
		locationHeader := subscriptionData.AmfStatusUri + "/" + newSubscriptionID
		headers := http.Header{
			"Location": {locationHeader},
		}
		logger.CommLog.Infof("new AMF Status Subscription[%s]", newSubscriptionID)
		return http_wrapper.NewResponse(http.StatusCreated, headers, responseBody)
	} else {
		problem.Status = http.StatusForbidden
		problem.Cause = "UNSPECIFIED"
		return http_wrapper.NewResponse(http.StatusForbidden, nil, problem)
	}
}

// TS 29.518 5.2.2.5.2
func HandleAMFStatusChangeUnSubscribeRequest(request *http_wrapper.Request) *http_wrapper.Response {
	logger.CommLog.Info("Handle AMF Status Change UnSubscribe Request")

	var problem models.ProblemDetails

	subscriptionID := request.Params["subscriptionId"]
	amfSelf := context.AMF_Self()

	if _, ok := amfSelf.FindAMFStatusSubscription(subscriptionID); !ok {
		problem.Status = http.StatusNotFound
		problem.Cause = "SUBSCRIPTION_NOT_FOUND"
		return http_wrapper.NewResponse(http.StatusNotFound, nil, problem)
	} else {
		logger.CommLog.Debugf("Delete AMF status subscription[%s]", subscriptionID)

		amfSelf.DeleteAMFStatusSubscription(subscriptionID)
		return http_wrapper.NewResponse(http.StatusNoContent, nil, nil)
	}
}

// TS 29.518 5.2.2.5.1.3
func HandleAMFStatusChangeSubscribeModify(request *http_wrapper.Request) *http_wrapper.Response {
	logger.CommLog.Info("Handle AMF Status Change Subscribe Modify Request")

	var responseBody models.SubscriptionData
	var problem models.ProblemDetails

	updateSubscriptionData := request.Body.(models.SubscriptionData)
	subscriptionID := request.Params["subscriptionId"]
	amfSelf := context.AMF_Self()

	if subscriptionData, ok := amfSelf.FindAMFStatusSubscription(subscriptionID); !ok {
		problem.Status = 403
		problem.Cause = "Forbidden"
		return http_wrapper.NewResponse(http.StatusForbidden, nil, problem)
	} else {
		logger.CommLog.Debugf("Modify AMF status subscription[%s]", subscriptionID)

		subscriptionData.GuamiList = subscriptionData.GuamiList[:0]
		for _, guamiList := range updateSubscriptionData.GuamiList {
			subscriptionData.GuamiList = append(subscriptionData.GuamiList, guamiList)
			responseBody.GuamiList = append(responseBody.GuamiList, guamiList)
		}

		subscriptionData.AmfStatusUri = updateSubscriptionData.AmfStatusUri
		responseBody.AmfStatusUri = subscriptionData.AmfStatusUri
		amfSelf.AMFStatusSubscriptions.Store(subscriptionID, subscriptionData)
		return http_wrapper.NewResponse(http.StatusAccepted, nil, responseBody)
	}
}
