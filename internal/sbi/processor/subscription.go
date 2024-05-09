package processor

import (
	"net/http"
	"reflect"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/httpwrapper"
)

// TS 29.518 5.2.2.5.1
func (p *Processor) HandleAMFStatusChangeSubscribeRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.CommLog.Info("Handle AMF Status Change Subscribe Request")

	subscriptionDataReq := request.Body.(models.SubscriptionData)

	subscriptionDataRsp, locationHeader, problemDetails := p.AMFStatusChangeSubscribeProcedure(subscriptionDataReq)
	if problemDetails != nil {
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	}

	headers := http.Header{
		"Location": {locationHeader},
	}
	return httpwrapper.NewResponse(http.StatusCreated, headers, subscriptionDataRsp)
}

func (p *Processor) AMFStatusChangeSubscribeProcedure(subscriptionDataReq models.SubscriptionData) (
	subscriptionDataRsp models.SubscriptionData, locationHeader string, problemDetails *models.ProblemDetails,
) {
	amfSelf := context.GetSelf()

	for _, guami := range subscriptionDataReq.GuamiList {
		for _, servedGumi := range amfSelf.ServedGuamiList {
			if reflect.DeepEqual(guami, servedGumi) {
				// AMF status is available
				subscriptionDataRsp.GuamiList = append(subscriptionDataRsp.GuamiList, guami)
			}
		}
	}

	if subscriptionDataRsp.GuamiList != nil {
		newSubscriptionID := amfSelf.NewAMFStatusSubscription(subscriptionDataReq)
		locationHeader = subscriptionDataReq.AmfStatusUri + "/" + newSubscriptionID
		logger.CommLog.Infof("new AMF Status Subscription[%s]", newSubscriptionID)
		return
	} else {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  "UNSPECIFIED",
		}
		return
	}
}

// TS 29.518 5.2.2.5.2
func (p *Processor) HandleAMFStatusChangeUnSubscribeRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.CommLog.Info("Handle AMF Status Change UnSubscribe Request")

	subscriptionID := request.Params["subscriptionId"]

	problemDetails := p.AMFStatusChangeUnSubscribeProcedure(subscriptionID)
	if problemDetails != nil {
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	} else {
		return httpwrapper.NewResponse(http.StatusNoContent, nil, nil)
	}
}

func (p *Processor) AMFStatusChangeUnSubscribeProcedure(subscriptionID string) (problemDetails *models.ProblemDetails) {
	amfSelf := context.GetSelf()

	if _, ok := amfSelf.FindAMFStatusSubscription(subscriptionID); !ok {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "SUBSCRIPTION_NOT_FOUND",
		}
	} else {
		logger.CommLog.Debugf("Delete AMF status subscription[%s]", subscriptionID)
		amfSelf.DeleteAMFStatusSubscription(subscriptionID)
	}
	return
}

// TS 29.518 5.2.2.5.1.3
func (p *Processor) HandleAMFStatusChangeSubscribeModify(request *httpwrapper.Request) *httpwrapper.Response {
	logger.CommLog.Info("Handle AMF Status Change Subscribe Modify Request")

	updateSubscriptionData := request.Body.(models.SubscriptionData)
	subscriptionID := request.Params["subscriptionId"]

	updatedSubscriptionData, problemDetails := p.AMFStatusChangeSubscribeModifyProcedure(subscriptionID,
		updateSubscriptionData)
	if problemDetails != nil {
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	} else {
		return httpwrapper.NewResponse(http.StatusAccepted, nil, updatedSubscriptionData)
	}
}

func (p *Processor) AMFStatusChangeSubscribeModifyProcedure(subscriptionID string,
	subscriptionData models.SubscriptionData) (
	*models.SubscriptionData, *models.ProblemDetails,
) {
	amfSelf := context.GetSelf()

	if currentSubscriptionData, ok := amfSelf.FindAMFStatusSubscription(subscriptionID); !ok {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  "Forbidden",
		}
		return nil, problemDetails
	} else {
		logger.CommLog.Debugf("Modify AMF status subscription[%s]", subscriptionID)

		currentSubscriptionData.GuamiList = currentSubscriptionData.GuamiList[:0]

		currentSubscriptionData.GuamiList = append(currentSubscriptionData.GuamiList, subscriptionData.GuamiList...)
		currentSubscriptionData.AmfStatusUri = subscriptionData.AmfStatusUri

		amfSelf.AMFStatusSubscriptions.Store(subscriptionID, currentSubscriptionData)
		return currentSubscriptionData, nil
	}
}
