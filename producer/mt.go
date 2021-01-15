package producer

import (
	"free5gc/lib/http_wrapper"
	"free5gc/lib/openapi/models"
	"free5gc/src/amf/context"
	"free5gc/src/amf/logger"
	"net/http"
)

func HandleProvideDomainSelectionInfoRequest(request *http_wrapper.Request) *http_wrapper.Response {
	logger.MtLog.Info("Handle Provide Domain Selection Info Request")

	ueContextID := request.Params["ueContextId"]
	infoClassQuery := request.Query.Get("info-class")
	supportedFeaturesQuery := request.Query.Get("supported-features")

	ueContextInfo, problemDetails := ProvideDomainSelectionInfoProcedure(ueContextID,
		infoClassQuery, supportedFeaturesQuery)
	if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	} else {
		return http_wrapper.NewResponse(http.StatusOK, nil, ueContextInfo)
	}
}

func ProvideDomainSelectionInfoProcedure(ueContextID string, infoClassQuery string, supportedFeaturesQuery string) (
	*models.UeContextInfo, *models.ProblemDetails) {
	amfSelf := context.AMF_Self()

	ue, ok := amfSelf.AmfUeFindByUeContextID(ueContextID)
	if !ok {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "CONTEXT_NOT_FOUND",
		}
		return nil, problemDetails
	}

	ueContextInfo := new(models.UeContextInfo)

	// TODO: Error Status 307, 403 in TS29.518 Table 6.3.3.3.3.1-3
	anType := ue.GetAnType()
	if anType != "" && infoClassQuery != "" {
		ranUe := ue.RanUe[anType]
		ueContextInfo.AccessType = anType
		ueContextInfo.LastActTime = ranUe.LastActTime
		ueContextInfo.RatType = ue.RatType
		ueContextInfo.SupportedFeatures = ranUe.SupportedFeatures
		ueContextInfo.SupportVoPS = ranUe.SupportVoPS
		ueContextInfo.SupportVoPSn3gpp = ranUe.SupportVoPSn3gpp
	}

	return ueContextInfo, nil
}
