package producer

import (
	"net/http"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/httpwrapper"
)

func HandleProvideLocationInfoRequest(request *httpwrapper.Request) *httpwrapper.Response {
	logger.ProducerLog.Info("Handle Provide Location Info Request")

	requestLocInfo := request.Body.(models.RequestLocInfo)
	ueContextID := request.Params["ueContextId"]

	provideLocInfo, problemDetails := ProvideLocationInfoProcedure(requestLocInfo, ueContextID)
	if problemDetails != nil {
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	} else {
		return httpwrapper.NewResponse(http.StatusOK, nil, provideLocInfo)
	}
}

func ProvideLocationInfoProcedure(requestLocInfo models.RequestLocInfo, ueContextID string) (
	*models.ProvideLocInfo, *models.ProblemDetails,
) {
	amfSelf := context.GetSelf()

	ue, ok := amfSelf.AmfUeFindByUeContextID(ueContextID)
	if !ok {
		logger.CtxLog.Warnf("AmfUe Context[%s] not found", ueContextID)
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "CONTEXT_NOT_FOUND",
		}
		return nil, problemDetails
	}

	ue.Lock.Lock()
	defer ue.Lock.Unlock()

	anType := ue.GetAnType()
	if anType == "" {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "CONTEXT_NOT_FOUND",
		}
		return nil, problemDetails
	}

	provideLocInfo := new(models.ProvideLocInfo)

	ranUe := ue.RanUe[anType]
	if requestLocInfo.Req5gsLoc || requestLocInfo.ReqCurrentLoc {
		provideLocInfo.CurrentLoc = true
		provideLocInfo.Location = &ue.Location
	}

	if requestLocInfo.ReqRatType {
		provideLocInfo.RatType = ue.RatType
	}

	if requestLocInfo.ReqTimeZone {
		provideLocInfo.Timezone = ue.TimeZone
	}

	if requestLocInfo.SupportedFeatures != "" {
		provideLocInfo.SupportedFeatures = ranUe.SupportedFeatures
	}
	return provideLocInfo, nil
}
