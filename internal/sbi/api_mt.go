package sbi

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/httpwrapper"
)

func (s *Server) getMTRoutes() []Route {
	return []Route{
		{
			Method:  http.MethodGet,
			Pattern: "/",
			APIFunc: func(c *gin.Context) {
				c.String(http.StatusOK, "Hello World!")
			},
		},
		{
			Method:  http.MethodGet,
			Pattern: "/ue-contexts/:ueContextId",
			APIFunc: s.HTTPProvideDomainSelectionInfo,
		},
		{
			Method:  http.MethodPost,
			Pattern: "/ue-contexts/:ueContextId/ue-reachind",
			APIFunc: s.HTTPEnableUeReachability,
		},
	}
}

// ProvideDomainSelectionInfo - Namf_MT Provide Domain Selection Info service Operation
func (s *Server) HTTPProvideDomainSelectionInfo(c *gin.Context) {
	req := httpwrapper.NewRequest(c.Request, nil)
	req.Params["ueContextId"] = c.Params.ByName("ueContextId")
	infoClassQuery := c.Query("info-class")
	req.Query.Add("info-class", infoClassQuery)
	supportedFeaturesQuery := c.Query("supported-features")
	req.Query.Add("supported-features", supportedFeaturesQuery)

	rsp := s.Processor().HandleProvideDomainSelectionInfoRequest(req)

	responseBody, err := openapi.Serialize(rsp.Body, "application/json")
	if err != nil {
		logger.MtLog.Errorln(err)
		problemDetails := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: err.Error(),
		}
		c.JSON(http.StatusInternalServerError, problemDetails)
	} else {
		c.Data(rsp.Status, "application/json", responseBody)
	}
}

func (s *Server) HTTPEnableUeReachability(c *gin.Context) {
	logger.MtLog.Warnf("Handle Enable Ue Reachability is not implemented.")
	c.JSON(http.StatusOK, gin.H{})
}
