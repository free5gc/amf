/*
 * Namf_Location
 *
 * AMF Location Service
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package sbi

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/metrics/sbi"
)

func (s *Server) getLocationRoutes() []Route {
	return []Route{
		{
			Method:  http.MethodGet,
			Pattern: "/",
			APIFunc: func(c *gin.Context) {
				c.String(http.StatusOK, "Hello World!")
			},
		},
		{
			Name:    "ProvideLocationInfo",
			Method:  http.MethodPost,
			Pattern: "/:ueContextId/provide-loc-info",
			APIFunc: s.HTTPProvideLocationInfo,
		},
		{
			Name:    "ProvidePositioningInfo",
			Method:  http.MethodPost,
			Pattern: "/:ueContextId/provide-pos-info",
			APIFunc: s.HTTPProvidePositioningInfo,
		},
		{
			Name:    "CancelLocation",
			Method:  http.MethodPost,
			Pattern: "/:ueContextId/cancel-loc-info",
			APIFunc: s.HTTPCancelLocation,
		},
	}
}

// ProvideLocationInfo - Namf_Location ProvideLocationInfo service Operation
func (s *Server) HTTPProvideLocationInfo(c *gin.Context) {
	var requestLocInfo models.RequestLocInfo

	requestBody, err := c.GetRawData()
	if err != nil {
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		logger.LocationLog.Errorf("Get Request Body error: %+v", err)
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetail.Cause)
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	err = openapi.Deserialize(&requestLocInfo, requestBody, "application/json")
	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.LocationLog.Errorln(problemDetail)
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, http.StatusText(http.StatusBadRequest))
		c.JSON(http.StatusBadRequest, rsp)
		return
	}
	s.Processor().HandleProvideLocationInfoRequest(c, requestLocInfo)
}

// ProvidePositioningInfo - Namf_Location ProvidePositioningInfo service Operation
func (s *Server) HTTPProvidePositioningInfo(c *gin.Context) {
	logger.LocationLog.Warnf("Handle Provide Positioning Info is not implemented.")
	c.JSON(http.StatusNotImplemented, gin.H{})
}

func (s *Server) HTTPCancelLocation(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{})
}
