package sbi

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/amf/internal/logger"
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
	s.Processor().HandleProvideDomainSelectionInfoRequest(c)
}

func (s *Server) HTTPEnableUeReachability(c *gin.Context) {
	logger.MtLog.Warnf("Handle Enable Ue Reachability is not implemented.")
	c.JSON(http.StatusNotImplemented, gin.H{})
}
