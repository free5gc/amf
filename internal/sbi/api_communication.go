package sbi

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/httpwrapper"
)

func Index(c *gin.Context) {
	c.String(http.StatusOK, "Hello World!")
}

func (s *Server) getCommunicationRoutes() []Route {
	return []Route{
		{
			Method:  http.MethodGet,
			Pattern: "/",
			APIFunc: func(c *gin.Context) {
				c.String(http.StatusOK, "Hello World!")
			},
		},
		{
			Method:  http.MethodPut,
			Pattern: "/subscriptions/:subscriptionId",
			APIFunc: s.HTTPAMFStatusChangeSubscribeModify,
		},
		{
			Method:  http.MethodDelete,
			Pattern: "/subscriptions/:subscriptionId",
			APIFunc: s.HTTPAMFStatusChangeUnSubscribe,
		},
		{
			Method:  http.MethodPut,
			Pattern: "/ue-contexts/:ueContextId",
			APIFunc: s.HTTPCreateUEContext,
		},
		{
			Method:  http.MethodPost,
			Pattern: "/ue-contexts/:ueContextId/assign-ebi",
			APIFunc: s.HTTPEBIAssignment,
		},
		{
			Method:  http.MethodPost,
			Pattern: "/ue-contexts/:ueContextId/transfer-update",
			APIFunc: s.HTTPRegistrationStatusUpdate,
		},
		{
			Method:  http.MethodPost,
			Pattern: "/ue-contexts/:ueContextId/release",
			APIFunc: s.HTTPReleaseUEContext,
		},
		{
			Method:  http.MethodPost,
			Pattern: "/ue-contexts/:ueContextId/transfer",
			APIFunc: s.HTTPUEContextTransfer,
		},
		{
			Method:  http.MethodDelete,
			Pattern: "/ue-contexts/:ueContextId/n1-n2-messages/subscriptions/:subscriptionId",
			APIFunc: s.HTTPN1N2MessageUnSubscribe,
		},
		{
			Method:  http.MethodPost,
			Pattern: "/ue-contexts/:ueContextId/n1-n2-messages",
			APIFunc: s.HTTPN1N2MessageTransfer,
		},
		{
			Method:  http.MethodGet,
			Pattern: "/ue-contexts/:ueContextId/n1-n2-messages/:n1N2MessageId",
			APIFunc: s.HTTPN1N2MessageTransferStatus,
		},
		{
			Method:  http.MethodPost,
			Pattern: "/ue-contexts/:ueContextId/n1-n2-messages/subscriptions",
			APIFunc: s.HTTPN1N2MessageSubscribe,
		},
		{
			Method:  http.MethodDelete,
			Pattern: "/non-ue-n2-messages/subscriptions/:n2NotifySubscriptionId",
			APIFunc: s.HTTPNonUeN2InfoUnSubscribe,
		},
		{
			Method:  http.MethodPost,
			Pattern: "/non-ue-n2-messages/transfer",
			APIFunc: s.HTTPNonUeN2MessageTransfer,
		},
		{
			Method:  http.MethodPost,
			Pattern: "/non-ue-n2-messages/subscriptions",
			APIFunc: s.HTTPNonUeN2InfoSubscribe,
		},
		{
			Method:  http.MethodPost,
			Pattern: "/subscriptions",
			APIFunc: s.HTTPAMFStatusChangeSubscribe,
		},
	}
}

// AMFStatusChangeSubscribeModify - Namf_Communication AMF Status Change Subscribe Modify service Operation
func (s *Server) HTTPAMFStatusChangeSubscribeModify(c *gin.Context) {
	var subscriptionData models.SubscriptionData

	requestBody, err := c.GetRawData()
	if err != nil {
		logger.CommLog.Errorf("Get Request Body error: %+v", err)
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	err = openapi.Deserialize(&subscriptionData, requestBody, applicationjson)
	if err != nil {
		problemDetail := reqbody + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.CommLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, subscriptionData)
	req.Params["subscriptionId"] = c.Params.ByName("subscriptionId")

	rsp := s.Processor().HandleAMFStatusChangeSubscribeModify(req)

	responseBody, err := openapi.Serialize(rsp.Body, applicationjson)
	if err != nil {
		logger.CommLog.Errorln(err)
		problemDetails := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: err.Error(),
		}
		c.JSON(http.StatusInternalServerError, problemDetails)
	} else {
		c.Data(rsp.Status, applicationjson, responseBody)
	}
}

// AMFStatusChangeUnSubscribe - Namf_Communication AMF Status Change UnSubscribe service Operation
func (s *Server) HTTPAMFStatusChangeUnSubscribe(c *gin.Context) {
	req := httpwrapper.NewRequest(c.Request, nil)
	req.Params["subscriptionId"] = c.Params.ByName("subscriptionId")

	rsp := s.Processor().HandleAMFStatusChangeUnSubscribeRequest(req)

	responseBody, err := openapi.Serialize(rsp.Body, applicationjson)
	if err != nil {
		logger.CommLog.Errorln(err)
		problemDetails := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: err.Error(),
		}
		c.JSON(http.StatusInternalServerError, problemDetails)
	} else {
		c.Data(rsp.Status, applicationjson, responseBody)
	}
}

func (s *Server) HTTPCreateUEContext(c *gin.Context) {
	var createUeContextRequest models.CreateUeContextRequest
	createUeContextRequest.JsonData = new(models.UeContextCreateData)

	requestBody, err := c.GetRawData()
	if err != nil {
		logger.CommLog.Errorf("Get Request Body error: %+v", err)
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	contentType := c.GetHeader("Content-Type")
	str := strings.Split(contentType, ";")
	switch str[0] {
	case applicationjson:
		err = openapi.Deserialize(createUeContextRequest.JsonData, requestBody, contentType)
	case multipartrelate:
		err = openapi.Deserialize(&createUeContextRequest, requestBody, contentType)
	default:
		err = fmt.Errorf("wrong content type")
	}

	if err != nil {
		problemDetail := reqbody + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.CommLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, createUeContextRequest)
	req.Params["ueContextId"] = c.Params.ByName("ueContextId")
	rsp := s.Processor().HandleCreateUEContextRequest(req)

	if rsp.Status == http.StatusCreated {
		responseBody, contentTyperspBody, errrspBody := openapi.MultipartSerialize(rsp.Body)
		if errrspBody != nil {
			logger.CommLog.Errorln(errrspBody)
			problemDetails := models.ProblemDetails{
				Status: http.StatusInternalServerError,
				Cause:  "SYSTEM_FAILURE",
				Detail: errrspBody.Error(),
			}
			c.JSON(http.StatusInternalServerError, problemDetails)
		} else {
			c.Data(rsp.Status, contentTyperspBody, responseBody)
		}
	} else {
		responseBody, errSerialize := openapi.Serialize(rsp.Body, applicationjson)
		if errSerialize != nil {
			logger.CommLog.Errorln(errSerialize)
			problemDetails := models.ProblemDetails{
				Status: http.StatusInternalServerError,
				Cause:  "SYSTEM_FAILURE",
				Detail: errSerialize.Error(),
			}
			c.JSON(http.StatusInternalServerError, problemDetails)
		} else {
			c.Data(rsp.Status, applicationjson, responseBody)
		}
	}
}

// EBIAssignment - Namf_Communication EBI Assignment service Operation
func (s *Server) HTTPEBIAssignment(c *gin.Context) {
	var assignEbiData models.AssignEbiData

	requestBody, err := c.GetRawData()
	if err != nil {
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		logger.CommLog.Errorf("Get Request Body error: %+v", err)
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	err = openapi.Deserialize(&assignEbiData, requestBody, applicationjson)
	if err != nil {
		problemDetail := reqbody + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.CommLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, assignEbiData)
	req.Params["ueContextId"] = c.Params.ByName("ueContextId")
	rsp := s.Processor().HandleAssignEbiDataRequest(req)

	responseBody, err := openapi.Serialize(rsp.Body, applicationjson)
	if err != nil {
		logger.CommLog.Errorln(err)
		problemDetails := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: err.Error(),
		}
		c.JSON(http.StatusInternalServerError, problemDetails)
	} else {
		c.Data(rsp.Status, applicationjson, responseBody)
	}
}

// RegistrationStatusUpdate - Namf_Communication RegistrationStatusUpdate service Operation
func (s *Server) HTTPRegistrationStatusUpdate(c *gin.Context) {
	var ueRegStatusUpdateReqData models.UeRegStatusUpdateReqData

	requestBody, err := c.GetRawData()
	if err != nil {
		logger.CommLog.Errorf("Get Request Body error: %+v", err)
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	err = openapi.Deserialize(&ueRegStatusUpdateReqData, requestBody, applicationjson)
	if err != nil {
		problemDetail := reqbody + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.CommLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, ueRegStatusUpdateReqData)
	req.Params["ueContextId"] = c.Params.ByName("ueContextId")
	rsp := s.Processor().HandleRegistrationStatusUpdateRequest(req)

	responseBody, err := openapi.Serialize(rsp.Body, applicationjson)
	if err != nil {
		logger.CommLog.Errorln(err)
		problemDetails := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: err.Error(),
		}
		c.JSON(http.StatusInternalServerError, problemDetails)
	} else {
		c.Data(rsp.Status, applicationjson, responseBody)
	}
}

// ReleaseUEContext - Namf_Communication ReleaseUEContext service Operation
func (s *Server) HTTPReleaseUEContext(c *gin.Context) {
	var ueContextRelease models.UeContextRelease

	requestBody, err := c.GetRawData()
	if err != nil {
		logger.CommLog.Errorf("Get Request Body error: %+v", err)
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	err = openapi.Deserialize(&ueContextRelease, requestBody, applicationjson)
	if err != nil {
		problemDetail := reqbody + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.CommLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, ueContextRelease)
	req.Params["ueContextId"] = c.Params.ByName("ueContextId")
	rsp := s.Processor().HandleReleaseUEContextRequest(req)

	responseBody, err := openapi.Serialize(rsp.Body, applicationjson)
	if err != nil {
		logger.CommLog.Errorln(err)
		problemDetails := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: err.Error(),
		}
		c.JSON(http.StatusInternalServerError, problemDetails)
	} else {
		c.Data(rsp.Status, applicationjson, responseBody)
	}
}

// UEContextTransfer - Namf_Communication UEContextTransfer service Operation
func (s *Server) HTTPUEContextTransfer(c *gin.Context) {
	var ueContextTransferRequest models.UeContextTransferRequest
	ueContextTransferRequest.JsonData = new(models.UeContextTransferReqData)

	requestBody, err := c.GetRawData()
	if err != nil {
		logger.CommLog.Errorf("Get Request Body error: %+v", err)
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	contentType := c.GetHeader("Content-Type")
	str := strings.Split(contentType, ";")
	switch str[0] {
	case applicationjson:
		err = openapi.Deserialize(ueContextTransferRequest.JsonData, requestBody, contentType)
	case multipartrelate:
		err = openapi.Deserialize(&ueContextTransferRequest, requestBody, contentType)
	}

	if err != nil {
		problemDetail := reqbody + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.CommLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, ueContextTransferRequest)
	req.Params["ueContextId"] = c.Params.ByName("ueContextId")
	rsp := s.Processor().HandleUEContextTransferRequest(req)

	if rsp.Status == http.StatusOK {
		responseBody, contentTyperspBody, errMultipartSerialize := openapi.MultipartSerialize(rsp.Body)
		if errMultipartSerialize != nil {
			logger.CommLog.Errorln(errMultipartSerialize)
			problemDetails := models.ProblemDetails{
				Status: http.StatusInternalServerError,
				Cause:  "SYSTEM_FAILURE",
				Detail: errMultipartSerialize.Error(),
			}
			c.JSON(http.StatusInternalServerError, problemDetails)
		} else {
			c.Data(rsp.Status, contentTyperspBody, responseBody)
		}
	} else {
		responseBody, errSerialize := openapi.Serialize(rsp.Body, applicationjson)
		if errSerialize != nil {
			logger.CommLog.Errorln(errSerialize)
			problemDetails := models.ProblemDetails{
				Status: http.StatusInternalServerError,
				Cause:  "SYSTEM_FAILURE",
				Detail: errSerialize.Error(),
			}
			c.JSON(http.StatusInternalServerError, problemDetails)
		} else {
			c.Data(rsp.Status, applicationjson, responseBody)
		}
	}
}

func (s *Server) HTTPN1N2MessageUnSubscribe(c *gin.Context) {
	req := httpwrapper.NewRequest(c.Request, nil)
	req.Params["ueContextId"] = c.Params.ByName("ueContextId")
	req.Params["subscriptionId"] = c.Params.ByName("subscriptionId")

	rsp := s.Processor().HandleN1N2MessageUnSubscribeRequest(req)

	responseBody, err := openapi.Serialize(rsp.Body, applicationjson)
	if err != nil {
		logger.CommLog.Errorln(err)
		problemDetails := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: err.Error(),
		}
		c.JSON(http.StatusInternalServerError, problemDetails)
	} else {
		c.Data(rsp.Status, applicationjson, responseBody)
	}
}

func (s *Server) HTTPN1N2MessageTransfer(c *gin.Context) {
	var n1n2MessageTransferRequest models.N1N2MessageTransferRequest
	n1n2MessageTransferRequest.JsonData = new(models.N1N2MessageTransferReqData)

	requestBody, err := c.GetRawData()
	if err != nil {
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		logger.CommLog.Errorf("Get Request Body error: %+v", err)
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	contentType := c.GetHeader("Content-Type")
	str := strings.Split(contentType, ";")
	switch str[0] {
	case applicationjson:
		err = fmt.Errorf("N1 and N2 datas are both Empty in N1N2MessgeTransfer")
	case multipartrelate:
		err = openapi.Deserialize(&n1n2MessageTransferRequest, requestBody, contentType)
	default:
		err = fmt.Errorf("wrong content type")
	}

	if err != nil {
		problemDetail := reqbody + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.CommLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, n1n2MessageTransferRequest)
	req.Params["ueContextId"] = c.Params.ByName("ueContextId")
	req.Params["reqUri"] = c.Request.RequestURI

	rsp := s.Processor().HandleN1N2MessageTransferRequest(req)

	for key, val := range rsp.Header {
		c.Header(key, val[0])
	}
	responseBody, err := openapi.Serialize(rsp.Body, applicationjson)
	if err != nil {
		logger.CommLog.Errorln(err)
		problemDetails := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: err.Error(),
		}
		c.JSON(http.StatusInternalServerError, problemDetails)
	} else {
		c.Data(rsp.Status, applicationjson, responseBody)
	}
}

func (s *Server) HTTPN1N2MessageTransferStatus(c *gin.Context) {
	req := httpwrapper.NewRequest(c.Request, nil)
	req.Params["ueContextId"] = c.Params.ByName("ueContextId")
	req.Params["reqUri"] = c.Request.RequestURI

	rsp := s.Processor().HandleN1N2MessageTransferStatusRequest(req)

	responseBody, err := openapi.Serialize(rsp.Body, applicationjson)
	if err != nil {
		logger.CommLog.Errorln(err)
		problemDetails := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: err.Error(),
		}
		c.JSON(http.StatusInternalServerError, problemDetails)
	} else {
		c.Data(rsp.Status, applicationjson, responseBody)
	}
}

func (s *Server) HTTPN1N2MessageSubscribe(c *gin.Context) {
	var ueN1N2InfoSubscriptionCreateData models.UeN1N2InfoSubscriptionCreateData

	requestBody, err := c.GetRawData()
	if err != nil {
		logger.CommLog.Errorf("Get Request Body error: %+v", err)
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	err = openapi.Deserialize(&ueN1N2InfoSubscriptionCreateData, requestBody, applicationjson)
	if err != nil {
		problemDetail := reqbody + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.CommLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, ueN1N2InfoSubscriptionCreateData)
	req.Params["ueContextId"] = c.Params.ByName("ueContextId")

	rsp := s.Processor().HandleN1N2MessageSubscirbeRequest(req)

	responseBody, err := openapi.Serialize(rsp.Body, applicationjson)
	if err != nil {
		logger.CommLog.Errorln(err)
		problemDetails := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: err.Error(),
		}
		c.JSON(http.StatusInternalServerError, problemDetails)
	} else {
		c.Data(rsp.Status, applicationjson, responseBody)
	}
}

func (s *Server) HTTPNonUeN2InfoUnSubscribe(c *gin.Context) {
	logger.CommLog.Warnf("Handle Non Ue N2 Info UnSubscribe is not implemented.")
	c.JSON(http.StatusOK, gin.H{})
}

func (s *Server) HTTPNonUeN2MessageTransfer(c *gin.Context) {
	logger.CommLog.Warnf("Handle Non Ue N2 Message Transfer is not implemented.")
	c.JSON(http.StatusOK, gin.H{})
}

func (s *Server) HTTPNonUeN2InfoSubscribe(c *gin.Context) {
	logger.CommLog.Warnf("Handle Non Ue N2 Info Subscribe is not implemented.")
	c.JSON(http.StatusOK, gin.H{})
}

func (s *Server) HTTPAMFStatusChangeSubscribe(c *gin.Context) {
	var subscriptionData models.SubscriptionData

	requestBody, err := c.GetRawData()
	if err != nil {
		logger.CommLog.Errorf("Get Request Body error: %+v", err)
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	err = openapi.Deserialize(&subscriptionData, requestBody, applicationjson)
	if err != nil {
		problemDetail := reqbody + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.CommLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, subscriptionData)
	rsp := s.Processor().HandleAMFStatusChangeSubscribeRequest(req)

	for key, val := range rsp.Header {
		c.Header(key, val[0])
	}
	responseBody, err := openapi.Serialize(rsp.Body, applicationjson)
	if err != nil {
		logger.CommLog.Errorln(err)
		problemDetails := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: err.Error(),
		}
		c.JSON(http.StatusInternalServerError, problemDetails)
	} else {
		c.Data(rsp.Status, applicationjson, responseBody)
	}
}
