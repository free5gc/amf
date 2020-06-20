package httpcallback

import (
	"free5gc/lib/http_wrapper"
	"free5gc/lib/openapi"
	"free5gc/lib/openapi/models"
	"free5gc/src/amf/context"
	gmm_message "free5gc/src/amf/gmm/message"
	amf_message "free5gc/src/amf/handler/message"
	"free5gc/src/amf/logger"
	ngap_message "free5gc/src/amf/ngap/message"
	"free5gc/src/amf/producer"
	"net/http"

	"github.com/gin-gonic/gin"
)

func HTTPAmPolicyControlUpdateNotifyUpdate(c *gin.Context) {
	var policyUpdate models.PolicyUpdate

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

	err = openapi.Deserialize(&policyUpdate, requestBody, "application/json")
	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.CommLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := http_wrapper.NewRequest(c.Request, policyUpdate)
	req.Params["polAssoId"] = c.Params.ByName("polAssoId")

	ue, rsp := producer.HandleAmPolicyControlUpdateNotifyUpdate(req)

	responseBody, err := openapi.Serialize(rsp.Body, "application/json")
	if err != nil {
		logger.CommLog.Errorln(err)
		problemDetails := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: err.Error(),
		}
		c.JSON(http.StatusInternalServerError, problemDetails)
	} else {
		c.Data(rsp.Status, "application/json", responseBody)
	}

	if ue != nil {
		// UE is CM-Connected State
		if ue.CmConnect(models.AccessType__3_GPP_ACCESS) {
			gmm_message.SendConfigurationUpdateCommand(ue, models.AccessType__3_GPP_ACCESS, nil)
			// UE is CM-IDLE => paging
		} else {
			message, err := gmm_message.BuildConfigurationUpdateCommand(ue, models.AccessType__3_GPP_ACCESS, nil)
			if err != nil {
				logger.GmmLog.Errorf("Build Configuration Update Command Failed : %s", err.Error())
				return
			}

			ue.ConfigurationUpdateMessage = message
			ue.OnGoing[models.AccessType__3_GPP_ACCESS].Procedure = context.OnGoingProcedurePaging

			pkg, err := ngap_message.BuildPaging(ue, nil, false)
			if err != nil {
				logger.NgapLog.Errorf("Build Paging failed : %s", err.Error())
				return
			}
			ngap_message.SendPaging(ue, pkg)
		}
	}
}

func HTTPAmPolicyControlUpdateNotifyTerminate(c *gin.Context) {

	var request models.TerminationNotification

	err := c.ShouldBindJSON(&request)
	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.CallbackLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := http_wrapper.NewRequest(c.Request, request)
	req.Params["polAssoId"] = c.Params.ByName("polAssoId")

	handlerMsg := amf_message.NewHandlerMessage(amf_message.EventAmPolicyControlUpdateNotifyTerminate, req)
	amf_message.SendMessage(handlerMsg)

	rsp := <-handlerMsg.ResponseChan

	HTTPResponse := rsp.HTTPResponse

	c.JSON(HTTPResponse.Status, HTTPResponse.Body)
}
