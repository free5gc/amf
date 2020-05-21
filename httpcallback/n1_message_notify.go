package httpcallback

import (
	"free5gc/lib/http_wrapper"
	"free5gc/lib/openapi/models"
	amf_message "free5gc/src/amf/handler/message"
	"free5gc/src/amf/logger"
	"net/http"

	"github.com/gin-gonic/gin"
)

func N1MessageNotify(c *gin.Context) {
	var request models.N1MessageNotification

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

	handlerMsg := amf_message.NewHandlerMessage(amf_message.EventN1MessageNotify, req)
	amf_message.SendMessage(handlerMsg)

	rsp := <-handlerMsg.ResponseChan

	HTTPResponse := rsp.HTTPResponse

	c.JSON(HTTPResponse.Status, HTTPResponse.Body)
}
