package Namf_OAM

import (
	"github.com/gin-gonic/gin"
	"gofree5gc/src/amf/amf_handler/amf_message"
)

func RegisteredUEContext(c *gin.Context) {
	handlerMsg := amf_message.NewHandlerMessage(amf_message.EventOAMRegisteredUEContext, nil)
	amf_message.SendMessage(handlerMsg)

	rsp := <-handlerMsg.ResponseChan

	HTTPResponse := rsp.HTTPResponse

	c.JSON(HTTPResponse.Status, HTTPResponse.Body)
}
