package Namf_OAM

import (
	"github.com/gin-gonic/gin"
	"gofree5gc/lib/http_wrapper"
	"gofree5gc/src/amf/amf_handler/amf_message"
)

func RegisteredUEContext(c *gin.Context) {

	req := http_wrapper.NewRequest(c.Request, nil)
	if supi, exists := c.Params.Get("supi"); exists {
		req.Params["supi"] = supi
	}

	handlerMsg := amf_message.NewHandlerMessage(amf_message.EventOAMRegisteredUEContext, req)
	amf_message.SendMessage(handlerMsg)

	rsp := <-handlerMsg.ResponseChan

	HTTPResponse := rsp.HTTPResponse

	c.JSON(HTTPResponse.Status, HTTPResponse.Body)
}
