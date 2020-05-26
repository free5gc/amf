/*
 * Namf_Communication
 *
 * AMF Communication Service
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package communication

import (
	"free5gc/src/amf/logger"
	"github.com/sirupsen/logrus"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

var HttpLog *logrus.Entry

func init() {
	HttpLog = logger.HttpLog
}

// Route is the information for every URI.
type Route struct {
	// Name is the name of this Route.
	Name string
	// Method is the string for the HTTP method. ex) GET, POST etc..
	Method string
	// Pattern is the pattern of the URI.
	Pattern string
	// HandlerFunc is the handler function of this route.
	HandlerFunc gin.HandlerFunc
}

// Routes is the list of the generated Route.
type Routes []Route

// NewRouter returns a new router.
func NewRouter() *gin.Engine {
	router := gin.Default()
	AddService(router)
	return router
}

func AddService(engine *gin.Engine) *gin.RouterGroup {
	group := engine.Group("/namf-comm/v1")

	for _, route := range routes {
		switch route.Method {
		case "GET":
			group.GET(route.Pattern, route.HandlerFunc)
		case "POST":
			group.POST(route.Pattern, route.HandlerFunc)
		case "PUT":
			group.PUT(route.Pattern, route.HandlerFunc)
		case "DELETE":
			group.DELETE(route.Pattern, route.HandlerFunc)
		}
	}
	return group
}

// Index is the index handler.
func Index(c *gin.Context) {
	c.String(http.StatusOK, "Hello World!")
}

var routes = Routes{
	{
		"Index",
		"GET",
		"/",
		Index,
	},

	{
		"AMFStatusChangeSubscribeModfy",
		strings.ToUpper("Put"),
		"/subscriptions/:subscriptionId",
		AMFStatusChangeSubscribeModfy,
	},

	{
		"AMFStatusChangeUnSubscribe",
		strings.ToUpper("Delete"),
		"/subscriptions/:subscriptionId",
		AMFStatusChangeUnSubscribe,
	},

	{
		"CreateUEContext",
		strings.ToUpper("Put"),
		"/ue-contexts/:ueContextId",
		CreateUEContext,
	},

	{
		"EBIAssignment",
		strings.ToUpper("Post"),
		"/ue-contexts/:ueContextId/assign-ebi",
		EBIAssignment,
	},

	{
		"RegistrationStatusUpdate",
		strings.ToUpper("Post"),
		"/ue-contexts/:ueContextId/transfer-update",
		RegistrationStatusUpdate,
	},

	{
		"ReleaseUEContext",
		strings.ToUpper("Post"),
		"/ue-contexts/:ueContextId/release",
		ReleaseUEContext,
	},

	{
		"UEContextTransfer",
		strings.ToUpper("Post"),
		"/ue-contexts/:ueContextId/transfer",
		UEContextTransfer,
	},

	{
		"N1N2MessageUnSubscribe",
		strings.ToUpper("Delete"),
		"/ue-contexts/:ueContextId/n1-n2-messages/subscriptions/:subscriptionId",
		N1N2MessageUnSubscribe,
	},

	{
		"N1N2MessageTransfer",
		strings.ToUpper("Post"),
		"/ue-contexts/:ueContextId/n1-n2-messages",
		HTTPN1N2MessageTransfer,
	},

	{
		"N1N2MessageTransferStatus",
		strings.ToUpper("Get"),
		"/ue-contexts/:ueContextId/n1-n2-messages/:n1N2MessageId",
		N1N2MessageTransferStatus,
	},

	{
		"N1N2MessageSubscribe",
		strings.ToUpper("Post"),
		"/ue-contexts/:ueContextId/n1-n2-messages/subscriptions",
		N1N2MessageSubscribe,
	},

	{
		"NonUeN2InfoUnSubscribe",
		strings.ToUpper("Delete"),
		"/non-ue-n2-messages/subscriptions/:n2NotifySubscriptionId",
		NonUeN2InfoUnSubscribe,
	},

	{
		"NonUeN2MessageTransfer",
		strings.ToUpper("Post"),
		"/non-ue-n2-messages/transfer",
		NonUeN2MessageTransfer,
	},

	{
		"NonUeN2InfoSubscribe",
		strings.ToUpper("Post"),
		"/non-ue-n2-messages/subscriptions",
		NonUeN2InfoSubscribe,
	},

	{
		"AMFStatusChangeSubscribe",
		strings.ToUpper("Post"),
		"/subscriptions",
		AMFStatusChangeSubscribe,
	},
}
