package httpcallback

import (
	"net/http"

	"github.com/gin-gonic/gin"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
)

func HTTPHandleDeregistrationNotification(c *gin.Context) {
	// TS 23.502 - 4.2.2.2.2 - step 14d
	logger.CallbackLog.Infoln("Handle Deregistration Notification")

	var deregData models.DeregistrationData

	requestBody, err := c.GetRawData()
	if err != nil {
		logger.CallbackLog.Errorf("Get Request Body error: %+v", err)
		problemDetails := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		c.JSON(http.StatusInternalServerError, problemDetails)
		return
	}

	err = openapi.Deserialize(&deregData, requestBody, "application/json")
	if err != nil {
		problemDetails := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: "[Request Body] " + err.Error(),
		}
		logger.CallbackLog.Errorln(problemDetails.Detail)
		c.JSON(http.StatusBadRequest, problemDetails)
		return
	}

	ueid := c.Param("ueid")
	deregType := c.Query("type")
	ue, ok := amf_context.GetSelf().AmfUeFindByUeContextID(ueid)
	if !ok {
		logger.CallbackLog.Errorf("AmfUe Context[%s] not found", ueid)
		problemDetails := models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "CONTEXT_NOT_FOUND",
		}
		c.JSON(http.StatusNotFound, problemDetails)
		return
	}

	problemDetails, err := DeregistrationNotificationProcedure(ue, deregType, deregData)
	if problemDetails != nil {
		ue.GmmLog.Errorf("Deregistration Notification Procedure Failed Problem[%+v]", problemDetails)
	} else if err != nil {
		ue.GmmLog.Errorf("Deregistration Notification Procedure Error[%v]", err.Error())
	}
	// TS 23.503 - 5.3.2.3.2 UDM initiated NF Deregistration
	// The AMF acknowledges the Nudm_UECM_DeRegistrationNotification to the UDM.
	c.JSON(http.StatusNoContent, nil)
}

// TS 23.502 - 4.2.2.3.3 Network-initiated Deregistration
// The AMF can initiate this procedure for either explicit (e.g. by O&M intervention) or
// implicit (e.g. expiring of Implicit Deregistration timer)
func DeregistrationNotificationProcedure(ue *amf_context.AmfUe, deregType string, deregData models.DeregistrationData) (
	problemDetails *models.ProblemDetails, err error,
) {
	var doUecmDereg bool = true

	if deregType == "implicit" {
		// The AMF does not send the Deregistration Request message to the UE for Implicit Deregistration.
		switch deregData.DeregReason {
		case models.DeregistrationReason_UE_INITIAL_REGISTRATION:
			// TS 23.502 - 4.2.2.2.2 General Registration
			// Invokes the Nsmf_PDUSession_ReleaseSMContext for the corresponding access type
			ue.SmContextList.Range(func(key, value interface{}) bool {
				smContext := value.(*amf_context.SmContext)
				if smContext.AccessType() == deregData.AccessType {
					problemDetails, err = consumer.SendReleaseSmContextRequest(ue, smContext, nil, "", nil)
					if problemDetails != nil {
						ue.GmmLog.Errorf("Release SmContext Failed Problem[%+v]", problemDetails)
					} else if err != nil {
						ue.GmmLog.Errorf("Release SmContext Error[%v]", err.Error())
					}
				}
				return true
			})
		case models.DeregistrationReason_SUBSCRIPTION_WITHDRAWN:
			// The notification is triggered by the new AMF executing UECM registration,
			// UDM will use the new data to replace the old context.
			// Therefore old AMF doesn't need to execute UECM de-registration to clean the old context stored in UDM.
			doUecmDereg = false
		}
		// TS 23.502 - 4.2.2.2.2 General Registration - 14e
		// TODO: (R16) If old AMF does not have UE context for another access type (i.e. non-3GPP access),
		// the Old AMF unsubscribes with the UDM for subscription data using Nudm_SDM_unsubscribe
		if ue.SdmSubscriptionId != "" {
			problemDetails, err = consumer.SDMUnsubscribe(ue)
			if problemDetails != nil {
				logger.GmmLog.Errorf("SDM Unubscribe Failed Problem[%+v]", problemDetails)
			} else if err != nil {
				logger.GmmLog.Errorf("SDM Unubscribe Error[%+v]", err)
			}
			ue.SdmSubscriptionId = ""
		}

		if doUecmDereg {
			if ue.UeCmRegistered[deregData.AccessType] {
				problemDetails, err := consumer.UeCmDeregistration(ue, deregData.AccessType)
				if problemDetails != nil {
					logger.GmmLog.Errorf("UECM Deregistration Failed Problem[%+v]", problemDetails)
				} else if err != nil {
					logger.GmmLog.Errorf("UECM Deregistration Error[%+v]", err)
				}
				ue.UeCmRegistered[deregData.AccessType] = false
			}
		}

		// TS 23.502 - 4.2.2.2.2 General Registration - 20
		if ue.PolicyAssociationId != "" {
			// TODO: It also needs to check if the PCF ID is tranfered to new AMF
			// Currently, old AMF will transfer the PCF ID but new AMF will not utilize the PCF ID
			problemDetails, err := consumer.AMPolicyControlDelete(ue)
			if problemDetails != nil {
				logger.GmmLog.Errorf("Delete AM policy Failed Problem[%+v]", problemDetails)
			} else if err != nil {
				logger.GmmLog.Errorf("Delete AM policy Error[%+v]", err)
			}
		}

		// The old AMF should clean the UE context
		// TODO: (R16) Only remove the target access UE context
		ue.Remove()
	} else if deregType == "explicit" {
		// TODO: TS 23.502 - 4.2.2.3.3 Network-initiated Deregistration
		// AMF may need to send Deregistration Request message to the UE.
	} else {
		logger.CallbackLog.Errorf("Deregistration Notification Procedure: unknown deregistration type: %v", deregType)
	}

	return nil, nil
}
