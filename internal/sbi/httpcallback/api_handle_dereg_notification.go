package httpcallback

import (
	"net/http"

	"github.com/gin-gonic/gin"

	amf_context "github.com/free5gc/amf/internal/context"
	gmm_common "github.com/free5gc/amf/internal/gmm/common"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
)

func HTTPAmfHandleDeregistrationNotification(c *gin.Context) {
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
		problemDetails := "[Request Body] " + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetails,
		}
		logger.CallbackLog.Errorln(problemDetails)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	ueid := c.Param("ueid")
	amfSelf := amf_context.GetSelf()
	ue, ok := amfSelf.AmfUeFindByUeContextID(ueid)
	if !ok {
		logger.CallbackLog.Errorf("AmfUe Context[%s] not found", ueid)
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "CONTEXT_NOT_FOUND",
		}
		c.JSON(http.StatusNotFound, problemDetails)
		return
	}

	switch deregData.DeregReason {
	case models.DeregistrationReason_UE_INITIAL_REGISTRATION:
		// TS 23.502 - 4.2.2.2.2 General Registration
		// Invokes the Nsmf_PDUSession_ReleaseSMContext for the corresponding access type
		ue.SmContextList.Range(func(key, value interface{}) bool {
			smContext := value.(*amf_context.SmContext)

			if smContext.AccessType() == deregData.AccessType {
				var problemDetails *models.ProblemDetails
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
		// TS 23.502 - 4.2.2.3.3 Network-initiated Deregistration
		// The AMF executes Deregistration procedure over the access(es) the Access Type indicates

		// Use old AMF as the backup AMF
		backupAmfInfo := models.BackupAmfInfo{
			BackupAmf: amfSelf.Name,
			GuamiList: amfSelf.ServedGuamiList,
		}
		ue.UpdateBackupAmfInfo(backupAmfInfo)
	}

	// TS 23.502 - 4.2.2.2.2 General Registration
	// The old AMF should clean the UE context
	// The AMF also unsubscribes with the UDM using Nudm_SDM_Unsubscribe service operation.
	err = gmm_common.PurgeSubscriberData(ue, deregData.AccessType)
	if err != nil {
		logger.CallbackLog.Errorf("Purge subscriber data Error: %v", err)
	}
	// TODO: (R16) Only remove the target access UE context
	ue.Remove()

	// TS 23.503 - 5.3.2.3.2 UDM initiated NF Deregistration
	// The AMF acknowledges the Nudm_UECM_DeRegistrationNotification to the UDM.
	c.JSON(http.StatusNoContent, nil)
}
