package producer

import (
	"fmt"
	"free5gc/lib/http_wrapper"
	"free5gc/lib/nas/nasMessage"
	"free5gc/lib/ngap/ngapType"
	"free5gc/lib/openapi/models"
	"free5gc/src/amf/consumer"
	"free5gc/src/amf/context"
	gmm_message "free5gc/src/amf/gmm/message"
	"free5gc/src/amf/logger"
	"free5gc/src/amf/nas"
	ngap_message "free5gc/src/amf/ngap/message"
	"net/http"
	"strconv"

	"github.com/mohae/deepcopy"
)

func HandleSmContextStatusNotify(request *http_wrapper.Request) *http_wrapper.Response {
	logger.ProducerLog.Infoln("[AMF] Handle SmContext Status Notify")

	guti := request.Params["guti"]
	pduSessionIDString := request.Params["pduSessionId"]
	var pduSessionID int
	if pduSessionIDTmp, err := strconv.Atoi(pduSessionIDString); err != nil {
		logger.ProducerLog.Warnf("PDU Session ID atoi failed: %+v", err)
	} else {
		pduSessionID = pduSessionIDTmp
	}
	smContextStatusNotification := request.Body.(models.SmContextStatusNotification)

	problemDetails := SmContextStatusNotifyProcedure(guti, int32(pduSessionID), smContextStatusNotification)
	if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	} else {
		return http_wrapper.NewResponse(http.StatusNoContent, nil, nil)
	}
}

func SmContextStatusNotifyProcedure(guti string, pduSessionID int32,
	smContextStatusNotification models.SmContextStatusNotification) *models.ProblemDetails {
	amfSelf := context.AMF_Self()

	ue, ok := amfSelf.AmfUeFindByGuti(guti)
	if !ok {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "CONTEXT_NOT_FOUND",
			Detail: fmt.Sprintf("Guti[%s] Not Found", guti),
		}
		return problemDetails
	}

	_, ok = ue.SmContextList[pduSessionID]
	if !ok {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "CONTEXT_NOT_FOUND",
			Detail: fmt.Sprintf("PDUSessionID[%d] Not Found", pduSessionID),
		}
		return problemDetails
	}

	logger.ProducerLog.Debugf("Release PDUSessionId[%d] of UE[%s] By SmContextStatus Notification because of %s",
		pduSessionID, ue.Supi, smContextStatusNotification.StatusInfo.Cause)
	delete(ue.SmContextList, pduSessionID)

	if storedSmContext, exist := ue.StoredSmContext[pduSessionID]; exist {
		go func() {
			smContextCreateData := consumer.BuildCreateSmContextRequest(ue, *storedSmContext.PduSessionContext,
				models.RequestType_INITIAL_REQUEST)

			response, smContextRef, errResponse, problemDetail, err := consumer.SendCreateSmContextRequest(
				ue, storedSmContext.SmfUri, storedSmContext.Payload, smContextCreateData)
			if response != nil {
				var smContext context.SmContext
				smContext.PduSessionContext = storedSmContext.PduSessionContext
				smContext.PduSessionContext.SmContextRef = smContextRef
				smContext.UserLocation = deepcopy.Copy(ue.Location).(models.UserLocation)
				smContext.SmfUri = storedSmContext.SmfUri
				smContext.SmfId = storedSmContext.SmfId
				ue.SmContextList[pduSessionID] = &smContext
				logger.CallbackLog.Infof("Http create smContext[pduSessionID: %d] Success", pduSessionID)
				// TODO: handle response(response N2SmInfo to RAN if exists)
			} else if errResponse != nil {
				logger.ProducerLog.Warnf("PDU Session Establishment Request is rejected by SMF[pduSessionId:%d]\n", pduSessionID)
				gmm_message.SendDLNASTransport(ue.RanUe[storedSmContext.AnType],
					nasMessage.PayloadContainerTypeN1SMInfo, errResponse.BinaryDataN1SmMessage, pduSessionID, 0, nil, 0)
			} else if err != nil {
				logger.ProducerLog.Errorf("Failed to Create smContext[pduSessionID: %d], Error[%s]\n", pduSessionID, err.Error())
			} else {
				logger.ProducerLog.Errorf("Failed to Create smContext[pduSessionID: %d], Error[%v]\n", pduSessionID, problemDetail)
			}
			delete(ue.StoredSmContext, pduSessionID)
		}()
	}

	return nil
}

func HandleAmPolicyControlUpdateNotifyUpdate(request *http_wrapper.Request) *http_wrapper.Response {
	logger.ProducerLog.Infoln("Handle AM Policy Control Update Notify [Policy update notification]")

	polAssoID := request.Params["polAssoId"]
	policyUpdate := request.Body.(models.PolicyUpdate)

	problemDetails := AmPolicyControlUpdateNotifyUpdateProcedure(polAssoID, policyUpdate)

	if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	} else {
		return http_wrapper.NewResponse(http.StatusNoContent, nil, nil)
	}
}

func AmPolicyControlUpdateNotifyUpdateProcedure(polAssoID string,
	policyUpdate models.PolicyUpdate) *models.ProblemDetails {
	amfSelf := context.AMF_Self()

	ue, ok := amfSelf.AmfUeFindByPolicyAssociationID(polAssoID)
	if !ok {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "CONTEXT_NOT_FOUND",
			Detail: fmt.Sprintf("Policy Association ID[%s] Not Found", polAssoID),
		}
		return problemDetails
	}

	ue.AmPolicyAssociation.Triggers = policyUpdate.Triggers
	ue.RequestTriggerLocationChange = false

	for _, trigger := range policyUpdate.Triggers {
		if trigger == models.RequestTrigger_LOC_CH {
			ue.RequestTriggerLocationChange = true
		}
		//if trigger == models.RequestTrigger_PRA_CH {
		// TODO: Presence Reporting Area handling (TS 23.503 6.1.2.5, TS 23.501 5.6.11)
		//}
	}

	if policyUpdate.ServAreaRes != nil {
		ue.AmPolicyAssociation.ServAreaRes = policyUpdate.ServAreaRes
	}

	if policyUpdate.Rfsp != 0 {
		ue.AmPolicyAssociation.Rfsp = policyUpdate.Rfsp
	}

	if ue != nil {
		// use go routine to write response first to ensure the order of the procedure
		go func() {
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
		}()
	}
	return nil
}

// TS 29.507 4.2.4.3
func HandleAmPolicyControlUpdateNotifyTerminate(request *http_wrapper.Request) *http_wrapper.Response {
	logger.ProducerLog.Infoln("Handle AM Policy Control Update Notify [Request for termination of the policy association]")

	polAssoID := request.Params["polAssoId"]
	terminationNotification := request.Body.(models.TerminationNotification)

	problemDetails := AmPolicyControlUpdateNotifyTerminateProcedure(polAssoID, terminationNotification)
	if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	} else {
		return http_wrapper.NewResponse(http.StatusNoContent, nil, nil)
	}
}

func AmPolicyControlUpdateNotifyTerminateProcedure(polAssoID string,
	terminationNotification models.TerminationNotification) *models.ProblemDetails {
	amfSelf := context.AMF_Self()

	ue, ok := amfSelf.AmfUeFindByPolicyAssociationID(polAssoID)
	if !ok {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "CONTEXT_NOT_FOUND",
			Detail: fmt.Sprintf("Policy Association ID[%s] Not Found", polAssoID),
		}
		return problemDetails
	}

	logger.CallbackLog.Infof("Cause of AM Policy termination[%+v]", terminationNotification.Cause)

	// use go routine to write response first to ensure the order of the procedure
	go func() {
		problem, err := consumer.AMPolicyControlDelete(ue)
		if problem != nil {
			logger.ProducerLog.Errorf("AM Policy Control Delete Failed Problem[%+v]", problem)
		} else if err != nil {
			logger.ProducerLog.Errorf("AM Policy Control Delete Error[%v]", err.Error())
		}
	}()
	return nil
}

// TS 23.502 4.2.2.2.3 Registration with AMF re-allocation
func HandleN1MessageNotify(request *http_wrapper.Request) *http_wrapper.Response {
	logger.ProducerLog.Infoln("[AMF] Handle N1 Message Notify")

	n1MessageNotify := request.Body.(models.N1MessageNotify)

	problemDetails := N1MessageNotifyProcedure(n1MessageNotify)
	if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	} else {
		return http_wrapper.NewResponse(http.StatusNoContent, nil, nil)
	}
}

func N1MessageNotifyProcedure(n1MessageNotify models.N1MessageNotify) *models.ProblemDetails {
	logger.ProducerLog.Debugf("n1MessageNotify: %+v", n1MessageNotify)

	amfSelf := context.AMF_Self()

	registrationCtxtContainer := n1MessageNotify.JsonData.RegistrationCtxtContainer
	if registrationCtxtContainer.UeContext == nil {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusBadRequest,
			Cause:  "MANDATORY_IE_MISSING", // Defined in TS 29.500 5.2.7.2
			Detail: "Missing IE [UeContext] in RegistrationCtxtContainer",
		}
		return problemDetails
	}

	ran, ok := amfSelf.AmfRanFindByRanID(*registrationCtxtContainer.RanNodeId)
	if !ok {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusBadRequest,
			Cause:  "MANDATORY_IE_INCORRECT",
			Detail: fmt.Sprintf("Can not find RAN[RanId: %+v]", *registrationCtxtContainer.RanNodeId),
		}
		return problemDetails
	}

	go func() {
		var amfUe *context.AmfUe
		ueContext := registrationCtxtContainer.UeContext
		if ueContext.Supi != "" {
			amfUe = amfSelf.NewAmfUe(ueContext.Supi)
		} else {
			amfUe = amfSelf.NewAmfUe("")
		}
		amfUe.CopyDataFromUeContextModel(*ueContext)

		ranUe := ran.RanUeFindByRanUeNgapID(int64(registrationCtxtContainer.AnN2ApId))

		ranUe.Location = *registrationCtxtContainer.UserLocation
		amfUe.Location = *registrationCtxtContainer.UserLocation
		ranUe.UeContextRequest = registrationCtxtContainer.UeContextRequest
		ranUe.OldAmfName = registrationCtxtContainer.InitialAmfName

		if registrationCtxtContainer.AllowedNssai != nil {
			allowedNssai := registrationCtxtContainer.AllowedNssai
			amfUe.AllowedNssai[allowedNssai.AccessType] = allowedNssai.AllowedSnssaiList
		}

		if len(registrationCtxtContainer.ConfiguredNssai) > 0 {
			amfUe.ConfiguredNssai = registrationCtxtContainer.ConfiguredNssai
		}

		amfUe.AttachRanUe(ranUe)

		nas.HandleNAS(ranUe, ngapType.ProcedureCodeInitialUEMessage, n1MessageNotify.BinaryDataN1Message)
	}()
	return nil
}
