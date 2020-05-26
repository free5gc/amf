package producer

import (
	"free5gc/lib/aper"
	"free5gc/lib/http_wrapper"
	"free5gc/lib/nas/nasMessage"
	"free5gc/lib/ngap/ngapType"
	"free5gc/lib/openapi/models"
	"free5gc/src/amf/context"
	"free5gc/src/amf/gmm"
	gmm_message "free5gc/src/amf/gmm/message"
	"free5gc/src/amf/gmm/state"
	amf_message "free5gc/src/amf/handler/message"
	"free5gc/src/amf/logger"
	ngap_message "free5gc/src/amf/ngap/message"
	"free5gc/src/amf/producer/callback"
	"free5gc/src/amf/util"
	"net/http"
	"strconv"
	"strings"
)

// TS23502 4.2.3.3, 4.2.4.3, 4.3.2.2, 4.3.2.3, 4.3.3.2, 4.3.7
func HandleN1N2MessageTransferRequest(request *http_wrapper.Request) *http_wrapper.Response {

	logger.ProducerLog.Infof("Handle N1N2 Message Transfer Request")

	n1n2MessageTransferRequest := request.Body.(models.N1N2MessageTransferRequest)
	ueContextID := request.Params["ueContextId"]
	reqUri := request.Params["reqUri"]

	n1n2MessageTransferRspData, locationHeader, problemDetails, transferErr := N1N2MessageTransferProcedure(ueContextID, reqUri, n1n2MessageTransferRequest)

	if n1n2MessageTransferRspData != nil {
		switch n1n2MessageTransferRspData.Cause {
		case models.N1N2MessageTransferCause_N1_MSG_NOT_TRANSFERRED:
			fallthrough
		case models.N1N2MessageTransferCause_N1_N2_TRANSFER_INITIATED:
			return http_wrapper.NewResponse(http.StatusOK, nil, n1n2MessageTransferRspData)
		case models.N1N2MessageTransferCause_ATTEMPTING_TO_REACH_UE:
			headers := http.Header{
				"Location": {locationHeader},
			}
			return http_wrapper.NewResponse(http.StatusAccepted, headers, n1n2MessageTransferRspData)
		}
	} else if problemDetails != nil {
		return http_wrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	} else if transferErr != nil {
		return http_wrapper.NewResponse(int(transferErr.Error.Status), nil, transferErr)
	}

	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}
	return http_wrapper.NewResponse(http.StatusForbidden, nil, problemDetails)
}

// There are 4 possible return value for this function:
//   - n1n2MessageTransferRspData: if AMF handle N1N2MessageTransfer Request successfully.
//   - locationHeader: if response status code is 202, then it will return a non-empty string location header for response
//   - problemDetails: if AMF reject the request due to application error, e.g. UE context not found.
//   - TransferErr: if AMF reject the request due to procedure error, e.g. UE has an ongoing procedure.
// see TS 29.518 6.1.3.5.3.1 for more details.
func N1N2MessageTransferProcedure(ueContextID string, reqUri string, n1n2MessageTransferRequest models.N1N2MessageTransferRequest) (n1n2MessageTransferRspData *models.N1N2MessageTransferRspData, locationHeader string, problemDetails *models.ProblemDetails, transferErr *models.N1N2MessageTransferError) {

	var ue *context.AmfUe
	var ok bool
	var smContext *context.SmContext

	amfSelf := context.AMF_Self()
	requestData := n1n2MessageTransferRequest.JsonData
	n2Info := n1n2MessageTransferRequest.BinaryDataN2Information
	n1Msg := n1n2MessageTransferRequest.BinaryDataN1Message
	anType := models.AccessType__3_GPP_ACCESS

	if ue, ok = amfSelf.AmfUeFindByUeContextID(ueContextID); !ok {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "CONTEXT_NOT_FOUND",
		}
		return
	}

	if requestData.N1MessageContainer != nil && requestData.N1MessageContainer.N1MessageClass == models.N1MessageClass_SM {
		smContext = ue.SmContextList[requestData.PduSessionId]
	}
	if smContext == nil && requestData.N2InfoContainer != nil && requestData.N2InfoContainer.N2InformationClass == models.N2InformationClass_SM {
		smContext = ue.SmContextList[requestData.PduSessionId]
	}
	if smContext != nil {
		anType = smContext.PduSessionContext.AccessType
	}
	onGoing := ue.OnGoing[anType]
	// TODO: Error Status 307, 403 in TS29.518 Table 6.1.3.5.3.1-3
	if onGoing != nil {
		switch onGoing.Procedure {
		case context.OnGoingProcedurePaging:
			if requestData.Ppi == 0 || (onGoing.Ppi != 0 && onGoing.Ppi <= requestData.Ppi) {
				transferErr = new(models.N1N2MessageTransferError)
				transferErr.Error = &models.ProblemDetails{
					Status: http.StatusConflict,
					Cause:  "HIGHER_PRIORITY_REQUEST_ONGOING",
				}
				return
			}
			util.ClearT3513(ue)
			callback.SendN1N2TransferFailureNotification(ue, models.N1N2MessageTransferCause_UE_NOT_RESPONDING)
		case context.OnGoingProcedureN2Handover:
			transferErr = new(models.N1N2MessageTransferError)
			transferErr.Error = &models.ProblemDetails{
				Status: http.StatusConflict,
				Cause:  "TEMPORARY_REJECT_HANDOVER_ONGOING",
			}
			return
		}
	}
	if !ue.Sm[anType].Check(state.REGISTERED) {
		transferErr = new(models.N1N2MessageTransferError)
		transferErr.Error = &models.ProblemDetails{
			Status: http.StatusConflict,
			Cause:  "TEMPORARY_REJECT_REGISTRATION_ONGOING",
		}
		return
	}

	if ue.CmConnect(anType) {
		n1n2MessageTransferRspData = new(models.N1N2MessageTransferRspData)
		n1n2MessageTransferRspData.Cause = models.N1N2MessageTransferCause_N1_N2_TRANSFER_INITIATED

		if n2Info == nil {
			switch requestData.N1MessageContainer.N1MessageClass {
			case models.N1MessageClass_SM:
				gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeN1SMInfo, n1Msg, &requestData.PduSessionId, 0, nil, 0)
			case models.N1MessageClass_LPP:
				gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeLPP, n1Msg, nil, 0, nil, 0)
			case models.N1MessageClass_SMS:
				gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeSMS, n1Msg, nil, 0, nil, 0)
			case models.N1MessageClass_UPDP:
				gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeUEPolicy, n1Msg, nil, 0, nil, 0)
			}
			return
		}
		if smContext != nil {
			smInfo := requestData.N2InfoContainer.SmInfo
			switch smInfo.N2InfoContent.NgapIeType {
			case models.NgapIeType_PDU_RES_SETUP_REQ:
				logger.ProducerLog.Debugln("AMF Transfer NGAP PDU Resource Setup Req from SMF")
				var nasPdu []byte
				var err error
				if n1Msg != nil {
					pduSessionId := uint8(smInfo.PduSessionId)
					nasPdu, err = gmm_message.BuildDLNASTransport(ue, nasMessage.PayloadContainerTypeN1SMInfo, n1Msg, &pduSessionId, nil, nil, 0)
					if err != nil {
						logger.HttpLog.Errorln(err.Error())
					}
				}
				list := ngapType.PDUSessionResourceSetupListSUReq{}
				ngap_message.AppendPDUSessionResourceSetupListSUReq(&list, smInfo.PduSessionId, *smInfo.SNssai, nasPdu, n2Info)
				ngap_message.SendPDUSessionResourceSetupRequest(ue.RanUe[anType], nil, list)
			case models.NgapIeType_PDU_RES_MOD_REQ:
				logger.ProducerLog.Debugln("AMF Transfer NGAP PDU Resource Modify Req from SMF")
				var nasPdu []byte
				var err error
				if n1Msg != nil {
					pduSessionId := uint8(smInfo.PduSessionId)
					nasPdu, err = gmm_message.BuildDLNASTransport(ue, nasMessage.PayloadContainerTypeN1SMInfo, n1Msg, &pduSessionId, nil, nil, 0)
					if err != nil {
						logger.HttpLog.Errorln(err.Error())
					}
				}
				list := ngapType.PDUSessionResourceModifyListModReq{}
				ngap_message.AppendPDUSessionResourceModifyListModReq(&list, smInfo.PduSessionId, nasPdu, n2Info)
				ngap_message.SendPDUSessionResourceModifyRequest(ue.RanUe[anType], list)

			case models.NgapIeType_PDU_RES_REL_CMD:
				logger.ProducerLog.Debugln("AMF Transfer NGAP PDU Resource Rel CMD from SMF")
				var nasPdu []byte
				var err error
				if n1Msg != nil {
					pduSessionId := uint8(smInfo.PduSessionId)
					nasPdu, err = gmm_message.BuildDLNASTransport(ue, nasMessage.PayloadContainerTypeN1SMInfo, n1Msg, &pduSessionId, nil, nil, 0)
					if err != nil {
						logger.HttpLog.Errorln(err.Error())
					}
				}
				list := ngapType.PDUSessionResourceToReleaseListRelCmd{}
				ngap_message.AppendPDUSessionResourceToReleaseListRelCmd(&list, smInfo.PduSessionId, n2Info)
				ngap_message.SendPDUSessionResourceReleaseCommand(ue.RanUe[anType], nasPdu, list)
			}
		} else {
			//TODO: send n2 info for non pdu session case
		}
		return
	}

	// 409: transfer a N2 PDU Session Resource Release Command to a 5G-AN and if the UE is in CM-IDLE
	if smContext != nil && n2Info != nil && requestData.N2InfoContainer.SmInfo.N2InfoContent.NgapIeType == models.NgapIeType_PDU_RES_REL_CMD {
		transferErr = new(models.N1N2MessageTransferError)
		transferErr.Error = &models.ProblemDetails{
			Status: http.StatusConflict,
			Cause:  "UE_IN_CM_IDLE_STATE",
		}
		return
	}
	// 504: the UE in MICO mode or the UE is only registered over Non-3GPP access and its state is CM-IDLE
	if !ue.Sm[models.AccessType__3_GPP_ACCESS].Check(state.REGISTERED) {
		transferErr = new(models.N1N2MessageTransferError)
		transferErr.Error = &models.ProblemDetails{
			Status: http.StatusGatewayTimeout,
			Cause:  "UE_NOT_REACHABLE",
		}
		return
	}

	n1n2MessageTransferRspData = new(models.N1N2MessageTransferRspData)

	var pagingPriority *ngapType.PagingPriority

	n1n2MessageID, err := ue.N1N2MessageIDGenerator.Allocate()
	if err != nil {
		logger.ProducerLog.Errorf("Allocate n1n2MessageID error: %+v", err)
		problemDetails = &models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: err.Error(),
		}
		return
	}
	locationHeader = context.AMF_Self().GetIPv4Uri() + reqUri + "/" + strconv.Itoa(int(n1n2MessageID))

	// Case A (UE is CM-IDLE in 3GPP access and the associated access type is 3GPP access) in subclause 5.2.2.3.1.2 of TS29518
	if anType == models.AccessType__3_GPP_ACCESS {
		if requestData.SkipInd && n2Info == nil {
			n1n2MessageTransferRspData.Cause = models.N1N2MessageTransferCause_N1_MSG_NOT_TRANSFERRED
		} else {
			n1n2MessageTransferRspData.Cause = models.N1N2MessageTransferCause_ATTEMPTING_TO_REACH_UE
			message := context.N1N2Message{
				Request:     n1n2MessageTransferRequest,
				Status:      n1n2MessageTransferRspData.Cause,
				ResourceUri: locationHeader,
			}
			ue.N1N2Message = &message
			onGoing.Procedure = context.OnGoingProcedurePaging
			onGoing.Ppi = requestData.Ppi
			if onGoing.Ppi != 0 {
				pagingPriority = new(ngapType.PagingPriority)
				pagingPriority.Value = aper.Enumerated(onGoing.Ppi)
			}
			pkg, err := ngap_message.BuildPaging(ue, pagingPriority, false)
			if err != nil {
				logger.NgapLog.Errorf("Build Paging failed : %s", err.Error())
				return
			}
			ngap_message.SendPaging(ue, pkg)
		}
		// TODO: WAITING_FOR_ASYNCHRONOUS_TRANSFER
		return
	}
	// Case B (UE is CM-IDLE in Non-3GPP access but CM-CONNECTED in 3GPP access and the associated access type is Non-3GPP access)in subclause 5.2.2.3.1.2 of TS29518
	if ue.CmConnect(models.AccessType__3_GPP_ACCESS) {
		if n2Info == nil {
			n1n2MessageTransferRspData.Cause = models.N1N2MessageTransferCause_N1_N2_TRANSFER_INITIATED
			gmm_message.SendDLNASTransport(ue.RanUe[models.AccessType__3_GPP_ACCESS], nasMessage.PayloadContainerTypeN1SMInfo, n1Msg, &requestData.PduSessionId, 0, nil, 0)
		} else {
			n1n2MessageTransferRspData.Cause = models.N1N2MessageTransferCause_ATTEMPTING_TO_REACH_UE
			message := context.N1N2Message{
				Request:     n1n2MessageTransferRequest,
				Status:      n1n2MessageTransferRspData.Cause,
				ResourceUri: locationHeader,
			}
			ue.N1N2Message = &message
			nasMsg, err := gmm_message.BuildNotification(ue, nasMessage.AccessTypeNon3GPP)
			if err != nil {
				logger.GmmLog.Errorf("Build Notification failed : %s", err.Error())
				return
			}
			gmm_message.SendNotification(ue.RanUe[models.AccessType__3_GPP_ACCESS], nasMsg)
		}
		return
	}
	// Case C ( UE is CM-IDLE in both Non-3GPP access and 3GPP access and the associated access ype is Non-3GPP access) in subclause 5.2.2.3.1.2 of TS29518
	n1n2MessageTransferRspData.Cause = models.N1N2MessageTransferCause_ATTEMPTING_TO_REACH_UE
	message := context.N1N2Message{
		Request:     n1n2MessageTransferRequest,
		Status:      n1n2MessageTransferRspData.Cause,
		ResourceUri: locationHeader,
	}
	ue.N1N2Message = &message

	onGoing.Procedure = context.OnGoingProcedurePaging
	onGoing.Ppi = requestData.Ppi
	if onGoing.Ppi != 0 {
		pagingPriority = new(ngapType.PagingPriority)
		pagingPriority.Value = aper.Enumerated(onGoing.Ppi)
	}
	pkg, err := ngap_message.BuildPaging(ue, pagingPriority, true)
	if err != nil {
		logger.NgapLog.Errorf("Build Paging failed : %s", err.Error())
	}
	ngap_message.SendPaging(ue, pkg)
	return
}

func HandleN1N2MessageTransferStatusRequest(httpChannel chan amf_message.HandlerResponseMessage, ueContextId, reqUri string) {
	var problem models.ProblemDetails
	var ue *context.AmfUe
	var ok bool
	amfSelf := context.AMF_Self()
	if strings.HasPrefix(ueContextId, "imsi") {

		if ue, ok = amfSelf.AmfUeFindBySupi(ueContextId); !ok {
			problem.Status = 404
			problem.Cause = "CONTEXT_NOT_FOUND"
			amf_message.SendHttpResponseMessage(httpChannel, nil, http.StatusNotFound, problem)
			return
		}
	} else if strings.HasPrefix(ueContextId, "imei") {
		amfSelf.UePool.Range(func(key, value interface{}) bool {
			ue1 := value.(*context.AmfUe)
			if ue1.Pei == ueContextId {
				ue = ue1
				return false
			}
			return true
		})
		if ue == nil {
			problem.Status = 404
			problem.Cause = "CONTEXT_NOT_FOUND"
			amf_message.SendHttpResponseMessage(httpChannel, nil, http.StatusNotFound, problem)
			return
		}
	}
	resourceUri := context.AMF_Self().GetIPv4Uri() + reqUri
	n1n2Message := ue.N1N2Message
	if n1n2Message == nil || n1n2Message.ResourceUri != resourceUri {
		problem.Status = 404
		problem.Cause = "CONTEXT_NOT_FOUND"
		amf_message.SendHttpResponseMessage(httpChannel, nil, http.StatusNotFound, problem)
		return
	}
	amf_message.SendHttpResponseMessage(httpChannel, nil, http.StatusOK, n1n2Message.Status)
}

func HandleN1N2MessageSubscirbeRequest(httpChannel chan amf_message.HandlerResponseMessage, ueContextId string, body models.UeN1N2InfoSubscriptionCreateData) {
	var response models.UeN1N2InfoSubscriptionCreatedData

	var ue *context.AmfUe
	var ok bool
	amfSelf := context.AMF_Self()

	if strings.HasPrefix(ueContextId, "imsi") {
		if ue, ok = amfSelf.AmfUeFindBySupi(ueContextId); !ok {
			ue = amfSelf.NewAmfUe(ueContextId)
			if err := gmm.InitAmfUeSm(ue); err != nil {
				HttpLog.Errorf("InitAmfUeSm error: %v", err.Error())
			}
		}
	}
	if ue != nil {
		newSubscriptionID := strconv.Itoa(ue.N1N2MessageSubscribeIDGenerator)
		ue.N1N2MessageSubscribeInfo[newSubscriptionID] = &body
		ue.N1N2SubscriptionID = newSubscriptionID
		response.N1n2NotifySubscriptionId = ue.N1N2SubscriptionID
		ue.N1N2MessageSubscribeIDGenerator++
	}
	amf_message.SendHttpResponseMessage(httpChannel, nil, http.StatusCreated, response)
}

func HandleN1N2MessageUnSubscribeRequest(httpChannel chan amf_message.HandlerResponseMessage, ueContextId string, subscriptionId string) {
	var ue *context.AmfUe
	var ok bool
	amfSelf := context.AMF_Self()

	if strings.HasPrefix(ueContextId, "imsi") {
		if ue, ok = amfSelf.AmfUeFindBySupi(ueContextId); ok {
			_, ok := ue.N1N2MessageSubscribeInfo[subscriptionId]
			if ok {
				delete(ue.N1N2MessageSubscribeInfo, subscriptionId)
			}
			amf_message.SendHttpResponseMessage(httpChannel, nil, http.StatusNoContent, nil)
		}
	}
	amf_message.SendHttpResponseMessage(httpChannel, nil, http.StatusBadRequest, nil)
}
