package producer

import (
	"free5gc/lib/http_wrapper"
	"free5gc/lib/openapi/models"
	amf_message "free5gc/src/amf/handler/message"
	"free5gc/src/amf/consumer"
	"free5gc/src/amf/context"
	"free5gc/src/amf/gmm"
	"free5gc/src/amf/logger"
	"net/http"
	"strings"
)

// TS 29.518 5.2.2.2.3
func HandleCreateUeContextRequest(request *http_wrapper.Request) *http_wrapper.Response {
	var createUeContextResponse models.CreateUeContextResponse
	var rspErr models.UeContextCreateError
	var problem models.ProblemDetails
	amfSelf := context.AMF_Self()

	createUeContextRequest := request.Body.(models.CreateUeContextRequest)
	ueContextID := request.Params["ueContextId"]
	ueContextCreateData := createUeContextRequest.JsonData

	if ueContextCreateData.UeContext == nil || ueContextCreateData.TargetId == nil || ueContextCreateData.PduSessionList == nil || ueContextCreateData.SourceToTargetData == nil || ueContextCreateData.N2NotifyUri == "" {
		{
			rspErr.Error = &problem
			problem.Status = 403
			problem.Cause = "HANDOVER_FAILURE"
			return http_wrapper.NewResponse(http.StatusForbidden, nil, rspErr)
		}
	}
	// create the UE context in target amf
	ue := amfSelf.NewAmfUe(ueContextID)
	if err := gmm.InitAmfUeSm(ue); err != nil {
		HttpLog.Errorf("InitAmfUeSm error: %v", err.Error())
	}
	//amfSelf.AmfRanSetByRanId(*ueContextCreateData.TargetId.RanNodeId)
	// ue.N1N2Message[ueContextId] = &context.N1N2Message{}
	// ue.N1N2Message[ueContextId].Request.JsonData = &models.N1N2MessageTransferReqData{
	// 	N2InfoContainer: &models.N2InfoContainer{
	// 		SmInfo: &models.N2SmInformation{
	// 			N2InfoContent: ueContextCreateData.SourceToTargetData,
	// 		},
	// 	},
	// }
	ue.HandoverNotifyUri = ueContextCreateData.N2NotifyUri

	amfSelf.AmfRanFindByRanId(*ueContextCreateData.TargetId.RanNodeId)
	supportedTAI := context.NewSupportedTAI()
	supportedTAI.Tai.Tac = ueContextCreateData.TargetId.Tai.Tac
	supportedTAI.Tai.PlmnId = ueContextCreateData.TargetId.Tai.PlmnId
	ue.N1N2MessageSubscribeInfo[ueContextID] = &models.UeN1N2InfoSubscriptionCreateData{
		N2NotifyCallbackUri: ueContextCreateData.N2NotifyUri,
	}
	ue.UnauthenticatedSupi = ueContextCreateData.UeContext.SupiUnauthInd
	//should be smInfo list

	for _, smInfo := range ueContextCreateData.PduSessionList {
		if smInfo.N2InfoContent.NgapIeType == "NgapIeType_HANDOVER_REQUIRED" {
			// ue.N1N2Message[amfSelf.Uri].Request.JsonData.N2InfoContainer.SmInfo = &smInfo
		}
	}

	ue.RoutingIndicator = ueContextCreateData.UeContext.RoutingIndicator

	// optional
	ue.UdmGroupId = ueContextCreateData.UeContext.UdmGroupId
	ue.AusfGroupId = ueContextCreateData.UeContext.AusfGroupId
	//ueContextCreateData.UeContext.HpcfId
	ue.RatType = ueContextCreateData.UeContext.RestrictedRatList[0] //minItem = -1
	//ueContextCreateData.UeContext.ForbiddenAreaList
	//ueContextCreateData.UeContext.ServiceAreaRestriction
	//ueContextCreateData.UeContext.RestrictedCoreNwTypeList

	//it's not in 5.2.2.1.1 step 2a, so don't support
	//ue.Gpsi = ueContextCreateData.UeContext.GpsiList
	//ue.Pei = ueContextCreateData.UeContext.Pei
	//ueContextCreateData.UeContext.GroupList
	//ueContextCreateData.UeContext.DrxParameter
	//ueContextCreateData.UeContext.SubRfsp
	//ueContextCreateData.UeContext.UsedRfsp
	//ue.UEAMBR = ueContextCreateData.UeContext.SubUeAmbr
	//ueContextCreateData.UeContext.SmsSupport
	//ueContextCreateData.UeContext.SmsfId
	//ueContextCreateData.UeContext.SeafData
	//ueContextCreateData.UeContext.Var5gMmCapability
	//ueContextCreateData.UeContext.PcfId
	//ueContextCreateData.UeContext.PcfAmPolicyUri
	//ueContextCreateData.UeContext.AmPolicyReqTriggerList
	//ueContextCreateData.UeContext.EventSubscriptionList
	//ueContextCreateData.UeContext.MmContextList
	//ue.CurPduSession.PduSessionId = ueContextCreateData.UeContext.SessionContextList.
	//ue.TraceData = ueContextCreateData.UeContext.TraceData
	createUeContextResponse.JsonData = &models.UeContextCreatedData{
		UeContext: &models.UeContext{
			Supi: ueContextCreateData.UeContext.Supi,
		},
	}

	// response.JsonData.TargetToSourceData = ue.N1N2Message[ueContextId].Request.JsonData.N2InfoContainer.SmInfo.N2InfoContent
	createUeContextResponse.JsonData.PduSessionList = ueContextCreateData.PduSessionList
	createUeContextResponse.JsonData.PcfReselectedInd = false // TODO:When  Target AMF selects a nw PCF for AM policy, set the flag to true.

	//response.UeContext = ueContextCreateData.UeContext
	//response.TargetToSourceData = ue.N1N2Message[amfSelf.Uri].Request.JsonData.N2InfoContainer.SmInfo.N2InfoContent
	//response.PduSessionList = ueContextCreateData.PduSessionList
	//response.PcfReselectedInd = false // TODO:When  Target AMF selects a nw PCF for AM policy, set the flag to true.
	//

	return http_wrapper.NewResponse(http.StatusCreated, nil, createUeContextResponse)
}

// TS 29.518 5.2.2.2.4
func HandleReleaseUEContextRequest(request *http_wrapper.Request) *http_wrapper.Response {
	var problem models.ProblemDetails
	var ue *context.AmfUe
	var ok bool
	amfSelf := context.AMF_Self()
	ueContextRelease := request.Body.(models.UeContextRelease)
	ueContextID := request.Params["ueContextId"]

	// emergency handle
	if ueContextRelease.Supi != "" {
		if ueContextRelease.UnauthenticatedSupi {

		}
	}

	if strings.HasPrefix(ueContextID, "imsi") {
		if ue, ok = amfSelf.AmfUeFindBySupi(ueContextID); !ok {
			problem.Status = http.StatusNotFound
			problem.Cause = "CONTEXT_NOT_FOUND"
			return http_wrapper.NewResponse(http.StatusNotFound, nil, problem)
		}
	} else if strings.HasPrefix(ueContextID, "imei") {
		amfSelf.UePool.Range(func(key, value interface{}) bool {
			ue1 := value.(*context.AmfUe)
			if ue1.Pei == ueContextID {
				ue = ue1
				return false
			}
			return true
		})
		if ue == nil {
			problem.Status = http.StatusForbidden
			problem.Cause = "SUPI_OR_PEI_UNKNOWN"
			return http_wrapper.NewResponse(http.StatusForbidden, nil, problem)
		}
	}
	if ue != nil {
		ue.Remove()
	}
	// TODO : Ngap handle
	//if ueContextRelease.NgapCause.Group == ngapType.CauseRadioNetwork{
	//	if ueContextRelease.NgapCause.Value == 	ngapType.CauseRadioNetworkPresentHandoverCancelled {
	//
	//	}
	//}
	//ueContextRelease.NgapCause.Value
	return http_wrapper.NewResponse(http.StatusNoContent, nil, nil)
}

// TS 29.518 5.2.2.2.1
func HandleUEContextTransferRequest(request *http_wrapper.Request) *http_wrapper.Response {
	var responseBody models.UeContextTransferResponse
	var problem models.ProblemDetails
	var ue *context.AmfUe
	var ok bool
	amfSelf := context.AMF_Self()

	ueContextTransferRequest := request.Body.(models.UeContextTransferRequest)
	ueContextID := request.Params["ueContextId"]

	if ueContextTransferRequest.JsonData == nil {
		problem.Status = http.StatusForbidden
		problem.Cause = "CONTEXT_NOT_FOUND"
		return http_wrapper.NewResponse(http.StatusForbidden, nil, problem)
	}
	UeContextTransferReqData := ueContextTransferRequest.JsonData

	if UeContextTransferReqData.AccessType == "" || UeContextTransferReqData.Reason == "" {
		problem.Status = http.StatusForbidden
		problem.Cause = "CONTEXT_NOT_FOUND"
		return http_wrapper.NewResponse(http.StatusForbidden, nil, problem)
	}

	if strings.HasPrefix(ueContextID, "imsi") {
		if ue, ok = amfSelf.AmfUeFindBySupi(ueContextID); !ok {
			problem.Status = http.StatusForbidden
			problem.Cause = "CONTEXT_NOT_FOUND"
			return http_wrapper.NewResponse(http.StatusForbidden, nil, problem)
		}
	} else if strings.HasPrefix(ueContextID, "imei") {
		amfSelf.UePool.Range(func(key, value interface{}) bool {
			ue1 := value.(*context.AmfUe)
			if ue1.Pei == ueContextID {
				ue = ue1
				return false
			}
			return true
		})
		if ue == nil {
			problem.Status = http.StatusForbidden
			problem.Cause = "CONTEXT_NOT_FOUND"
			return http_wrapper.NewResponse(http.StatusForbidden, nil, problem)
		}
	} else if strings.HasPrefix(ueContextID, "5g-guti") {
		guti := ueContextID[strings.LastIndex(ueContextID, "-")+1:]
		if ue, ok = amfSelf.GutiPool[guti]; !ok {
			problem.Status = http.StatusForbidden
			problem.Cause = "CONTEXT_NOT_FOUND"
			return http_wrapper.NewResponse(http.StatusForbidden, nil, problem)
		}
	}

	responseBody.JsonData = new(models.UeContextTransferRspData)
	ueContextTransferRspData := responseBody.JsonData

	if ue != nil {
		if ue.GetAnType() != UeContextTransferReqData.AccessType {
			for _, tai := range ue.RegistrationArea[ue.GetAnType()] {
				if UeContextTransferReqData.PlmnId == tai.PlmnId {
					// TODO : generate N2 signalling
				}
			}
		}
		if UeContextTransferReqData.Reason == models.TransferReason_INIT_REG {
			// TODO optional
			//m := nas.NewMessage()
			//m.GmmMessage = nas.NewGmmMessage()
			//m.GmmHeader.SetMessageType(nas.MsgTypeRegistrationRequest)
			//m.GmmMessageDecode(&body.BinaryDataN1Message)
			//
			//registrationType5GS := m.RegistrationRequest.NgksiAndRegistrationType5GS.GetRegistrationType5GS()
			//switch registrationType5GS {
			//default:
			//	logger.ProducerLog.Debugln(registrationType5GS)
			//}
			//mobileIdentity5GSContents := m.RegistrationRequest.MobileIdentity5GS.GetMobileIdentity5GSContents()
			//switch mobileIdentity5GSContents[0] & 0x07 {
			//// cover guti and compare
			//}
			ueContextTransferRspData.UeContext = &models.UeContext{
				Supi:                     ue.Supi,
				SupiUnauthInd:            ue.UnauthenticatedSupi,
				GpsiList:                 nil,
				Pei:                      "",
				UdmGroupId:               ue.UdmGroupId,
				AusfGroupId:              ue.AusfGroupId,
				RoutingIndicator:         ue.RoutingIndicator,
				GroupList:                nil,
				DrxParameter:             "",
				SubRfsp:                  0,
				UsedRfsp:                 0,
				SubUeAmbr:                nil,
				SmsSupport:               "",
				SmsfId:                   "",
				SeafData:                 nil,
				Var5gMmCapability:        "",
				PcfId:                    "",
				PcfAmPolicyUri:           "",
				AmPolicyReqTriggerList:   nil,
				HpcfId:                   "",
				RestrictedRatList:        []models.RatType{ue.RatType},
				ForbiddenAreaList:        nil,
				ServiceAreaRestriction:   nil,
				RestrictedCoreNwTypeList: nil,
				EventSubscriptionList:    nil,
				MmContextList:            nil,
				SessionContextList:       nil,
				TraceData:                nil,
			}
		} else if UeContextTransferReqData.Reason == models.TransferReason_MOBI_REG {
			ueContextTransferRspData.UeContext = &models.UeContext{
				Supi:                     ue.Supi,
				SupiUnauthInd:            ue.UnauthenticatedSupi,
				GpsiList:                 nil,
				Pei:                      "",
				UdmGroupId:               ue.UdmGroupId,
				AusfGroupId:              ue.AusfGroupId,
				RoutingIndicator:         ue.RoutingIndicator,
				GroupList:                nil,
				DrxParameter:             "",
				SubRfsp:                  0,
				UsedRfsp:                 0,
				SubUeAmbr:                nil,
				SmsSupport:               "",
				SmsfId:                   "",
				SeafData:                 nil,
				Var5gMmCapability:        "",
				PcfId:                    "",
				PcfAmPolicyUri:           "",
				AmPolicyReqTriggerList:   nil,
				HpcfId:                   "",
				RestrictedRatList:        []models.RatType{ue.RatType},
				ForbiddenAreaList:        nil,
				ServiceAreaRestriction:   nil,
				RestrictedCoreNwTypeList: nil,
				EventSubscriptionList:    nil,
				MmContextList:            nil,
				SessionContextList:       nil,
				TraceData:                nil,
			}
			ueContextTransferRspData.UeRadioCapability = &models.N2InfoContent{
				NgapMessageType: 0,
				NgapIeType:      models.NgapIeType_UE_RADIO_CAPABILITY,
				NgapData: &models.RefToBinaryData{
					ContentId: "1",
				},
			}
			b := []byte(ue.UeRadioCapability)
			copy(responseBody.BinaryDataN2Information, b)
		} else {
			logger.ProducerLog.Errorln("error Reason")
			problem.Status = http.StatusForbidden
			problem.Cause = "CONTEXT_NOT_FOUND"
			return http_wrapper.NewResponse(http.StatusForbidden, nil, problem)
		}
	}
	return http_wrapper.NewResponse(http.StatusOK, nil, responseBody)
}

// TS 29.518 5.2.2.6
func HandleAssignEbiDataRequest(request *http_wrapper.Request) *http_wrapper.Response {
	var response models.AssignedEbiData
	var assignEbiError models.AssignEbiError
	var assignEbiFailed models.AssignEbiFailed
	var problem models.ProblemDetails
	var ue *context.AmfUe
	var ok bool
	amfSelf := context.AMF_Self()

	assignEbiData := request.Body.(models.AssignEbiData)
	ueContextID := request.Params["ueContextId"]

	if strings.HasPrefix(ueContextID, "imsi") {
		if ue, ok = amfSelf.AmfUeFindBySupi(ueContextID); !ok {
			problem.Status = http.StatusNotFound
			problem.Cause = "CONTEXT_NOT_FOUND"
			assignEbiError.Error = &problem
			assignEbiFailed.PduSessionId = assignEbiData.PduSessionId
			assignEbiFailed.FailedArpList = nil
			assignEbiError.FailureDetails = &assignEbiFailed
			return http_wrapper.NewResponse(http.StatusNotFound, nil, assignEbiError)
		}
	} else if strings.HasPrefix(ueContextID, "imei") {
		amfSelf.UePool.Range(func(key, value interface{}) bool {
			ue1 := value.(*context.AmfUe)
			if ue1.Pei == ueContextID {
				ue = ue1
				return false
			}
			return true
		})
		if ue == nil {
			problem.Status = http.StatusNotFound
			problem.Cause = "CONTEXT_NOT_FOUND"
			assignEbiError.Error = &problem
			assignEbiFailed.PduSessionId = assignEbiData.PduSessionId
			assignEbiFailed.FailedArpList = nil
			assignEbiError.FailureDetails = &assignEbiFailed
			return http_wrapper.NewResponse(http.StatusNotFound, nil, assignEbiError)
		}
	}

	if ue != nil {
		if ue.SmContextList[assignEbiData.PduSessionId] != nil {
			response.PduSessionId = assignEbiData.PduSessionId
			response.AssignedEbiList = ue.SmContextList[assignEbiData.PduSessionId].PduSessionContext.AllocatedEbiList
		} else {
			logger.ProducerLog.Errorln("ue.SmContextList is nil")
		}
	}
	return http_wrapper.NewResponse(http.StatusOK, nil, response)
}

func HandleRegistrationStatusUpdateRequest(httpChannel chan amf_message.HandlerResponseMessage, ueContextId string, body models.UeRegStatusUpdateReqData) {
	var response models.UeRegStatusUpdateRspData
	var problem models.ProblemDetails
	var ue *context.AmfUe
	var ok bool
	amfSelf := context.AMF_Self()

	if strings.HasPrefix(ueContextId, "5g-guti") {
		guti := ueContextId[strings.LastIndex(ueContextId, "-")+1:]
		if ue, ok = amfSelf.GutiPool[guti]; !ok {
			problem.Status = 404
			problem.Cause = "CONTEXT_NOT_FOUND"
			amf_message.SendHttpResponseMessage(httpChannel, nil, http.StatusNotFound, problem)
			return
		}
	} else {
		problem.Status = 404
		problem.Cause = "CONTEXT_NOT_FOUND"
		amf_message.SendHttpResponseMessage(httpChannel, nil, http.StatusNotFound, problem)
		return
	}

	if ue != nil {
		if body.TransferStatus == models.UeContextTransferStatus_TRANSFERRED {
			// remove the individual ueContext resource and release any PDU session(s)
			for _, pduSessionId := range body.ToReleaseSessionList {
				cause := models.Cause_REL_DUE_TO_SLICE_NOT_AVAILABLE
				causeAll := &context.CauseAll{
					Cause: &cause,
				}
				smContextReleaseRequest := consumer.BuildReleaseSmContextRequest(ue, causeAll, "", nil)
				problemDetails, err := consumer.SendReleaseSmContextRequest(ue, pduSessionId, smContextReleaseRequest)
				if problemDetails != nil {
					logger.GmmLog.Errorf("Release SmContext[pduSessionId: %d] Failed Problem[%+v]", pduSessionId, problemDetails)
				} else if err != nil {
					logger.GmmLog.Errorf("Release SmContext[pduSessionId: %d] Error[%v]", pduSessionId, err.Error())
				}
			}

			if body.PcfReselectedInd {
				problemDetails, err := consumer.AMPolicyControlDelete(ue)
				if problemDetails != nil {
					logger.GmmLog.Errorf("AM Policy Control Delete Failed Problem[%+v]", problemDetails)
				} else if err != nil {
					logger.GmmLog.Errorf("AM Policy Control Delete Error[%v]", err.Error())
				}
			}

			ue.Remove()
		} else {
			// NOT_TRANSFERRED
			logger.CommLog.Debug("[AMF] RegistrationStatusUpdate: NOT_TRANSFERRED")
		}
	}
	response.RegStatusTransferComplete = true
	amf_message.SendHttpResponseMessage(httpChannel, nil, http.StatusOK, response)
}
