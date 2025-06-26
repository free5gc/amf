package processor

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/amf/internal/context"
	gmm_common "github.com/free5gc/amf/internal/gmm/common"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/amf/internal/nas/nas_security"
	ngap_message "github.com/free5gc/amf/internal/ngap/message"
	"github.com/free5gc/aper"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/openapi/models"
)

// TS 29.518 5.2.2.2.3
func (p *Processor) HandleCreateUEContextRequest(c *gin.Context, createUeContextRequest models.CreateUeContextRequest) {
	logger.CommLog.Infof("Handle Create UE Context Request")

	ueContextID := c.Param("ueContextId")

	createUeContextResponse, ueContextCreateError := p.CreateUEContextProcedure(ueContextID, createUeContextRequest)
	if ueContextCreateError != nil {
		c.JSON(int(ueContextCreateError.JsonData.Error.Status), ueContextCreateError)
	} else {
		c.JSON(http.StatusCreated, createUeContextResponse)
	}
}

func (p *Processor) CreateUEContextProcedure(ueContextID string, createUeContextRequest models.CreateUeContextRequest) (
	*models.CreateUeContextResponse201, *models.CreateUeContextResponse403,
) {
	amfSelf := context.GetSelf()
	ueContextCreateData := createUeContextRequest.JsonData

	if ueContextCreateData.UeContext == nil || ueContextCreateData.TargetId == nil ||
		ueContextCreateData.PduSessionList == nil || ueContextCreateData.SourceToTargetData == nil ||
		ueContextCreateData.N2NotifyUri == "" {
		ueCtxCreateError := models.UeContextCreateError{
			Error: &models.ProblemDetails{
				Status: http.StatusForbidden,
				Cause:  "HANDOVER_FAILURE",
			},
		}
		ueContextCreateError := &models.CreateUeContextResponse403{
			JsonData: &ueCtxCreateError,
		}
		return nil, ueContextCreateError
	}
	// create the UE context in target amf
	ue := amfSelf.NewAmfUe(ueContextID)
	ue.Lock.Lock()
	defer ue.Lock.Unlock()

	// amfSelf.AmfRanSetByRanId(*ueContextCreateData.TargetId.RanNodeId)
	// ue.N1N2Message[ueContextId] = &context.N1N2Message{}
	// ue.N1N2Message[ueContextId].Request.JsonData = &models.N1N2MessageTransferReqData{
	// 	N2InfoContainer: &models.N2InfoContainer{
	// 		SmInfo: &models.N2SmInformation{
	// 			N2InfoContent: ueContextCreateData.SourceToTargetData,
	// 		},
	// 	},
	// }
	ue.HandoverNotifyUri = ueContextCreateData.N2NotifyUri

	targetRan, ok := amfSelf.AmfRanFindByRanID(*ueContextCreateData.TargetId.RanNodeId)
	if !ok {
		// internal error.
	}
	supportedTAI := context.NewSupportedTAI()
	supportedTAI.Tai.Tac = ueContextCreateData.TargetId.Tai.Tac
	supportedTAI.Tai.PlmnId = ueContextCreateData.TargetId.Tai.PlmnId
	// ue.N1N2MessageSubscribeInfo[ueContextID] = &models.UeN1N2InfoSubscriptionCreateData{
	// 	N2NotifyCallbackUri: ueContextCreateData.N2NotifyUri,
	// }
	ue.UnauthenticatedSupi = ueContextCreateData.UeContext.SupiUnauthInd
	// should be smInfo list

	//	for _, smInfo := range ueContextCreateData.PduSessionList {
	//		if smInfo.N2InfoContent.NgapIeType == "NgapIeType_HANDOVER_REQUIRED" {
	// 			ue.N1N2Message[amfSelf.Uri].Request.JsonData.N2InfoContainer.SmInfo = &smInfo
	//		}
	//	}

	ue.RoutingIndicator = ueContextCreateData.UeContext.RoutingIndicator

	// optional
	ue.UdmGroupId = ueContextCreateData.UeContext.UdmGroupId
	ue.AusfGroupId = ueContextCreateData.UeContext.AusfGroupId
	// ueContextCreateData.UeContext.HpcfId
	ue.RatType = ueContextCreateData.UeContext.RestrictedRatList[0] // minItem = -1
	// ueContextCreateData.UeContext.ForbiddenAreaList
	// ueContextCreateData.UeContext.ServiceAreaRestriction
	// ueContextCreateData.UeContext.RestrictedCoreNwTypeList

	// it's not in 5.2.2.1.1 step 2a, so don't support
	// ue.Gpsi = ueContextCreateData.UeContext.GpsiList
	// ue.Pei = ueContextCreateData.UeContext.Pei
	// ueContextCreateData.UeContext.GroupList
	// ueContextCreateData.UeContext.DrxParameter
	// ueContextCreateData.UeContext.SubRfsp
	// ueContextCreateData.UeContext.UsedRfsp
	// ue.UEAMBR = ueContextCreateData.UeContext.SubUeAmbr
	// ueContextCreateData.UeContext.SmsSupport
	// ueContextCreateData.UeContext.SmsfId
	// ueContextCreateData.UeContext.SeafData
	// ueContextCreateData.UeContext.Var5gMmCapability
	// ueContextCreateData.UeContext.PcfId
	// ueContextCreateData.UeContext.PcfAmPolicyUri
	// ueContextCreateData.UeContext.AmPolicyReqTriggerList
	// ueContextCreateData.UeContext.EventSubscriptionList
	// ueContextCreateData.UeContext.MmContextList
	// ue.CurPduSession.PduSessionId = ueContextCreateData.UeContext.SessionContextList.
	// ue.TraceData = ueContextCreateData.UeContext.TraceData

	// decode HandoverRequiredMessage.
	// refer to ngap/dispatcher.go and ngap/dispatcher_generated.go.
	pdu, err := ngap.Decoder(createUeContextRequest.BinaryDataN2Information)
	if err != nil {
		// internal error
	}
	if pdu.Present != ngapType.NGAPPDUPresentInitiatingMessage || pdu.
		InitiatingMessage.ProcedureCode.Value != ngapType.ProcedureCodeHandoverPreparation {
		// internal error
	}

	// extract IEs from message.
	// refer to ngap/handler_generated.go handlerHandoverRequired().
	var aMFUENGAPID *ngapType.AMFUENGAPID
	var rANUENGAPID *ngapType.RANUENGAPID
	var handoverType *ngapType.HandoverType
	var cause *ngapType.Cause
	var targetID *ngapType.TargetID
	var directForwardingPathAvailability *ngapType.DirectForwardingPathAvailability
	var pDUSessionResourceListHORqd *ngapType.PDUSessionResourceListHORqd
	var sourceToTargetTransparentContainer *ngapType.SourceToTargetTransparentContainer

	var syntaxCause *ngapType.Cause
	var iesCriticalityDiagnostics ngapType.CriticalityDiagnosticsIEList
	abort := false

	handoverRequiredMessage := pdu.InitiatingMessage.Value.HandoverRequired
	if handoverRequiredMessage == nil {
		logger.CommLog.Errorf("HandoverRequired is nil")
		// return
	}

	// Refer to buildCriticalityDiagnosticsIEItem() in ngap/handler.go
	buildCriticalityDiagnosticsIEItem := func(ieCriticality aper.Enumerated, ieID int64, typeOfErr aper.Enumerated) (
		item ngapType.CriticalityDiagnosticsIEItem,
	) {
		item = ngapType.CriticalityDiagnosticsIEItem{
			IECriticality: ngapType.Criticality{
				Value: ieCriticality,
			},
			IEID: ngapType.ProtocolIEID{
				Value: ieID,
			},
			TypeOfError: ngapType.TypeOfError{
				Value: typeOfErr,
			},
		}

		return item
	}

	for _, ie := range handoverRequiredMessage.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID: // mandatory, reject
			if aMFUENGAPID != nil {
				logger.CommLog.Errorf("Duplicate IE AMF-UE-NGAP-ID")
				syntaxCause = &ngapType.Cause{
					Present: ngapType.CausePresentProtocol,
					Protocol: &ngapType.CauseProtocol{
						Value: ngapType.CauseProtocolPresentAbstractSyntaxErrorFalselyConstructedMessage,
					},
				}
				abort = true
				break
			}
			aMFUENGAPID = ie.Value.AMFUENGAPID
			logger.CommLog.Trace("Decode IE AMF-UE-NGAP-ID")
		case ngapType.ProtocolIEIDRANUENGAPID: // mandatory, reject
			if rANUENGAPID != nil {
				logger.CommLog.Error("Duplicate IE RAN-UE-NGAP-ID")
				syntaxCause = &ngapType.Cause{
					Present: ngapType.CausePresentProtocol,
					Protocol: &ngapType.CauseProtocol{
						Value: ngapType.CauseProtocolPresentAbstractSyntaxErrorFalselyConstructedMessage,
					},
				}
				abort = true
				break
			}
			rANUENGAPID = ie.Value.RANUENGAPID
			logger.CommLog.Trace("Decode IE RAN-UE-NGAP-ID")
		case ngapType.ProtocolIEIDHandoverType: // mandatory, reject
			if handoverType != nil {
				logger.CommLog.Error("Duplicate IE HandoverType")
				syntaxCause = &ngapType.Cause{
					Present: ngapType.CausePresentProtocol,
					Protocol: &ngapType.CauseProtocol{
						Value: ngapType.CauseProtocolPresentAbstractSyntaxErrorFalselyConstructedMessage,
					},
				}
				abort = true
				break
			}
			handoverType = ie.Value.HandoverType
			logger.CommLog.Trace("Decode IE HandoverType")
		case ngapType.ProtocolIEIDCause: // mandatory, ignore
			if cause != nil {
				logger.CommLog.Error("Duplicate IE Cause")
				syntaxCause = &ngapType.Cause{
					Present: ngapType.CausePresentProtocol,
					Protocol: &ngapType.CauseProtocol{
						Value: ngapType.CauseProtocolPresentAbstractSyntaxErrorFalselyConstructedMessage,
					},
				}
				abort = true
				break
			}
			cause = ie.Value.Cause
			logger.CommLog.Trace("Decode IE Cause")
		case ngapType.ProtocolIEIDTargetID: // mandatory, reject
			if targetID != nil {
				logger.CommLog.Error("Duplicate IE TargetID")
				syntaxCause = &ngapType.Cause{
					Present: ngapType.CausePresentProtocol,
					Protocol: &ngapType.CauseProtocol{
						Value: ngapType.CauseProtocolPresentAbstractSyntaxErrorFalselyConstructedMessage,
					},
				}
				abort = true
				break
			}
			targetID = ie.Value.TargetID
			logger.CommLog.Trace("Decode IE TargetID")
		case ngapType.ProtocolIEIDDirectForwardingPathAvailability: // optional, ignore
			if directForwardingPathAvailability != nil {
				logger.CommLog.Error("Duplicate IE DirectForwardingPathAvailability")
				syntaxCause = &ngapType.Cause{
					Present: ngapType.CausePresentProtocol,
					Protocol: &ngapType.CauseProtocol{
						Value: ngapType.CauseProtocolPresentAbstractSyntaxErrorFalselyConstructedMessage,
					},
				}
				abort = true
				break
			}
			directForwardingPathAvailability = ie.Value.DirectForwardingPathAvailability
			logger.CommLog.Trace("Decode IE DirectForwardingPathAvailability")
		case ngapType.ProtocolIEIDPDUSessionResourceListHORqd: // mandatory, reject
			if pDUSessionResourceListHORqd != nil {
				logger.CommLog.Error("Duplicate IE PDUSessionResourceListHORqd")
				syntaxCause = &ngapType.Cause{
					Present: ngapType.CausePresentProtocol,
					Protocol: &ngapType.CauseProtocol{
						Value: ngapType.CauseProtocolPresentAbstractSyntaxErrorFalselyConstructedMessage,
					},
				}
				abort = true
				break
			}
			pDUSessionResourceListHORqd = ie.Value.PDUSessionResourceListHORqd
			logger.CommLog.Trace("Decode IE PDUSessionResourceListHORqd")
		case ngapType.ProtocolIEIDSourceToTargetTransparentContainer: // mandatory, reject
			if sourceToTargetTransparentContainer != nil {
				logger.CommLog.Error("Duplicate IE SourceToTarget-TransparentContainer")
				syntaxCause = &ngapType.Cause{
					Present: ngapType.CausePresentProtocol,
					Protocol: &ngapType.CauseProtocol{
						Value: ngapType.CauseProtocolPresentAbstractSyntaxErrorFalselyConstructedMessage,
					},
				}
				abort = true
				break
			}
			sourceToTargetTransparentContainer = ie.Value.SourceToTargetTransparentContainer
			logger.CommLog.Trace("Decode IE SourceToTarget-TransparentContainer")
		default:
			switch ie.Criticality.Value {
			case ngapType.CriticalityPresentReject:
				logger.CommLog.Errorf("Not comprehended IE ID 0x%04x (criticality: reject)", ie.Id.Value)
			case ngapType.CriticalityPresentIgnore:
				logger.CommLog.Infof("Not comprehended IE ID 0x%04x (criticality: ignore)", ie.Id.Value)
			case ngapType.CriticalityPresentNotify:
				logger.CommLog.Warnf("Not comprehended IE ID 0x%04x (criticality: notify)", ie.Id.Value)
			}
			if ie.Criticality.Value != ngapType.CriticalityPresentIgnore {
				item := buildCriticalityDiagnosticsIEItem(ie.Criticality.Value, ie.Id.Value, ngapType.TypeOfErrorPresentNotUnderstood)
				iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
				if ie.Criticality.Value == ngapType.CriticalityPresentReject {
					abort = true
				}
			}
		}
	} // end of extracting IEs from message.

	if aMFUENGAPID == nil {
		logger.CommLog.Error("Missing IE AMF-UE-NGAP-ID")
		item := buildCriticalityDiagnosticsIEItem(ngapType.CriticalityPresentReject, ngapType.ProtocolIEIDAMFUENGAPID, ngapType.TypeOfErrorPresentMissing)
		iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
		abort = true
	}
	if rANUENGAPID == nil {
		logger.CommLog.Error("Missing IE RAN-UE-NGAP-ID")
		item := buildCriticalityDiagnosticsIEItem(ngapType.CriticalityPresentReject, ngapType.ProtocolIEIDRANUENGAPID, ngapType.TypeOfErrorPresentMissing)
		iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
		abort = true
	}
	if handoverType == nil {
		logger.CommLog.Error("Missing IE HandoverType")
		item := buildCriticalityDiagnosticsIEItem(ngapType.CriticalityPresentReject, ngapType.ProtocolIEIDHandoverType, ngapType.TypeOfErrorPresentMissing)
		iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
		abort = true
	}
	if targetID == nil {
		logger.CommLog.Error("Missing IE TargetID")
		item := buildCriticalityDiagnosticsIEItem(ngapType.CriticalityPresentReject, ngapType.ProtocolIEIDTargetID, ngapType.TypeOfErrorPresentMissing)
		iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
		abort = true
	}
	if pDUSessionResourceListHORqd == nil {
		logger.CommLog.Error("Missing IE PDUSessionResourceListHORqd")
		item := buildCriticalityDiagnosticsIEItem(ngapType.CriticalityPresentReject, ngapType.ProtocolIEIDPDUSessionResourceListHORqd, ngapType.TypeOfErrorPresentMissing)
		iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
		abort = true
	}
	if sourceToTargetTransparentContainer == nil {
		logger.CommLog.Error("Missing IE SourceToTarget-TransparentContainer")
		item := buildCriticalityDiagnosticsIEItem(ngapType.CriticalityPresentReject, ngapType.ProtocolIEIDSourceToTargetTransparentContainer, ngapType.TypeOfErrorPresentMissing)
		iesCriticalityDiagnostics.List = append(iesCriticalityDiagnostics.List, item)
		abort = true
	}

	if syntaxCause != nil || len(iesCriticalityDiagnostics.List) > 0 {
		logger.CommLog.Trace("Has IE error") /*
			procedureCode := ngapType.ProcedureCodeHandoverPreparation
			triggeringMessage := ngapType.TriggeringMessagePresentInitiatingMessage
			procedureCriticality := ngapType.CriticalityPresentReject
			var pIesCriticalityDiagnostics *ngapType.CriticalityDiagnosticsIEList
			if len(iesCriticalityDiagnostics.List) > 0 {
				pIesCriticalityDiagnostics = &iesCriticalityDiagnostics
			} /*
			criticalityDiagnostics := func (
				procedureCode *int64,
				triggeringMessage *aper.Enumerated,
				procedureCriticality *aper.Enumerated,
				iesCriticalityDiagnostics *ngapType.CriticalityDiagnosticsIEList) (
				criticalityDiagnostics ngapType.CriticalityDiagnostics,
			) {
				if procedureCode != nil {
					criticalityDiagnostics.ProcedureCode = new(ngapType.ProcedureCode)
					criticalityDiagnostics.ProcedureCode.Value = *procedureCode
				}

				if triggeringMessage != nil {
					criticalityDiagnostics.TriggeringMessage = new(ngapType.TriggeringMessage)
					criticalityDiagnostics.TriggeringMessage.Value = *triggeringMessage
				}

				if procedureCriticality != nil {
					criticalityDiagnostics.ProcedureCriticality = new(ngapType.Criticality)
					criticalityDiagnostics.ProcedureCriticality.Value = *procedureCriticality
				}

				if iesCriticalityDiagnostics != nil {
					criticalityDiagnostics.IEsCriticalityDiagnostics = iesCriticalityDiagnostics
				}

				return criticalityDiagnostics
			} (&procedureCode, &triggeringMessage, &procedureCriticality, pIesCriticalityDiagnostics) */
		if aMFUENGAPID != nil && rANUENGAPID != nil {
			if syntaxCause == nil {
				syntaxCause = &ngapType.Cause{
					Present: ngapType.CausePresentProtocol,
					Protocol: &ngapType.CauseProtocol{
						Value: ngapType.CauseProtocolPresentAbstractSyntaxErrorFalselyConstructedMessage,
					},
				}
			}
			// rawSendHandoverPreparationFailure(ran, *aMFUENGAPID, *rANUENGAPID, *syntaxCause, &criticalityDiagnostics)
		} else {
			// ngap_message.SendErrorIndication(ran, aMFUENGAPID, rANUENGAPID, syntaxCause, &criticalityDiagnostics)
		}
	}
	if abort {
		// return
	}

	// TS 23.502 4.9.1.3.2 step 4
	var pduSessionReqList ngapType.PDUSessionResourceSetupListHOReq

	if pDUSessionResourceListHORqd != nil {
		logger.CommLog.Infof("Send HandoverRequiredTransfer to SMF")
		for _, n2SmInfo := range ueContextCreateData.PduSessionList {
			// Check if the S-NSSAI associated with the PDU session is available in the AMF.
			// If not, the T-AMF does not invoke Nsmf_PDUSession_UpdateSMContext for this PDU session.
			pduSessionID := n2SmInfo.PduSessionId
			if amfSelf.InPlmnSupportList(*n2SmInfo.SNssai) {
				continue
			}

			smContext, ok := ue.SmContextFindByPDUSessionID(pduSessionID)
			if !ok {
				logger.CommLog.Warnf("SmContext[PDU Session ID:%d] not found", pduSessionID)
				// TODO: Check if doing error handling here
				continue
			}

			updateSmContextResponse200, _, _, err := p.Consumer().
				SendUpdateSmContextHandoverBetweenAMF(ue, smContext, amfSelf.Name, &amfSelf.ServedGuamiList[0], false)
			if err != nil {
				logger.CommLog.Errorf("consumer.GetConsumer().SendUpdateSmContextN2HandoverPreparing Error: %+v", err)
			}
			if updateSmContextResponse200 == nil {
				logger.CommLog.Errorf("SendUpdateSmContextN2HandoverPreparing Error for pduSessionID[%d]", pduSessionID)
				continue
			} else if updateSmContextResponse200.BinaryDataN2SmInformation != nil {
				ngap_message.AppendPDUSessionResourceSetupListHOReq(&pduSessionReqList, pduSessionID,
					smContext.Snssai(), updateSmContextResponse200.BinaryDataN2SmInformation)
			}
		}
	}
	if len(pduSessionReqList.List) == 0 {
		logger.CommLog.Info("Handle Handover Preparation Failure [HoFailure In Target5GC NgranNode Or TargetSystem]")
		cause = &ngapType.Cause{
			Present: ngapType.CausePresentRadioNetwork,
			RadioNetwork: &ngapType.CauseRadioNetwork{
				Value: ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem,
			},
		}
		// ngap_message.SendHandoverPreparationFailure(ranUe, *cause, nil)
		// return
	}
	// Update NH
	ue.UpdateNH()
	if cause == nil {
		cause = &ngapType.Cause{
			Present: ngapType.CausePresentMisc,
			Misc: &ngapType.CauseMisc{
				Value: ngapType.CauseMiscPresentUnspecified,
			},
		}
	}
	ngap_message.SendHandoverRequest(ue.RanUe[ue.GetAnType()], targetRan, *cause, pduSessionReqList, *sourceToTargetTransparentContainer, false)

	createUeContextResponse, ok := amfSelf.PendingHandovers.Load(ue.Supi)
	createUeContextResp, ok := createUeContextResponse.(context.PendingHandoverResponse)
	if ok {
		if createUeContextResp.response201 != nil {
			return createUeContextResp.response201, nil
		} else if createUeContextResp.response403 != nil {
			return nil, createUeContextResp.response403
		}
	}

	ueCtxCreateError := models.UeContextCreateError{
		Error: &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  "HANDOVER_FAILURE",
		},
	}
	ueContextCreateError := &models.CreateUeContextResponse403{
		JsonData: &ueCtxCreateError,
	}
	return nil, ueContextCreateError

	/*
		 move to HandoverRequestAcknowledge handler (ngap/handler.go: handleHandoverRequestAcknowledgeMain() ).
			createUeContextResponse := new(models.CreateUeContextResponse201)
			createUeContextResponse.JsonData = &models.UeContextCreatedData{
				UeContext: &models.UeContext{
					Supi: ueContextCreateData.UeContext.Supi,
				},
			}

			// response.JsonData.TargetToSourceData =
			// ue.N1N2Message[ueContextId].Request.JsonData.N2InfoContainer.SmInfo.N2InfoContent
			createUeContextResponse.JsonData.PduSessionList = ueContextCreateData.PduSessionList
			createUeContextResponse.JsonData.PcfReselectedInd = false
			// TODO: When  Target AMF selects a nw PCF for AM policy, set the flag to true.

			//	response.UeContext = ueContextCreateData.UeContext
			//	response.TargetToSourceData = ue.N1N2Message[amfSelf.Uri].Request.JsonData.N2InfoContainer.SmInfo.N2InfoContent
			//	response.PduSessionList = ueContextCreateData.PduSessionList
			//	response.PcfReselectedInd = false // TODO:When  Target AMF selects a nw PCF for AM policy, set the flag to true.
			//

			// return httpwrapper.NewResponse(http.StatusCreated, nil, createUeContextResponse)
			return createUeContextResponse, nil
	*/
}

// TS 29.518 5.2.2.2.4
func (p *Processor) HandleReleaseUEContextRequest(c *gin.Context, ueContextRelease models.UeContextRelease) {
	logger.CommLog.Info("Handle Release UE Context Request")

	ueContextID := c.Param("ueContextId")

	problemDetails := p.ReleaseUEContextProcedure(ueContextID, ueContextRelease)
	if problemDetails != nil {
		c.JSON(int(problemDetails.Status), problemDetails)
	} else {
		c.Status(http.StatusNoContent)
	}
}

func (p *Processor) ReleaseUEContextProcedure(ueContextID string,
	ueContextRelease models.UeContextRelease,
) *models.ProblemDetails {
	amfSelf := context.GetSelf()

	// TODO: UE is emergency registered and the SUPI is not authenticated
	if ueContextRelease.Supi != "" {
		logger.GmmLog.Warnf("Emergency registered UE is not supported.")
		problemDetails := &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  "UNSPECIFIED",
		}
		return problemDetails
	}

	if ueContextRelease.NgapCause == nil {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusBadRequest,
			Cause:  "MANDATORY_IE_MISSING",
		}
		return problemDetails
	}

	logger.CommLog.Debugf("Release UE Context NGAP cause: %+v", ueContextRelease.NgapCause)

	ue, ok := amfSelf.AmfUeFindByUeContextID(ueContextID)
	if !ok {
		logger.CtxLog.Warnf("AmfUe Context[%s] not found", ueContextID)
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "CONTEXT_NOT_FOUND",
		}
		return problemDetails
	}

	ue.Lock.Lock()
	defer ue.Lock.Unlock()

	// TODO: TS 23.502 4.11.1.2.3.4
	// If the target CN node is AMF, the AMF invokes the
	// "Nsmf_PDUSession_UpdateSMContext request (SUPI, Relocation Cancel Indication) toward the SMF. Based
	// on the Relocation Cancel Indication, the target CN node deletes the session resources established during
	// handover preparation phase in SMF and UPF.

	gmm_common.RemoveAmfUe(ue, false)

	return nil
}

func (p *Processor) HandleMobiRegUe(ue *context.AmfUe, ueContextTransferRspData *models.UeContextTransferRspData,
	ueContextTransferResponse *models.UeContextTransferResponse200,
) {
	ueContextTransferRspData.UeRadioCapability = &models.N2InfoContent{
		NgapMessageType: 0,
		NgapIeType:      models.AmfCommunicationNgapIeType_UE_RADIO_CAPABILITY,
		NgapData: &models.RefToBinaryData{
			ContentId: "n2Info",
		},
	}
	b := []byte(ue.UeRadioCapability)
	copy(ueContextTransferResponse.BinaryDataN2Information, b)
}

// TS 29.518 5.2.2.2.1
func (p *Processor) HandleUEContextTransferRequest(c *gin.Context,
	ueContextTransferRequest models.UeContextTransferRequest,
) {
	logger.CommLog.Info("Handle UE Context Transfer Request")

	ueContextID := c.Param("ueContextId")

	ueContextTransferResponse, problemDetails := p.UEContextTransferProcedure(ueContextID, ueContextTransferRequest)
	if problemDetails != nil {
		c.JSON(int(problemDetails.Status), problemDetails)
	} else {
		c.JSON(http.StatusOK, ueContextTransferResponse)
	}
}

func (p *Processor) UEContextTransferProcedure(ueContextID string,
	ueContextTransferRequest models.UeContextTransferRequest) (
	*models.UeContextTransferResponse200, *models.ProblemDetails,
) {
	amfSelf := context.GetSelf()

	if ueContextTransferRequest.JsonData == nil {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusBadRequest,
			Cause:  "MANDATORY_IE_MISSING",
		}
		return nil, problemDetails
	}

	UeContextTransferReqData := ueContextTransferRequest.JsonData

	if UeContextTransferReqData.AccessType == "" || UeContextTransferReqData.Reason == "" {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusBadRequest,
			Cause:  "MANDATORY_IE_MISSING",
		}
		return nil, problemDetails
	}

	ue, ok := amfSelf.AmfUeFindByUeContextID(ueContextID)
	if !ok {
		logger.CtxLog.Warnf("AmfUe Context[%s] not found", ueContextID)
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "CONTEXT_NOT_FOUND",
		}
		return nil, problemDetails
	}

	ue.Lock.Lock()
	defer ue.Lock.Unlock()

	ueContextTransferResponse := &models.UeContextTransferResponse200{
		JsonData: new(models.UeContextTransferRspData),
	}
	ueContextTransferRspData := ueContextTransferResponse.JsonData

	//	if ue.GetAnType() != UeContextTransferReqData.AccessType {
	//		for _, tai := range ue.RegistrationArea[ue.GetAnType()] {
	//		if UeContextTransferReqData.PlmnId == tai.PlmnId {
	// 			TODO : generate N2 signaling
	//			}
	//		}
	//	}

	switch UeContextTransferReqData.Reason {
	case models.TransferReason_INIT_REG:
		_, integrityProtected, err := nas_security.Decode(ue, UeContextTransferReqData.AccessType,
			ueContextTransferRequest.BinaryDataN1Message, true)
		if err != nil {
			problemDetails := &models.ProblemDetails{
				Status: http.StatusForbidden,
				Cause:  "INTEGRITY_CHECK_FAIL",
			}
			ue.NASLog.Errorln(err)
			return nil, problemDetails
		}
		if integrityProtected {
			ueContextTransferRspData.UeContext = p.buildUEContextModel(ue, UeContextTransferReqData.Reason)
		} else {
			problemDetails := &models.ProblemDetails{
				Status: http.StatusForbidden,
				Cause:  "INTEGRITY_CHECK_FAIL",
			}
			return nil, problemDetails
		}
		// TODO: handle condition of TS 29.518 5.2.2.2.1.1 step 2a case b
	case models.TransferReason_MOBI_REG:
		_, integrityProtected, err := nas_security.Decode(ue, UeContextTransferReqData.AccessType,
			ueContextTransferRequest.BinaryDataN1Message, false)
		if err != nil {
			problemDetails := &models.ProblemDetails{
				Status: http.StatusForbidden,
				Cause:  "INTEGRITY_CHECK_FAIL",
			}
			ue.NASLog.Errorln(err)
			return nil, problemDetails
		}
		if integrityProtected {
			ueContextTransferRspData.UeContext = p.buildUEContextModel(ue, UeContextTransferReqData.Reason)
		} else {
			problemDetails := &models.ProblemDetails{
				Status: http.StatusForbidden,
				Cause:  "INTEGRITY_CHECK_FAIL",
			}
			return nil, problemDetails
		}
		p.HandleMobiRegUe(ue, ueContextTransferRspData, ueContextTransferResponse)

	case models.TransferReason_MOBI_REG_UE_VALIDATED:
		ueContextTransferRspData.UeContext = p.buildUEContextModel(ue, UeContextTransferReqData.Reason)
		p.HandleMobiRegUe(ue, ueContextTransferRspData, ueContextTransferResponse)

	default:
		logger.ProducerLog.Warnf("Invalid Transfer Reason: %+v", UeContextTransferReqData.Reason)
		problemDetails := &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  "MANDATORY_IE_INCORRECT",
			InvalidParams: []models.InvalidParam{
				{
					Param: "reason",
				},
			},
		}
		return nil, problemDetails
	}
	return ueContextTransferResponse, nil
}

func (p *Processor) buildUEContextModel(ue *context.AmfUe, reason models.TransferReason) *models.UeContext {
	ueContext := new(models.UeContext)
	ueContext.Supi = ue.Supi
	ueContext.SupiUnauthInd = ue.UnauthenticatedSupi
	if reason == models.TransferReason_INIT_REG || reason == models.TransferReason_MOBI_REG {
		var mmContext models.MmContext
		mmContext.AccessType = models.AccessType__3_GPP_ACCESS
		NasSecurityMode := new(models.NasSecurityMode)
		switch ue.IntegrityAlg {
		case security.AlgIntegrity128NIA0:
			NasSecurityMode.IntegrityAlgorithm = models.IntegrityAlgorithm_NIA0
		case security.AlgIntegrity128NIA1:
			NasSecurityMode.IntegrityAlgorithm = models.IntegrityAlgorithm_NIA1
		case security.AlgIntegrity128NIA2:
			NasSecurityMode.IntegrityAlgorithm = models.IntegrityAlgorithm_NIA2
		case security.AlgIntegrity128NIA3:
			NasSecurityMode.IntegrityAlgorithm = models.IntegrityAlgorithm_NIA3
		}
		switch ue.CipheringAlg {
		case security.AlgCiphering128NEA0:
			NasSecurityMode.CipheringAlgorithm = models.CipheringAlgorithm_NEA0
		case security.AlgCiphering128NEA1:
			NasSecurityMode.CipheringAlgorithm = models.CipheringAlgorithm_NEA1
		case security.AlgCiphering128NEA2:
			NasSecurityMode.CipheringAlgorithm = models.CipheringAlgorithm_NEA2
		case security.AlgCiphering128NEA3:
			NasSecurityMode.CipheringAlgorithm = models.CipheringAlgorithm_NEA3
		}
		NgKsi := new(models.NgKsi)
		NgKsi.Ksi = ue.NgKsi.Ksi
		NgKsi.Tsc = ue.NgKsi.Tsc
		KeyAmf := new(models.KeyAmf)
		KeyAmf.KeyType = models.KeyAmfType_KAMF
		KeyAmf.KeyVal = ue.Kamf
		SeafData := new(models.SeafData)
		SeafData.NgKsi = NgKsi
		SeafData.KeyAmf = KeyAmf
		if ue.NH != nil {
			SeafData.Nh = hex.EncodeToString(ue.NH)
		}
		SeafData.Ncc = int32(ue.NCC)
		SeafData.KeyAmfChangeInd = false
		SeafData.KeyAmfHDerivationInd = false
		ueContext.SeafData = SeafData
		mmContext.NasSecurityMode = NasSecurityMode
		if ue.UESecurityCapability.Buffer != nil {
			mmContext.UeSecurityCapability = base64.StdEncoding.EncodeToString(ue.UESecurityCapability.Buffer)
		}
		mmContext.NasDownlinkCount = int32(ue.DLCount.Get())
		mmContext.NasUplinkCount = int32(ue.ULCount.Get())
		if ue.AllowedNssai[models.AccessType__3_GPP_ACCESS] != nil {
			for _, allowedSnssai := range ue.AllowedNssai[models.AccessType__3_GPP_ACCESS] {
				mmContext.AllowedNssai = append(mmContext.AllowedNssai, *(allowedSnssai.AllowedSnssai))
			}
		}
		ueContext.MmContextList = append(ueContext.MmContextList, mmContext)
	}
	if reason == models.TransferReason_MOBI_REG_UE_VALIDATED || reason == models.TransferReason_MOBI_REG {
		sessionContextList := &ueContext.SessionContextList
		ue.SmContextList.Range(func(key, value interface{}) bool {
			smContext := value.(*context.SmContext)
			snssai := smContext.Snssai()
			pduSessionContext := models.PduSessionContext{
				PduSessionId: smContext.PduSessionID(),
				SmContextRef: smContext.SmContextRef(),
				SNssai:       &snssai,
				Dnn:          smContext.Dnn(),
				AccessType:   smContext.AccessType(),
				HsmfId:       smContext.HSmfID(),
				VsmfId:       smContext.VSmfID(),
				NsInstance:   smContext.NsInstance(),
			}
			*sessionContextList = append(*sessionContextList, pduSessionContext)
			return true
		})
	}
	if ue.Gpsi != "" {
		ueContext.GpsiList = append(ueContext.GpsiList, ue.Gpsi)
	}

	if ue.Pei != "" {
		ueContext.Pei = ue.Pei
	}

	if ue.UdmGroupId != "" {
		ueContext.UdmGroupId = ue.UdmGroupId
	}

	if ue.AusfGroupId != "" {
		ueContext.AusfGroupId = ue.AusfGroupId
	}

	if ue.RoutingIndicator != "" {
		ueContext.RoutingIndicator = ue.RoutingIndicator
	}

	if ue.AccessAndMobilitySubscriptionData != nil {
		if ue.AccessAndMobilitySubscriptionData.SubscribedUeAmbr != nil {
			ueContext.SubUeAmbr = &models.Ambr{
				Uplink:   ue.AccessAndMobilitySubscriptionData.SubscribedUeAmbr.Uplink,
				Downlink: ue.AccessAndMobilitySubscriptionData.SubscribedUeAmbr.Downlink,
			}
		}
		if ue.AccessAndMobilitySubscriptionData.RfspIndex != 0 {
			ueContext.SubRfsp = ue.AccessAndMobilitySubscriptionData.RfspIndex
		}
	}

	if ue.PcfId != "" {
		ueContext.PcfId = ue.PcfId
	}

	if ue.AmPolicyUri != "" {
		ueContext.PcfAmPolicyUri = ue.AmPolicyUri
	}

	if ue.AmPolicyAssociation != nil {
		if len(ue.AmPolicyAssociation.Triggers) > 0 {
			ueContext.AmPolicyReqTriggerList = p.buildAmPolicyReqTriggers(ue.AmPolicyAssociation.Triggers)
		}
	}

	for _, eventSub := range ue.EventSubscriptionsInfo {
		if eventSub.EventSubscription != nil {
			ueContext.EventSubscriptionList = append(ueContext.EventSubscriptionList, *eventSub.EventSubscription)
		}
	}

	if ue.TraceData != nil {
		ueContext.TraceData = ue.TraceData
	}
	return ueContext
}

func (p *Processor) buildAmPolicyReqTriggers(triggers []models.PcfAmPolicyControlRequestTrigger) (
	amPolicyReqTriggers []models.PolicyReqTrigger,
) {
	for _, trigger := range triggers {
		switch trigger {
		case models.PcfAmPolicyControlRequestTrigger_LOC_CH:
			amPolicyReqTriggers = append(amPolicyReqTriggers, models.PolicyReqTrigger_LOCATION_CHANGE)
		case models.PcfAmPolicyControlRequestTrigger_PRA_CH:
			amPolicyReqTriggers = append(amPolicyReqTriggers, models.PolicyReqTrigger_PRA_CHANGE)
		case models.PcfAmPolicyControlRequestTrigger_ALLOWED_NSSAI_CH:
			amPolicyReqTriggers = append(amPolicyReqTriggers, models.PolicyReqTrigger_ALLOWED_NSSAI_CHANGE)
		case models.PcfAmPolicyControlRequestTrigger_NWDAF_DATA_CH:
			amPolicyReqTriggers = append(amPolicyReqTriggers, models.PolicyReqTrigger_NWDAF_DATA_CHANGE)
		case models.PcfAmPolicyControlRequestTrigger_SMF_SELECT_CH:
			amPolicyReqTriggers = append(amPolicyReqTriggers, models.PolicyReqTrigger_SMF_SELECT_CHANGE)
		case models.PcfAmPolicyControlRequestTrigger_ACCESS_TYPE_CH:
			amPolicyReqTriggers = append(amPolicyReqTriggers, models.PolicyReqTrigger_ACCESS_TYPE_CHANGE)
		}
	}
	return
}

// TS 29.518 5.2.2.6
func (p *Processor) HandleAssignEbiDataRequest(c *gin.Context, assignEbiData models.AssignEbiData) {
	logger.CommLog.Info("Handle Assign Ebi Data Request")

	ueContextID := c.Param("ueContextId")

	assignedEbiData, assignEbiError, problemDetails := p.AssignEbiDataProcedure(ueContextID, assignEbiData)
	if problemDetails != nil {
		c.JSON(int(problemDetails.Status), problemDetails)
	} else if assignEbiError != nil {
		c.JSON(int(assignEbiError.Error.Status), assignEbiError)
	} else {
		c.JSON(http.StatusOK, assignedEbiData)
	}
}

func (p *Processor) AssignEbiDataProcedure(ueContextID string, assignEbiData models.AssignEbiData) (
	*models.AssignedEbiData, *models.AssignEbiError, *models.ProblemDetails,
) {
	amfSelf := context.GetSelf()

	ue, ok := amfSelf.AmfUeFindByUeContextID(ueContextID)
	if !ok {
		logger.CtxLog.Warnf("AmfUe Context[%s] not found", ueContextID)
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "CONTEXT_NOT_FOUND",
		}
		return nil, nil, problemDetails
	}

	ue.Lock.Lock()
	defer ue.Lock.Unlock()

	// TODO: AssignEbiError not used, check it!
	if _, okSmContextFind := ue.SmContextFindByPDUSessionID(assignEbiData.PduSessionId); okSmContextFind {
		assignedEbiData := &models.AssignedEbiData{
			PduSessionId: assignEbiData.PduSessionId,
		}
		return assignedEbiData, nil, nil
	}
	logger.ProducerLog.Errorf("SmContext[PDU Session ID:%d] not found", assignEbiData.PduSessionId)
	return nil, nil, nil
}

// TS 29.518 5.2.2.2.2
func (p *Processor) HandleRegistrationStatusUpdateRequest(c *gin.Context,
	ueRegStatusUpdateReqData models.UeRegStatusUpdateReqData,
) {
	logger.CommLog.Info("Handle Registration Status Update Request")

	ueContextID := c.Param("ueContextId")

	ueRegStatusUpdateRspData, problemDetails := p.RegistrationStatusUpdateProcedure(ueContextID, ueRegStatusUpdateReqData)
	if problemDetails != nil {
		c.JSON(int(problemDetails.Status), problemDetails)
	} else {
		c.JSON(http.StatusOK, ueRegStatusUpdateRspData)
	}
}

func (p *Processor) RegistrationStatusUpdateProcedure(ueContextID string,
	ueRegStatusUpdateReqData models.UeRegStatusUpdateReqData) (
	*models.UeRegStatusUpdateRspData, *models.ProblemDetails,
) {
	amfSelf := context.GetSelf()

	// ueContextID must be a 5g GUTI (TS 29.518 6.1.3.2.4.5.1)
	if !strings.HasPrefix(ueContextID, "5g-guti") {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  "UNSPECIFIED",
		}
		return nil, problemDetails
	}

	ue, okAmfUeFindByUeContextID := amfSelf.AmfUeFindByUeContextID(ueContextID)
	if !okAmfUeFindByUeContextID {
		logger.CtxLog.Warnf("AmfUe Context[%s] not found", ueContextID)
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "CONTEXT_NOT_FOUND",
		}
		return nil, problemDetails
	}

	ue.Lock.Lock()
	defer ue.Lock.Unlock()

	ueRegStatusUpdateRspData := new(models.UeRegStatusUpdateRspData)

	if ueRegStatusUpdateReqData.TransferStatus == models.UeContextTransferStatus_TRANSFERRED {
		// remove the individual ueContext resource and release any PDU session(s)
		for _, pduSessionId := range ueRegStatusUpdateReqData.ToReleaseSessionList {
			cause := models.SmfPduSessionCause_REL_DUE_TO_SLICE_NOT_AVAILABLE
			causeAll := &context.CauseAll{
				Cause: &cause,
			}
			smContext, okSmContextFindByPDUSessionID := ue.SmContextFindByPDUSessionID(pduSessionId)
			if !okSmContextFindByPDUSessionID {
				ue.ProducerLog.Errorf("SmContext[PDU Session ID:%d] not found", pduSessionId)
				continue
			}
			problem, err := p.Consumer().SendReleaseSmContextRequest(ue, smContext, causeAll, "", nil)
			if problem != nil {
				logger.GmmLog.Errorf("Release SmContext[pduSessionId: %d] Failed Problem[%+v]", pduSessionId, problem)
			} else if err != nil {
				logger.GmmLog.Errorf("Release SmContext[pduSessionId: %d] Error[%v]", pduSessionId, err.Error())
			}
		}

		if ueRegStatusUpdateReqData.PcfReselectedInd {
			problem, err := p.Consumer().AMPolicyControlDelete(ue)
			if problem != nil {
				logger.GmmLog.Errorf("AM Policy Control Delete Failed Problem[%+v]", problem)
			} else if err != nil {
				logger.GmmLog.Errorf("AM Policy Control Delete Error[%v]", err.Error())
			}
		}
		// TODO: Currently only consider the 3GPP access type
		if !ue.UeCmRegistered[models.AccessType__3_GPP_ACCESS] {
			gmm_common.RemoveAmfUe(ue, false)
		}
	} else {
		// NOT_TRANSFERRED
		logger.CommLog.Debug("[AMF] RegistrationStatusUpdate: NOT_TRANSFERRED")
	}

	ueRegStatusUpdateRspData.RegStatusTransferComplete = true
	return ueRegStatusUpdateRspData, nil
}
