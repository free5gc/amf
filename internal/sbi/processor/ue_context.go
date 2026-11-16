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
	nas_message "github.com/free5gc/nas/message"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/mediatype/multipart"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/metrics/sbi"
)

// TS 29.518 5.2.2.2.3
func (p *Processor) HandleCreateUEContextRequest(
	c *gin.Context,
	createUeContextRequest models.CreateUEContextRequestBody,
) {
	logger.CommLog.Infof("Handle Create UE Context Request")

	ueContextID := c.Param("ueContextId")

	createUeContextResponse, ueContextCreateError := p.CreateUEContextProcedure(ueContextID, createUeContextRequest)
	if ueContextCreateError != nil {
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, ueContextCreateError.JsonData.Error.Cause)
		c.JSON(int(ueContextCreateError.JsonData.Error.Status), ueContextCreateError)
	} else {
		c.Render(http.StatusCreated, openapi.MultipartRelatedRender{Data: createUeContextResponse})
	}
}

func (p *Processor) CreateUEContextProcedure(
	ueContextID string,
	createUeContextRequest models.CreateUEContextRequestBody,
) (
	*models.CreateUEContextResponse201, *models.CreateUEContextResponse403,
) {
	amfSelf := context.GetSelf()
	ueContextCreateData := createUeContextRequest.JsonData

	if ueContextCreateData.UeContext == nil || ueContextCreateData.TargetId == nil ||
		ueContextCreateData.TargetId.RanNodeId == nil || ueContextCreateData.TargetId.Tai == nil ||
		ueContextCreateData.TargetId.Tai.PlmnId == nil ||
		ueContextCreateData.PduSessionList == nil || ueContextCreateData.SourceToTargetData == nil ||
		ueContextCreateData.N2NotifyUri == "" {
		ueCtxCreateError := models.Amf_Comm_UeContextCreateError{
			Error: &models.ProblemDetails{
				Status: http.StatusForbidden,
				Cause:  "HANDOVER_FAILURE",
			},
		}
		ueContextCreateError := &models.CreateUEContextResponse403{
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
	// ue.N1N2Message[ueContextId].Request.JsonData = &models.Amf_Comm_N1N2MessageTransferReqData{
	// 	N2InfoContainer: &models.Amf_Comm_N2InfoContainer{
	// 		SmInfo: &models.Amf_Comm_N2SmInformation{
	// 			N2InfoContent: ueContextCreateData.SourceToTargetData,
	// 		},
	// 	},
	// }
	ue.HandoverNotifyUri = ueContextCreateData.N2NotifyUri

	targetRanNodeId := ueContextCreateData.TargetId.RanNodeId
	targetRan, ok := amfSelf.AmfRanFindByRanID(*targetRanNodeId)
	// TS 23.502 4.9.1.3.2 Step 4 Filter PDU Sessions not supported in Target TAI
	targetTai := *ueContextCreateData.TargetId.Tai
	supportedPdusessionList := []models.Amf_Comm_N2SmInformation{}
	for _, smInfo := range ueContextCreateData.PduSessionList {
		if smInfo.SNssai != nil {
			if ok && ue.CheckSliceAvailabilityInTargetRan(*smInfo.SNssai, targetRan, targetTai) {
				supportedPdusessionList = append(supportedPdusessionList, smInfo)
			} else {
				ue.ProducerLog.Warnf("Handover Filter: PDU Session %d (S-NSSAI: %+v) not supported in Target TAI %v, skipping.",
					smInfo.PduSessionId, smInfo.SNssai, targetTai.Tac)
			}
		} else {
			supportedPdusessionList = append(supportedPdusessionList, smInfo)
		}
	}

	amfSelf.AmfRanFindByRanID(*ueContextCreateData.TargetId.RanNodeId)
	supportedTAI := context.NewSupportedTAI()
	supportedTAI.Tai.Tac = ueContextCreateData.TargetId.Tai.Tac
	supportedTAI.Tai.PlmnId = ueContextCreateData.TargetId.Tai.PlmnId
	// ue.N1N2MessageSubscribeInfo[ueContextID] = &models.Amf_Comm_UeN1N2InfoSubscriptionCreateData{
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
	if len(ueContextCreateData.UeContext.RestrictedRatList) > 0 {
		ue.RatType = ueContextCreateData.UeContext.RestrictedRatList[0] // minItem = -1
	} else {
		logger.CtxLog.Debugf("ueContextCreateData.UeContext.RestrictedRatList is empty")
	}
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
	createUeContextResponse := new(models.CreateUEContextResponse201)
	createUeContextResponse.JsonData = &models.Amf_Comm_UeContextCreatedData{
		UeContext: &models.Amf_Comm_UeContext{
			Supi: ueContextCreateData.UeContext.Supi,
		},
	}

	// response.JsonData.TargetToSourceData =
	// ue.N1N2Message[ueContextId].Request.JsonData.N2InfoContainer.SmInfo.N2InfoContent
	createUeContextResponse.JsonData.PduSessionList = supportedPdusessionList
	createUeContextResponse.JsonData.PcfReselectedInd = false
	// TODO: When  Target AMF selects a nw PCF for AM policy, set the flag to true.

	//	response.UeContext = ueContextCreateData.UeContext
	//	response.TargetToSourceData = ue.N1N2Message[amfSelf.Uri].Request.JsonData.N2InfoContainer.SmInfo.N2InfoContent
	//	response.PduSessionList = ueContextCreateData.PduSessionList
	//	response.PcfReselectedInd = false // TODO:When  Target AMF selects a nw PCF for AM policy, set the flag to true.
	//

	// return httpwrapper.NewResponse(http.StatusCreated, nil, createUeContextResponse)
	return createUeContextResponse, nil
}

// TS 29.518 5.2.2.2.4
func (p *Processor) HandleReleaseUEContextRequest(c *gin.Context, ueContextRelease models.Amf_Comm_UEContextRelease) {
	logger.CommLog.Info("Handle Release UE Context Request")

	ueContextID := c.Param("ueContextId")

	problemDetails := p.ReleaseUEContextProcedure(ueContextID, ueContextRelease)
	if problemDetails != nil {
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
		c.JSON(int(problemDetails.Status), problemDetails)
	} else {
		c.Status(http.StatusNoContent)
	}
}

func (p *Processor) ReleaseUEContextProcedure(ueContextID string,
	ueContextRelease models.Amf_Comm_UEContextRelease,
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

func (p *Processor) HandleMobiRegUe(
	ue *context.AmfUe,
	ueContextTransferRspData *models.Amf_Comm_UeContextTransferRspData,
	ueContextTransferResponse *models.UEContextTransferResponse200,
) {
	ueContextTransferRspData.UeRadioCapability = &models.Amf_Comm_N2InfoContent{
		NgapMessageType: 0,
		NgapIeType:      models.Amf_Comm_NgapIeType_UE_RADIO_CAPABILITY,
		NgapData: &models.RefToBinaryData{
			ContentId: "n2Info",
		},
	}
	b := []byte(ue.UeRadioCapability)
	ueContextTransferResponse.BinaryDataN2Information = &multipart.RelatedContent{
		ContentID: "n2Info",
		Content:   b,
	}
}

// TS 29.518 5.2.2.2.1
func (p *Processor) HandleUEContextTransferRequest(c *gin.Context,
	ueContextTransferRequest models.UEContextTransferRequestBody,
) {
	logger.CommLog.Info("Handle UE Context Transfer Request")

	ueContextID := c.Param("ueContextId")

	ueContextTransferResponse, problemDetails := p.UEContextTransferProcedure(ueContextID, ueContextTransferRequest)
	if problemDetails != nil {
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
		c.JSON(int(problemDetails.Status), problemDetails)
	} else {
		c.Render(http.StatusOK, openapi.MultipartRelatedRender{Data: ueContextTransferResponse})
	}
}

func (p *Processor) UEContextTransferProcedure(ueContextID string,
	ueContextTransferRequest models.UEContextTransferRequestBody) (
	*models.UEContextTransferResponse200, *models.ProblemDetails,
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

	ueContextTransferResponse := &models.UEContextTransferResponse200{
		JsonData: new(models.Amf_Comm_UeContextTransferRspData),
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
	case models.Amf_Comm_TransferReason_INIT_REG:
		_, integrityProtected, err := nas_security.Decode(ue, UeContextTransferReqData.AccessType,
			relatedContentBytes(ueContextTransferRequest.BinaryDataN1Message), true)
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
	case models.Amf_Comm_TransferReason_MOBI_REG:
		_, integrityProtected, err := nas_security.Decode(ue, UeContextTransferReqData.AccessType,
			relatedContentBytes(ueContextTransferRequest.BinaryDataN1Message), false)
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

	case models.Amf_Comm_TransferReason_MOBI_REG_UE_VALIDATED:
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

func (p *Processor) buildUEContextModel(
	ue *context.AmfUe,
	reason models.Amf_Comm_TransferReason,
) *models.Amf_Comm_UeContext {
	ueContext := new(models.Amf_Comm_UeContext)
	ueContext.Supi = ue.Supi
	ueContext.SupiUnauthInd = ue.UnauthenticatedSupi
	if reason == models.Amf_Comm_TransferReason_INIT_REG || reason == models.Amf_Comm_TransferReason_MOBI_REG {
		var mmContext models.Amf_Comm_MmContext
		mmContext.AccessType = models.AccessType_3_GPP_ACCESS
		NasSecurityMode := new(models.Amf_Comm_NasSecurityMode)
		switch ue.IntegrityAlg {
		case uint8(nas_message.AlgIntegrity128NIA0):
			NasSecurityMode.IntegrityAlgorithm = models.Amf_Comm_IntegrityAlgorithm_NIA0
		case uint8(nas_message.AlgIntegrity128NIA1):
			NasSecurityMode.IntegrityAlgorithm = models.Amf_Comm_IntegrityAlgorithm_NIA1
		case uint8(nas_message.AlgIntegrity128NIA2):
			NasSecurityMode.IntegrityAlgorithm = models.Amf_Comm_IntegrityAlgorithm_NIA2
		case uint8(nas_message.AlgIntegrity128NIA3):
			NasSecurityMode.IntegrityAlgorithm = models.Amf_Comm_IntegrityAlgorithm_NIA3
		}
		switch ue.CipheringAlg {
		case uint8(nas_message.AlgCiphering128NEA0):
			NasSecurityMode.CipheringAlgorithm = models.Amf_Comm_CipheringAlgorithm_NEA0
		case uint8(nas_message.AlgCiphering128NEA1):
			NasSecurityMode.CipheringAlgorithm = models.Amf_Comm_CipheringAlgorithm_NEA1
		case uint8(nas_message.AlgCiphering128NEA2):
			NasSecurityMode.CipheringAlgorithm = models.Amf_Comm_CipheringAlgorithm_NEA2
		case uint8(nas_message.AlgCiphering128NEA3):
			NasSecurityMode.CipheringAlgorithm = models.Amf_Comm_CipheringAlgorithm_NEA3
		}
		NgKsi := new(models.Amf_Comm_NgKsi)
		NgKsi.Ksi = ue.NgKsi.Ksi
		NgKsi.Tsc = ue.NgKsi.Tsc
		KeyAmf := new(models.Amf_Comm_KeyAmf)
		KeyAmf.KeyType = models.Amf_Comm_KeyAmfType_KAMF
		KeyAmf.KeyVal = ue.Kamf
		SeafData := new(models.Amf_Comm_SeafData)
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
		if ue.UESecurityCapability.Length > 0 {
			if capability, err := ue.UESecurityCapability.MarshalBinary(); err == nil {
				mmContext.UeSecurityCapability = base64.StdEncoding.EncodeToString(capability)
			}
		}
		ulCount, dlCount := ue.NASCounts()
		mmContext.NasDownlinkCount = int32(dlCount.Get())
		mmContext.NasUplinkCount = int32(ulCount.Get())
		if ue.AllowedNssai[models.AccessType_3_GPP_ACCESS] != nil {
			for _, allowedSnssai := range ue.AllowedNssai[models.AccessType_3_GPP_ACCESS] {
				mmContext.AllowedNssai = append(mmContext.AllowedNssai, *(allowedSnssai.AllowedSnssai))
			}
		}
		ueContext.MmContextList = append(ueContext.MmContextList, mmContext)
	}
	if reason == models.Amf_Comm_TransferReason_MOBI_REG_UE_VALIDATED ||
		reason == models.Amf_Comm_TransferReason_MOBI_REG {
		sessionContextList := &ueContext.SessionContextList
		ue.SmContextList.Range(func(key, value interface{}) bool {
			smContext := value.(*context.SmContext)
			snssai := smContext.Snssai()
			pduSessionContext := models.Amf_Comm_PduSessionContext{
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

func (p *Processor) buildAmPolicyReqTriggers(triggers []models.Pcf_AMPolCtrl_RequestTrigger) (
	amPolicyReqTriggers []models.Amf_Comm_PolicyReqTrigger,
) {
	for _, trigger := range triggers {
		switch trigger {
		case models.Pcf_AMPolCtrl_RequestTrigger_LOC_CH:
			amPolicyReqTriggers = append(amPolicyReqTriggers, models.Amf_Comm_PolicyReqTrigger_LOCATION_CHANGE)
		case models.Pcf_AMPolCtrl_RequestTrigger_PRA_CH:
			amPolicyReqTriggers = append(amPolicyReqTriggers, models.Amf_Comm_PolicyReqTrigger_PRA_CHANGE)
		case models.Pcf_AMPolCtrl_RequestTrigger_ALLOWED_NSSAI_CH:
			amPolicyReqTriggers = append(amPolicyReqTriggers, models.Amf_Comm_PolicyReqTrigger_ALLOWED_NSSAI_CHANGE)
		case models.Pcf_AMPolCtrl_RequestTrigger_NWDAF_DATA_CH:
			amPolicyReqTriggers = append(amPolicyReqTriggers, models.Amf_Comm_PolicyReqTrigger_NWDAF_DATA_CHANGE)
		case models.Pcf_AMPolCtrl_RequestTrigger_SMF_SELECT_CH:
			amPolicyReqTriggers = append(amPolicyReqTriggers, models.Amf_Comm_PolicyReqTrigger_SMF_SELECT_CHANGE)
		case models.Pcf_AMPolCtrl_RequestTrigger_ACCESS_TYPE_CH:
			amPolicyReqTriggers = append(amPolicyReqTriggers, models.Amf_Comm_PolicyReqTrigger_ACCESS_TYPE_CHANGE)
		}
	}
	return
}

// TS 29.518 5.2.2.6
func (p *Processor) HandleAssignEbiDataRequest(c *gin.Context, assignEbiData models.Amf_Comm_AssignEbiData) {
	logger.CommLog.Info("Handle Assign Ebi Data Request")

	ueContextID := c.Param("ueContextId")

	assignedEbiData, assignEbiError, problemDetails := p.AssignEbiDataProcedure(ueContextID, assignEbiData)
	if problemDetails != nil {
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
		c.JSON(int(problemDetails.Status), problemDetails)
	} else if assignEbiError != nil {
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, assignEbiError.Error.Cause)
		c.JSON(int(assignEbiError.Error.Status), assignEbiError)
	} else {
		c.JSON(http.StatusOK, assignedEbiData)
	}
}

func (p *Processor) AssignEbiDataProcedure(ueContextID string, assignEbiData models.Amf_Comm_AssignEbiData) (
	*models.Amf_Comm_AssignedEbiData, *models.Amf_Comm_AssignEbiError, *models.ProblemDetails,
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
		assignedEbiData := &models.Amf_Comm_AssignedEbiData{
			PduSessionId: assignEbiData.PduSessionId,
		}
		return assignedEbiData, nil, nil
	}
	logger.ProducerLog.Errorf("SmContext[PDU Session ID:%d] not found", assignEbiData.PduSessionId)
	return nil, nil, nil
}

// TS 29.518 5.2.2.2.2
func (p *Processor) HandleRegistrationStatusUpdateRequest(c *gin.Context,
	ueRegStatusUpdateReqData models.Amf_Comm_UeRegStatusUpdateReqData,
) {
	logger.CommLog.Info("Handle Registration Status Update Request")

	ueContextID := c.Param("ueContextId")

	ueRegStatusUpdateRspData, problemDetails := p.RegistrationStatusUpdateProcedure(ueContextID, ueRegStatusUpdateReqData)
	if problemDetails != nil {
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
		c.JSON(int(problemDetails.Status), problemDetails)
	} else {
		c.JSON(http.StatusOK, ueRegStatusUpdateRspData)
	}
}

func (p *Processor) RegistrationStatusUpdateProcedure(ueContextID string,
	ueRegStatusUpdateReqData models.Amf_Comm_UeRegStatusUpdateReqData) (
	*models.Amf_Comm_UeRegStatusUpdateRspData, *models.ProblemDetails,
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

	ueRegStatusUpdateRspData := new(models.Amf_Comm_UeRegStatusUpdateRspData)

	if ueRegStatusUpdateReqData.TransferStatus == models.Amf_Comm_UeContextTransferStatus_TRANSFERRED {
		// remove the individual ueContext resource and release any PDU session(s)
		for _, pduSessionId := range ueRegStatusUpdateReqData.ToReleaseSessionList {
			cause := models.Smf_PDUSess_Cause_REL_DUE_TO_SLICE_NOT_AVAILABLE
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
		if !ue.UeCmRegistered[models.AccessType_3_GPP_ACCESS] {
			gmm_common.RemoveAmfUe(ue, false)
		}
	} else {
		// NOT_TRANSFERRED
		logger.CommLog.Debug("[AMF] RegistrationStatusUpdate: NOT_TRANSFERRED")
	}

	ueRegStatusUpdateRspData.RegStatusTransferComplete = true
	return ueRegStatusUpdateRspData, nil
}
