package consumer

import (
	"fmt"
	"sync"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/nas/ie"
	"github.com/free5gc/openapi"
	Namf_Communication "github.com/free5gc/openapi/amf/Comm"
	"github.com/free5gc/openapi/mediatype/multipart"
	"github.com/free5gc/openapi/models"
	sbi_metrics "github.com/free5gc/util/metrics/sbi"
)

type namfService struct {
	consumer *Consumer

	ComMu sync.RWMutex

	ComClients map[string]*Namf_Communication.APIClient
}

func (s *namfService) getComClient(uri string) *Namf_Communication.APIClient {
	if uri == "" {
		return nil
	}
	s.ComMu.RLock()
	client, ok := s.ComClients[uri]
	if ok {
		s.ComMu.RUnlock()
		return client
	}

	configuration := Namf_Communication.NewConfiguration()
	configuration.SetBasePath(uri)
	configuration.SetMetrics(sbi_metrics.SbiMetricHook)
	client = Namf_Communication.NewAPIClient(configuration)

	s.ComMu.RUnlock()
	s.ComMu.Lock()
	defer s.ComMu.Unlock()
	s.ComClients[uri] = client
	return client
}

func (s *namfService) BuildUeContextCreateData(ue *amf_context.AmfUe, targetRanId models.Amf_Comm_NgRanTargetId,
	sourceToTargetData models.Amf_Comm_N2InfoContent, pduSessionList []models.Amf_Comm_N2SmInformation,
	n2NotifyUri string, ngapCause *models.NgApCause,
) models.Amf_Comm_UeContextCreateData {
	var ueContextCreateData models.Amf_Comm_UeContextCreateData

	ueContext := s.BuildUeContextModel(ue)
	ueContextCreateData.UeContext = &ueContext
	ueContextCreateData.TargetId = &targetRanId
	ueContextCreateData.SourceToTargetData = &sourceToTargetData
	ueContextCreateData.PduSessionList = pduSessionList
	ueContextCreateData.N2NotifyUri = n2NotifyUri

	if ue.UeRadioCapability != "" {
		ueContextCreateData.UeRadioCapability = &models.Amf_Comm_N2InfoContent{
			NgapData: &models.RefToBinaryData{
				ContentId: ue.UeRadioCapability,
			},
		}
	}
	ueContextCreateData.NgapCause = ngapCause
	return ueContextCreateData
}

func (s *namfService) BuildUeContextModel(ue *amf_context.AmfUe) (ueContext models.Amf_Comm_UeContext) {
	ueContext.Supi = ue.Supi
	ueContext.SupiUnauthInd = ue.UnauthenticatedSupi

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
			ueContext.AmPolicyReqTriggerList = s.buildAmPolicyReqTriggers(ue.AmPolicyAssociation.Triggers)
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

func (s *namfService) buildAmPolicyReqTriggers(
	triggers []models.Pcf_AMPolCtrl_RequestTrigger,
) (amPolicyReqTriggers []models.Amf_Comm_PolicyReqTrigger) {
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

func (s *namfService) CreateUEContextRequest(
	ue *amf_context.AmfUe,
	ueContextCreateData models.Amf_Comm_UeContextCreateData,
) (
	ueContextCreatedData *models.Amf_Comm_UeContextCreatedData, problemDetails *models.ProblemDetails, err error,
) {
	client := s.getComClient(ue.TargetAmfUri)
	if client == nil {
		return nil, nil, openapi.ReportError("amf not found")
	}
	targetAMFID, err := targetAMFInstanceID(ue)
	if err != nil {
		return nil, nil, err
	}

	req := models.CreateUEContextRequestBody{
		JsonData: &ueContextCreateData,
	}
	ctx, _, err := amf_context.GetSelf().GetTokenCtxForNFInstance(
		models.Nrf_NFMgmt_ServiceName_NAMF_COMM, models.Nrf_NFMgmt_NFType_AMF, targetAMFID)
	if err != nil {
		return nil, nil, err
	}

	creatuectxreq := Namf_Communication.CreateUEContextRequest{
		UeContextId: &ue.Supi,
		RequestBody: &req,
	}

	res, localErr := client.IndividualUeContextDocumentApi.CreateUEContext(ctx, &creatuectxreq)
	if localErr == nil {
		if res == nil || res.CreateUEContextResponse201 == nil {
			return nil, openapi.ProblemDetailsSystemFailure(
				"invalid UE context create response: missing response data",
			), nil
		}
		ueContextCreatedData = res.CreateUEContextResponse201.JsonData
		if ueContextCreatedData == nil {
			return nil, openapi.ProblemDetailsSystemFailure(
				"invalid UE context create response: missing JSON data",
			), nil
		}
		logger.ConsumerLog.Debugf("UeContextCreatedData: %+v", *ueContextCreatedData)
	} else {
		if apiErr, ok := localErr.(openapi.GenericOpenAPIError); ok {
			switch createErr := apiErr.Model().(type) {
			case Namf_Communication.CreateUEContextError:
				return nil, createErr.ProblemDetails, nil
			case *Namf_Communication.CreateUEContextError:
				return nil, createErr.ProblemDetails, nil
			}
		}
		return nil, nil, localErr
	}
	return ueContextCreatedData, problemDetails, err
}

func (s *namfService) ReleaseUEContextRequest(ue *amf_context.AmfUe, ngapCause models.NgApCause) (
	problemDetails *models.ProblemDetails, err error,
) {
	client := s.getComClient(ue.TargetAmfUri)
	if client == nil {
		return nil, openapi.ReportError("amf not found")
	}
	targetAMFID, err := targetAMFInstanceID(ue)
	if err != nil {
		return nil, err
	}

	var ueContextId string
	if ue.Supi != "" {
		ueContextId = ue.Supi
	} else {
		ueContextId = ue.Pei
	}

	ueContextRelease := models.Amf_Comm_UEContextRelease{
		NgapCause: &ngapCause,
	}
	if ue.RegistrationType5GS == ie.RegType_EmergReg && ue.UnauthenticatedSupi {
		ueContextRelease.Supi = ue.Supi
		ueContextRelease.UnauthenticatedSupi = true
	}
	ctx, _, err := amf_context.GetSelf().GetTokenCtxForNFInstance(
		models.Nrf_NFMgmt_ServiceName_NAMF_COMM, models.Nrf_NFMgmt_NFType_AMF, targetAMFID)
	if err != nil {
		return nil, err
	}

	ueCtxReleaseReq := Namf_Communication.ReleaseUEContextRequest{
		UeContextId: &ueContextId,
		RequestBody: &ueContextRelease,
	}

	_, err = client.IndividualUeContextDocumentApi.ReleaseUEContext(
		ctx, &ueCtxReleaseReq)
	if err != nil {
		switch apiErr := err.(type) {
		// API error
		case openapi.GenericOpenAPIError:
			switch errModel := apiErr.Model().(type) {
			case Namf_Communication.ReleaseUEContextError:
				return errModel.ProblemDetails, nil
			case error:
				return openapi.ProblemDetailsSystemFailure(errModel.Error()), nil
			default:
				return nil, openapi.ReportError("openapi error")
			}
		case error:
			return openapi.ProblemDetailsSystemFailure(apiErr.Error()), nil
		default:
			return nil, openapi.ReportError("server no response")
		}
	}
	return nil, nil
}

func (s *namfService) UEContextTransferRequest(
	ue *amf_context.AmfUe, accessType models.AccessType, transferReason models.Amf_Comm_TransferReason) (
	ueContextTransferRspData *models.Amf_Comm_UeContextTransferRspData, problemDetails *models.ProblemDetails, err error,
) {
	client := s.getComClient(ue.TargetAmfUri)
	if client == nil {
		return nil, nil, openapi.ReportError("amf not found")
	}
	targetAMFID, err := targetAMFInstanceID(ue)
	if err != nil {
		return nil, nil, err
	}

	ueContextTransferReqData := models.Amf_Comm_UeContextTransferReqData{
		Reason:     transferReason,
		AccessType: accessType,
	}

	req := models.UEContextTransferRequestBody{
		JsonData: &ueContextTransferReqData,
	}
	if transferReason == models.Amf_Comm_TransferReason_INIT_REG ||
		transferReason == models.Amf_Comm_TransferReason_MOBI_REG {
		ueContextTransferReqData.RegRequest = &models.Amf_Comm_N1MessageContainer{
			N1MessageClass: models.Amf_Comm_N1MessageClass_5_GMM,
			N1MessageContent: &models.RefToBinaryData{
				ContentId: "n1Msg",
			},
		}
		req.BinaryDataN1Message = &multipart.RelatedContent{
			ContentID: "n1Msg",
			Content:   ue.NasPduValue,
		}
	}

	// guti format is defined at TS 29.518 Table 6.1.3.2.2-1 5g-guti-[0-9]{5,6}[0-9a-fA-F]{14}
	ueContextId := fmt.Sprintf("5g-guti-%s", ue.Guti)

	ctx, _, err := amf_context.GetSelf().GetTokenCtxForNFInstance(
		models.Nrf_NFMgmt_ServiceName_NAMF_COMM, models.Nrf_NFMgmt_NFType_AMF, targetAMFID)
	if err != nil {
		return nil, nil, err
	}

	ueCtxTransferReq := Namf_Communication.UEContextTransferRequest{
		UeContextId: &ueContextId,
		RequestBody: &req,
	}

	res, localErr := client.IndividualUeContextDocumentApi.UEContextTransfer(ctx, &ueCtxTransferReq)
	if localErr == nil {
		if res == nil || res.UEContextTransferResponse200 == nil ||
			res.UEContextTransferResponse200.JsonData == nil {
			problemDetails = openapi.ProblemDetailsSystemFailure("invalid UE context transfer response: missing response data")
			return ueContextTransferRspData, problemDetails, err
		}
		ueContextTransferRspData = res.UEContextTransferResponse200.JsonData
		if ueContextTransferRspData == nil {
			logger.ConsumerLog.Warnln("UeContextTransfer 200 response missing JsonData")
			problemDetails = openapi.ProblemDetailsSystemFailure("invalid UE context transfer response: missing response data")
			err = openapi.ReportError("UeContextTransfer 200 missing JsonData")
			return ueContextTransferRspData, problemDetails, err
		}
		if ueContextTransferRspData.UeContext == nil {
			problemDetails = openapi.ProblemDetailsSystemFailure("invalid UE context transfer response: missing UE context")
			return ueContextTransferRspData, problemDetails, err
		}
		logger.ConsumerLog.Debugf("UeContextTransferRspData: %+v", *ueContextTransferRspData)
	} else {
		switch apiErr := localErr.(type) {
		// API error
		case openapi.GenericOpenAPIError:
			switch errModel := apiErr.Model().(type) {
			case Namf_Communication.UEContextTransferError:
				problemDetails = errModel.ProblemDetails
			case error:
				problemDetails = openapi.ProblemDetailsSystemFailure(errModel.Error())
			default:
				err = openapi.ReportError("openapi error")
			}
		case error:
			problemDetails = openapi.ProblemDetailsSystemFailure(apiErr.Error())
		default:
			err = openapi.ReportError("server no response")
		}
	}
	return ueContextTransferRspData, problemDetails, err
}

func (s *namfService) RegistrationStatusUpdate(
	ue *amf_context.AmfUe,
	request models.Amf_Comm_UeRegStatusUpdateReqData,
) (
	regStatusTransferComplete bool, problemDetails *models.ProblemDetails, err error,
) {
	client := s.getComClient(ue.TargetAmfUri)
	if client == nil {
		return false, nil, openapi.ReportError("amf not found")
	}
	targetAMFID, err := targetAMFInstanceID(ue)
	if err != nil {
		return false, nil, err
	}

	ueContextId := fmt.Sprintf("5g-guti-%s", ue.Guti)

	ctx, _, err := amf_context.GetSelf().GetTokenCtxForNFInstance(
		models.Nrf_NFMgmt_ServiceName_NAMF_COMM, models.Nrf_NFMgmt_NFType_AMF, targetAMFID)
	if err != nil {
		return regStatusTransferComplete, nil, err
	}

	regStatusUpdateReq := Namf_Communication.RegistrationStatusUpdateRequest{
		UeContextId: &ueContextId,
		RequestBody: &request,
	}

	res, localErr := client.IndividualUeContextDocumentApi.
		RegistrationStatusUpdate(ctx, &regStatusUpdateReq)
	if localErr == nil {
		regStatusTransferComplete = res.Amf_Comm_UeRegStatusUpdateRspData.RegStatusTransferComplete
	} else {
		switch apiErr := localErr.(type) {
		// API error
		case openapi.GenericOpenAPIError:
			switch errModel := apiErr.Model().(type) {
			case Namf_Communication.RegistrationStatusUpdateError:
				problemDetails = errModel.ProblemDetails
			case error:
				problemDetails = openapi.ProblemDetailsSystemFailure(errModel.Error())
			default:
				err = openapi.ReportError("openapi error")
			}
		case error:
			problemDetails = openapi.ProblemDetailsSystemFailure(apiErr.Error())
		default:
			err = openapi.ReportError("server no response")
		}
	}
	return regStatusTransferComplete, problemDetails, err
}

func targetAMFInstanceID(ue *amf_context.AmfUe) (string, error) {
	if ue == nil || ue.TargetAmfProfile == nil {
		return "", openapi.ReportError("target AMF profile not found")
	}
	return ue.TargetAmfProfile.NfInstanceId, nil
}
