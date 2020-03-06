package amf_consumer

import (
	"context"
	"gofree5gc/lib/Namf_Communication"
	"gofree5gc/lib/nas/nasMessage"
	"gofree5gc/lib/openapi/common"
	"gofree5gc/lib/openapi/models"
	"gofree5gc/src/amf/amf_context"
	"gofree5gc/src/amf/logger"
)

func BuildUeContextCreateData(ue *amf_context.AmfUe, targetRanId models.NgRanTargetId, sourceToTargetData models.N2InfoContent, pduSessionList []models.N2SmInformation, n2NotifyUri string, ngapCause *models.NgApCause) (ueContextCreateData models.UeContextCreateData) {

	ueContext := models.UeContext{
		Supi:          ue.Supi,
		SupiUnauthInd: ue.UnauthenticatedSupi,
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
			ueContext.AmPolicyReqTriggerList = buildAmPolicyReqTriggers(ue.AmPolicyAssociation.Triggers)
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

	ueContextCreateData.UeContext = &ueContext
	ueContextCreateData.TargetId = &targetRanId
	ueContextCreateData.SourceToTargetData = &sourceToTargetData
	ueContextCreateData.PduSessionList = pduSessionList
	ueContextCreateData.N2NotifyUri = n2NotifyUri

	if ue.UeRadioCapability != "" {
		ueContextCreateData.UeRadioCapability = &models.N2InfoContent{
			NgapData: &models.RefToBinaryData{
				ContentId: ue.UeRadioCapability,
			},
		}
	}
	ueContextCreateData.NgapCause = ngapCause
	return
}

func buildAmPolicyReqTriggers(triggers []models.RequestTrigger) (amPolicyReqTriggers []models.AmPolicyReqTrigger) {
	for _, trigger := range triggers {
		switch trigger {
		case models.RequestTrigger_LOC_CH:
			amPolicyReqTriggers = append(amPolicyReqTriggers, models.AmPolicyReqTrigger_LOCATION_CHANGE)
		case models.RequestTrigger_PRA_CH:
			amPolicyReqTriggers = append(amPolicyReqTriggers, models.AmPolicyReqTrigger_PRA_CHANGE)
		case models.RequestTrigger_SERV_AREA_CH:
			amPolicyReqTriggers = append(amPolicyReqTriggers, models.AmPolicyReqTrigger_SARI_CHANGE)
		case models.RequestTrigger_RFSP_CH:
			amPolicyReqTriggers = append(amPolicyReqTriggers, models.AmPolicyReqTrigger_RFSP_INDEX_CHANGE)
		}
	}
	return
}

func CreateUEContextRequest(ue *amf_context.AmfUe, targetAmfUri string, ueContextCreateData models.UeContextCreateData) (ueContextCreatedData *models.UeContextCreatedData, problemDetails *models.ProblemDetails, err error) {
	configuration := Namf_Communication.NewConfiguration()
	configuration.SetBasePath(targetAmfUri)
	client := Namf_Communication.NewAPIClient(configuration)

	req := models.CreateUeContextRequest{
		JsonData: &ueContextCreateData,
	}
	res, httpResp, localErr := client.IndividualUeContextDocumentApi.CreateUEContext(context.TODO(), ue.Guti, req)
	if localErr == nil {
		logger.ConsumerLog.Debugf("UeContextCreatedData: %+v", *res.JsonData)
		ueContextCreatedData = res.JsonData
	} else if httpResp != nil {
		if httpResp.Status != localErr.Error() {
			err = localErr
			return
		}
		problem := localErr.(common.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = common.ReportError("%s: erver no response", targetAmfUri)
	}
	return
}

func ReleaseUEContextRequest(ue *amf_context.AmfUe, targetAmfUri string, ngapCause models.NgApCause) (problemDetails *models.ProblemDetails, err error) {
	configuration := Namf_Communication.NewConfiguration()
	configuration.SetBasePath(targetAmfUri)
	client := Namf_Communication.NewAPIClient(configuration)

	var ueContextId string
	if ue.Supi != "" {
		ueContextId = ue.Supi
	} else {
		ueContextId = ue.Pei
	}

	ueContextRelease := models.UeContextRelease{
		NgapCause: &ngapCause,
	}
	if ue.RegistrationType5GS == nasMessage.RegistrationType5GSEmergencyRegistration && ue.UnauthenticatedSupi {
		ueContextRelease.Supi = ue.Supi
		ueContextRelease.UnauthenticatedSupi = true
	}

	httpResp, localErr := client.IndividualUeContextDocumentApi.ReleaseUEContext(context.TODO(), ueContextId, ueContextRelease)
	if localErr == nil {
		return
	} else if httpResp != nil {
		if httpResp.Status != localErr.Error() {
			err = localErr
			return
		}
		problem := localErr.(common.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = common.ReportError("%s: erver no response", targetAmfUri)
	}
	return
}

func UEContextTransferRequest(ue *amf_context.AmfUe, accessType models.AccessType, transferReason models.TransferReason) (ueContextTransferRspData *models.UeContextTransferRspData, problemDetails *models.ProblemDetails, err error) {
	return
}

func RegistrationCompleteNotify(ue *amf_context.AmfUe) (problemDetails models.ProblemDetails, err error) {
	return
}

func N2InfoNotify(ue *amf_context.AmfUe) (problemDetails models.ProblemDetails, err error) {
	return
}

func N1MessageNotify(ue *amf_context.AmfUe) (problemDetails models.ProblemDetails, err error) {
	return
}
