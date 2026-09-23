package message

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	ngapConvert "github.com/free5gc/amf/internal/ngap/convert"
	"github.com/free5gc/amf/internal/util"
	"github.com/free5gc/amf/pkg/factory"
	ngapAper "github.com/free5gc/ngap/aper"
	ngapIE "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

const (
	CauseChoiceRadioNetwork = 1
	CauseChoiceTransport    = 2
	CauseChoiceNas          = 3
	CauseChoiceProtocol     = 4
	CauseChoiceMisc         = 5
)

func BuildPDUSessionResourceReleaseCommand(
	ue *context.RanUe,
	nasPdu []byte,
	releasedList ngapIE.PDUSessionResourceToReleaseListRelCmd,
) ([]byte, error) {
	if ue == nil {
		return nil, fmt.Errorf("ranUe is nil")
	}
	command := &ngapMessage.PDUSessionResourceReleaseCommand{
		AMFUENGAPID:                           &ngapIE.AMFUENGAPID{Value: ue.AmfUeNgapId},
		RANUENGAPID:                           &ngapIE.RANUENGAPID{Value: ue.RanUeNgapId},
		PDUSessionResourceToReleaseListRelCmd: &releasedList,
	}
	if nasPdu != nil {
		command.NASPDU = &ngapIE.NASPDU{Value: nasPdu}
	}
	return command.MarshalBinary()
}

func BuildNGSetupResponse(criticalityDiagnostics *ngapIE.CriticalityDiagnostics) ([]byte, error) {
	amfSelf := context.GetSelf()
	return (&ngapMessage.NGSetupResponse{
		AMFName:                &ngapIE.AMFName{Value: ngapAper.PrintableString(amfSelf.Name)},
		ServedGUAMIList:        buildServedGUAMIList(amfSelf.ServedGuamiList),
		RelativeAMFCapacity:    &ngapIE.RelativeAMFCapacity{Value: amfSelf.RelativeCapacity},
		PLMNSupportList:        buildPLMNSupportList(amfSelf.PlmnSupportList),
		CriticalityDiagnostics: criticalityDiagnostics,
	}).MarshalBinary()
}

func BuildNGSetupFailure(
	cause ngapIE.Cause,
	criticalityDiagnostics *ngapIE.CriticalityDiagnostics,
) ([]byte, error) {
	return (&ngapMessage.NGSetupFailure{
		Cause:                  &cause,
		CriticalityDiagnostics: criticalityDiagnostics,
	}).MarshalBinary()
}

func BuildNGReset(
	cause ngapIE.Cause,
	partOfNGInterface *ngapIE.UEAssociatedLogicalNGConnectionList,
) ([]byte, error) {
	resetType := &ngapIE.ResetType{}
	if partOfNGInterface == nil {
		resetType.Choice = &ngapIE.ResetAll{Value: ngapIE.ResetAllPresentResetAll}
	} else {
		resetType.Choice = partOfNGInterface
	}
	return (&ngapMessage.NGReset{Cause: &cause, ResetType: resetType}).MarshalBinary()
}

func BuildNGResetAcknowledge(
	partOfNGInterface *ngapIE.UEAssociatedLogicalNGConnectionList,
	criticalityDiagnostics *ngapIE.CriticalityDiagnostics,
) ([]byte, error) {
	return (&ngapMessage.NGResetAcknowledge{
		UEAssociatedLogicalNGConnectionList: partOfNGInterface,
		CriticalityDiagnostics:              criticalityDiagnostics,
	}).MarshalBinary()
}

func BuildDownlinkNasTransport(
	ue *context.RanUe,
	nasPdu []byte,
	mobilityRestrictionList *ngapIE.MobilityRestrictionList,
) ([]byte, error) {
	if ue == nil {
		return nil, fmt.Errorf("ranUe is nil")
	}
	request := &ngapMessage.DownlinkNASTransport{
		AMFUENGAPID: &ngapIE.AMFUENGAPID{Value: ue.AmfUeNgapId},
		RANUENGAPID: &ngapIE.RANUENGAPID{Value: ue.RanUeNgapId},
		NASPDU:      &ngapIE.NASPDU{Value: nasPdu},
	}
	if ue.OldAmfName != "" {
		request.OldAMF = &ngapIE.AMFName{Value: ngapAper.PrintableString(ue.OldAmfName)}
		ue.OldAmfName = ""
	}
	if config := factory.AmfConfig.GetNgapIEMobilityRestrictionList(); config != nil &&
		config.Enable && ue.Ran.AnType == models.AccessType_3_GPP_ACCESS &&
		mobilityRestrictionList != nil {
		if ue.AmfUe == nil {
			return nil, fmt.Errorf("amfUe is nil")
		}
		request.MobilityRestrictionList = mobilityRestrictionList
	}
	return request.MarshalBinary()
}

func BuildUEContextReleaseCommand(
	ue *context.RanUe,
	causePresent int,
	cause ngapAper.Enumerated,
) ([]byte, error) {
	if ue == nil {
		return nil, fmt.Errorf("ranUe is nil")
	}
	ids := &ngapIE.UENGAPIDs{}
	if ue.RanUeNgapId == context.RanUeNgapIdUnspecified {
		ids.Choice = &ngapIE.AMFUENGAPID{Value: ue.AmfUeNgapId}
	} else {
		ids.Choice = &ngapIE.UENGAPIDPair{
			AMFUENGAPID: &ngapIE.AMFUENGAPID{Value: ue.AmfUeNgapId},
			RANUENGAPID: &ngapIE.RANUENGAPID{Value: ue.RanUeNgapId},
		}
	}
	ngapCause, err := newCause(causePresent, cause)
	if err != nil {
		return nil, err
	}
	return (&ngapMessage.UEContextReleaseCommand{UENGAPIDs: ids, Cause: ngapCause}).MarshalBinary()
}

func newCause(present int, value ngapAper.Enumerated) (*ngapIE.Cause, error) {
	switch present {
	case CauseChoiceRadioNetwork:
		return &ngapIE.Cause{Choice: &ngapIE.CauseRadioNetwork{Value: value}}, nil
	case CauseChoiceTransport:
		return &ngapIE.Cause{Choice: &ngapIE.CauseTransport{Value: value}}, nil
	case CauseChoiceNas:
		return &ngapIE.Cause{Choice: &ngapIE.CauseNas{Value: value}}, nil
	case CauseChoiceProtocol:
		return &ngapIE.Cause{Choice: &ngapIE.CauseProtocol{Value: value}}, nil
	case CauseChoiceMisc:
		return &ngapIE.Cause{Choice: &ngapIE.CauseMisc{Value: value}}, nil
	default:
		return nil, fmt.Errorf("unknown cause choice: %d", present)
	}
}

func BuildErrorIndication(
	amfUeNgapID, ranUeNgapID *int64,
	cause *ngapIE.Cause,
	criticalityDiagnostics *ngapIE.CriticalityDiagnostics,
) ([]byte, error) {
	if cause == nil && criticalityDiagnostics == nil {
		logger.NgapLog.Error("Error Indication shall contain Cause or Criticality Diagnostics")
	}
	request := &ngapMessage.ErrorIndication{
		Cause:                  cause,
		CriticalityDiagnostics: criticalityDiagnostics,
	}
	if amfUeNgapID != nil {
		request.AMFUENGAPID = &ngapIE.AMFUENGAPID{Value: *amfUeNgapID}
	}
	if ranUeNgapID != nil {
		request.RANUENGAPID = &ngapIE.RANUENGAPID{Value: *ranUeNgapID}
	}
	return request.MarshalBinary()
}

func BuildUERadioCapabilityCheckRequest(ue *context.RanUe) ([]byte, error) {
	if ue == nil {
		return nil, fmt.Errorf("ranUe is nil")
	}
	return (&ngapMessage.UERadioCapabilityCheckRequest{
		AMFUENGAPID: &ngapIE.AMFUENGAPID{Value: ue.AmfUeNgapId},
		RANUENGAPID: &ngapIE.RANUENGAPID{Value: ue.RanUeNgapId},
	}).MarshalBinary()
}

func BuildHandoverCancelAcknowledge(
	ue *context.RanUe,
	criticalityDiagnostics *ngapIE.CriticalityDiagnostics,
) ([]byte, error) {
	if ue == nil {
		return nil, fmt.Errorf("ranUe is nil")
	}
	return (&ngapMessage.HandoverCancelAcknowledge{
		AMFUENGAPID:            &ngapIE.AMFUENGAPID{Value: ue.AmfUeNgapId},
		RANUENGAPID:            &ngapIE.RANUENGAPID{Value: ue.RanUeNgapId},
		CriticalityDiagnostics: criticalityDiagnostics,
	}).MarshalBinary()
}

func BuildPDUSessionResourceSetupRequest(
	ue *context.RanUe,
	nasPdu []byte,
	setupList *ngapIE.PDUSessionResourceSetupListSUReq,
) ([]byte, error) {
	if ue == nil || ue.AmfUe == nil || ue.AmfUe.AccessAndMobilitySubscriptionData == nil {
		return nil, fmt.Errorf("ranUe or subscription data is nil")
	}
	if setupList == nil {
		return nil, fmt.Errorf("PDU session resource setup list is nil")
	}
	subscription := ue.AmfUe.AccessAndMobilitySubscriptionData
	if subscription.SubscribedUeAmbr == nil {
		return nil, fmt.Errorf("subscribed UE AMBR is nil")
	}
	request := &ngapMessage.PDUSessionResourceSetupRequest{
		AMFUENGAPID:                      &ngapIE.AMFUENGAPID{Value: ue.AmfUeNgapId},
		RANUENGAPID:                      &ngapIE.RANUENGAPID{Value: ue.RanUeNgapId},
		PDUSessionResourceSetupListSUReq: setupList,
		UEAggregateMaximumBitRate: newUEAggregateMaximumBitRate(
			subscription.SubscribedUeAmbr.Uplink,
			subscription.SubscribedUeAmbr.Downlink,
		),
	}
	if nasPdu != nil {
		request.NASPDU = &ngapIE.NASPDU{Value: nasPdu}
	}
	return request.MarshalBinary()
}

func BuildPDUSessionResourceModifyConfirm(
	ue *context.RanUe,
	modifyList ngapIE.PDUSessionResourceModifyListModCfm,
	failedList ngapIE.PDUSessionResourceFailedToModifyListModCfm,
	criticalityDiagnostics *ngapIE.CriticalityDiagnostics,
) ([]byte, error) {
	if ue == nil {
		return nil, fmt.Errorf("ranUe is nil")
	}
	response := &ngapMessage.PDUSessionResourceModifyConfirm{
		AMFUENGAPID:                        &ngapIE.AMFUENGAPID{Value: ue.AmfUeNgapId},
		RANUENGAPID:                        &ngapIE.RANUENGAPID{Value: ue.RanUeNgapId},
		PDUSessionResourceModifyListModCfm: &modifyList,
		CriticalityDiagnostics:             criticalityDiagnostics,
	}
	if len(failedList.List) != 0 {
		response.PDUSessionResourceFailedToModifyListModCfm = &failedList
	}
	return response.MarshalBinary()
}

func BuildPDUSessionResourceModifyRequest(
	ue *context.RanUe,
	modifyList ngapIE.PDUSessionResourceModifyListModReq,
) ([]byte, error) {
	if ue == nil {
		return nil, fmt.Errorf("ranUe is nil")
	}
	return (&ngapMessage.PDUSessionResourceModifyRequest{
		AMFUENGAPID:                        &ngapIE.AMFUENGAPID{Value: ue.AmfUeNgapId},
		RANUENGAPID:                        &ngapIE.RANUENGAPID{Value: ue.RanUeNgapId},
		PDUSessionResourceModifyListModReq: &modifyList,
	}).MarshalBinary()
}

func BuildInitialContextSetupRequest(
	amfUe *context.AmfUe,
	anType models.AccessType,
	nasPdu []byte,
	setupList *ngapIE.PDUSessionResourceSetupListCxtReq,
	rrcInactiveTransitionReportRequest *ngapIE.RRCInactiveTransitionReportRequest,
	coreNetworkAssistanceInfo *ngapIE.CoreNetworkAssistanceInformationForInactive,
	emergencyFallbackIndicator *ngapIE.EmergencyFallbackIndicator,
) ([]byte, error) {
	if amfUe == nil {
		return nil, fmt.Errorf("amfUe is nil")
	}
	ranUe := amfUe.GetRanUe(anType)
	if ranUe == nil {
		return nil, fmt.Errorf("ranUe for %s is nil", anType)
	}
	if setupList != nil && len(setupList.List) == 0 {
		setupList = nil
	}
	request := &ngapMessage.InitialContextSetupRequest{
		AMFUENGAPID: &ngapIE.AMFUENGAPID{Value: ranUe.AmfUeNgapId},
		RANUENGAPID: &ngapIE.RANUENGAPID{Value: ranUe.RanUeNgapId},
		CoreNetworkAssistanceInformationForInactive: coreNetworkAssistanceInfo,
		GUAMI:                              buildGUAMI(context.GetSelf().ServedGuamiList[0]),
		PDUSessionResourceSetupListCxtReq:  setupList,
		AllowedNSSAI:                       buildAllowedNSSAI(amfUe.AllowedNssai[anType]),
		UESecurityCapabilities:             buildUESecurityCapabilities(amfUe),
		SecurityKey:                        buildSecurityKey(amfUe, ranUe.Ran.AnType),
		EmergencyFallbackIndicator:         emergencyFallbackIndicator,
		RRCInactiveTransitionReportRequest: rrcInactiveTransitionReportRequest,
	}
	if ranUe.OldAmfName != "" {
		request.OldAMF = &ngapIE.AMFName{Value: ngapAper.PrintableString(ranUe.OldAmfName)}
		ranUe.OldAmfName = ""
	}
	if setupList != nil && len(setupList.List) != 0 {
		if amfUe.AccessAndMobilitySubscriptionData == nil ||
			amfUe.AccessAndMobilitySubscriptionData.SubscribedUeAmbr == nil {
			return nil, fmt.Errorf("subscribed UE AMBR is nil")
		}
		ambr := amfUe.AccessAndMobilitySubscriptionData.SubscribedUeAmbr
		request.UEAggregateMaximumBitRate = newUEAggregateMaximumBitRate(ambr.Uplink, ambr.Downlink)
	}
	if amfUe.TraceData != nil {
		trace := ngapConvert.TraceDataToNgap(*amfUe.TraceData, ranUe.Trsr)
		request.TraceActivation = &trace
	}
	if config := factory.AmfConfig.GetNgapIEMobilityRestrictionList(); config != nil &&
		config.Enable && anType == models.AccessType_3_GPP_ACCESS {
		restrictions := BuildIEMobilityRestrictionList(amfUe)
		request.MobilityRestrictionList = &restrictions
	}
	if amfUe.UeRadioCapability != "" {
		value, err := hex.DecodeString(amfUe.UeRadioCapability)
		if err != nil {
			return nil, fmt.Errorf("decode UE radio capability: %w", err)
		}
		request.UERadioCapability = &ngapIE.UERadioCapability{Value: value}
	}
	if amfUe.AmPolicyAssociation != nil && amfUe.AmPolicyAssociation.Rfsp != 0 {
		request.IndexToRFSP = &ngapIE.IndexToRFSP{Value: int64(amfUe.AmPolicyAssociation.Rfsp)}
	}
	request.MaskedIMEISV = buildMaskedIMEISV(amfUe)
	if nasPdu != nil {
		request.NASPDU = &ngapIE.NASPDU{Value: nasPdu}
	}
	request.UERadioCapabilityForPaging = buildUERadioCapabilityForPaging(amfUe)
	if config := factory.AmfConfig.GetNgapIERedirectionVoiceFallback(); config != nil && config.Enable {
		request.RedirectionVoiceFallback = &ngapIE.RedirectionVoiceFallback{
			Value: ngapIE.RedirectionVoiceFallbackPresentNotPossible,
		}
	}
	return request.MarshalBinary()
}

func BuildUEContextModificationRequest(
	amfUe *context.AmfUe,
	anType models.AccessType,
	oldAmfUeNgapID *int64,
	rrcInactiveTransitionReportRequest *ngapIE.RRCInactiveTransitionReportRequest,
	coreNetworkAssistanceInfo *ngapIE.CoreNetworkAssistanceInformationForInactive,
	_ *ngapIE.MobilityRestrictionList,
	emergencyFallbackIndicator *ngapIE.EmergencyFallbackIndicator,
) ([]byte, error) {
	if amfUe == nil {
		return nil, fmt.Errorf("amfUe is nil")
	}
	ranUe := amfUe.GetRanUe(anType)
	if ranUe == nil {
		return nil, fmt.Errorf("ranUe for %s is nil", anType)
	}
	amfID := ranUe.AmfUeNgapId
	if oldAmfUeNgapID != nil {
		amfID = *oldAmfUeNgapID
	}
	request := &ngapMessage.UEContextModificationRequest{
		AMFUENGAPID: &ngapIE.AMFUENGAPID{Value: amfID},
		RANUENGAPID: &ngapIE.RANUENGAPID{Value: ranUe.RanUeNgapId},
		CoreNetworkAssistanceInformationForInactive: coreNetworkAssistanceInfo,
		EmergencyFallbackIndicator:                  emergencyFallbackIndicator,
		RRCInactiveTransitionReportRequest:          rrcInactiveTransitionReportRequest,
	}
	if oldAmfUeNgapID != nil {
		request.NewAMFUENGAPID = &ngapIE.AMFUENGAPID{Value: ranUe.AmfUeNgapId}
	}
	if amfUe.AmPolicyAssociation != nil && amfUe.AmPolicyAssociation.Rfsp != 0 {
		request.IndexToRFSP = &ngapIE.IndexToRFSP{Value: int64(amfUe.AmPolicyAssociation.Rfsp)}
	}
	if subscription := amfUe.AccessAndMobilitySubscriptionData; subscription != nil &&
		subscription.SubscribedUeAmbr != nil {
		request.UEAggregateMaximumBitRate = newUEAggregateMaximumBitRate(
			subscription.SubscribedUeAmbr.Uplink,
			subscription.SubscribedUeAmbr.Downlink,
		)
	}
	return request.MarshalBinary()
}

func BuildHandoverCommand(
	sourceUe *context.RanUe,
	handoverList ngapIE.PDUSessionResourceHandoverList,
	releaseList ngapIE.PDUSessionResourceToReleaseListHOCmd,
	container ngapIE.TargetToSourceTransparentContainer,
	criticalityDiagnostics *ngapIE.CriticalityDiagnostics,
) ([]byte, error) {
	if sourceUe == nil {
		return nil, fmt.Errorf("source ranUe is nil")
	}
	response := &ngapMessage.HandoverCommand{
		AMFUENGAPID:                        &ngapIE.AMFUENGAPID{Value: sourceUe.AmfUeNgapId},
		RANUENGAPID:                        &ngapIE.RANUENGAPID{Value: sourceUe.RanUeNgapId},
		HandoverType:                       &ngapIE.HandoverType{Value: sourceUe.HandOverType.Value},
		PDUSessionResourceHandoverList:     &handoverList,
		TargetToSourceTransparentContainer: &container,
		CriticalityDiagnostics:             criticalityDiagnostics,
	}
	if sourceUe.HandOverType.Value == ngapIE.HandoverTypePresentFivegsToEps {
		response.NASSecurityParametersFromNGRAN = &ngapIE.NASSecurityParametersFromNGRAN{}
	}
	if len(releaseList.List) != 0 {
		response.PDUSessionResourceToReleaseListHOCmd = &releaseList
	}
	return response.MarshalBinary()
}

func BuildHandoverPreparationFailure(
	sourceUe *context.RanUe,
	cause ngapIE.Cause,
	criticalityDiagnostics *ngapIE.CriticalityDiagnostics,
) ([]byte, error) {
	if sourceUe == nil {
		return nil, fmt.Errorf("source ranUe is nil")
	}
	return (&ngapMessage.HandoverPreparationFailure{
		AMFUENGAPID:            &ngapIE.AMFUENGAPID{Value: sourceUe.AmfUeNgapId},
		RANUENGAPID:            &ngapIE.RANUENGAPID{Value: sourceUe.RanUeNgapId},
		Cause:                  &cause,
		CriticalityDiagnostics: criticalityDiagnostics,
	}).MarshalBinary()
}

func BuildHandoverRequest(
	ue *context.RanUe,
	cause ngapIE.Cause,
	setupList ngapIE.PDUSessionResourceSetupListHOReq,
	sourceToTargetContainer ngapIE.SourceToTargetTransparentContainer,
	newSecurityContext bool,
) ([]byte, error) {
	if ue == nil || ue.AmfUe == nil {
		return nil, fmt.Errorf("ranUe or amfUe is nil")
	}
	amfUe := ue.AmfUe
	if amfUe.AccessAndMobilitySubscriptionData == nil ||
		amfUe.AccessAndMobilitySubscriptionData.SubscribedUeAmbr == nil {
		return nil, fmt.Errorf("subscribed UE AMBR is nil")
	}
	ambr := amfUe.AccessAndMobilitySubscriptionData.SubscribedUeAmbr
	request := &ngapMessage.HandoverRequest{
		AMFUENGAPID:                        &ngapIE.AMFUENGAPID{Value: ue.AmfUeNgapId},
		HandoverType:                       &ngapIE.HandoverType{Value: ue.HandOverType.Value},
		Cause:                              &cause,
		UEAggregateMaximumBitRate:          newUEAggregateMaximumBitRate(ambr.Uplink, ambr.Downlink),
		UESecurityCapabilities:             buildUESecurityCapabilities(amfUe),
		SecurityContext:                    buildSecurityContext(amfUe),
		PDUSessionResourceSetupListHOReq:   &setupList,
		AllowedNSSAI:                       buildAllowedNSSAIFromModels(context.GetSelf().PlmnSupportList[0].SNssaiList),
		MaskedIMEISV:                       buildMaskedIMEISV(amfUe),
		SourceToTargetTransparentContainer: &sourceToTargetContainer,
		GUAMI:                              buildGUAMI(context.GetSelf().ServedGuamiList[0]),
	}
	if config := factory.AmfConfig.GetNgapIEMobilityRestrictionList(); config != nil && config.Enable {
		restrictions := BuildIEMobilityRestrictionList(amfUe)
		request.MobilityRestrictionList = &restrictions
	}
	if newSecurityContext {
		request.NewSecurityContextInd = &ngapIE.NewSecurityContextInd{
			Value: ngapIE.NewSecurityContextIndPresentTrue,
		}
	}
	if config := factory.AmfConfig.GetNgapIERedirectionVoiceFallback(); config != nil && config.Enable {
		request.RedirectionVoiceFallback = &ngapIE.RedirectionVoiceFallback{
			Value: ngapIE.RedirectionVoiceFallbackPresentNotPossible,
		}
	}
	return request.MarshalBinary()
}

func BuildPathSwitchRequestAcknowledge(
	ue *context.RanUe,
	switchedList ngapIE.PDUSessionResourceSwitchedList,
	releasedList ngapIE.PDUSessionResourceReleasedListPSAck,
	newSecurityContext bool,
	coreNetworkAssistanceInformation *ngapIE.CoreNetworkAssistanceInformationForInactive,
	rrcInactiveTransitionReportRequest *ngapIE.RRCInactiveTransitionReportRequest,
	criticalityDiagnostics *ngapIE.CriticalityDiagnostics,
) ([]byte, error) {
	if ue == nil || ue.AmfUe == nil {
		return nil, fmt.Errorf("ranUe or amfUe is nil")
	}
	response := &ngapMessage.PathSwitchRequestAcknowledge{
		AMFUENGAPID:                    &ngapIE.AMFUENGAPID{Value: ue.AmfUeNgapId},
		RANUENGAPID:                    &ngapIE.RANUENGAPID{Value: ue.RanUeNgapId},
		UESecurityCapabilities:         buildUESecurityCapabilities(ue.AmfUe),
		SecurityContext:                buildSecurityContext(ue.AmfUe),
		PDUSessionResourceSwitchedList: &switchedList,
		AllowedNSSAI:                   buildAllowedNSSAIFromModels(context.GetSelf().PlmnSupportList[0].SNssaiList),
		CoreNetworkAssistanceInformationForInactive: coreNetworkAssistanceInformation,
		RRCInactiveTransitionReportRequest:          rrcInactiveTransitionReportRequest,
		CriticalityDiagnostics:                      criticalityDiagnostics,
	}
	if len(releasedList.List) != 0 {
		response.PDUSessionResourceReleasedListPSAck = &releasedList
	}
	if newSecurityContext {
		response.NewSecurityContextInd = &ngapIE.NewSecurityContextInd{
			Value: ngapIE.NewSecurityContextIndPresentTrue,
		}
	}
	if config := factory.AmfConfig.GetNgapIERedirectionVoiceFallback(); config != nil && config.Enable {
		response.RedirectionVoiceFallback = &ngapIE.RedirectionVoiceFallback{
			Value: ngapIE.RedirectionVoiceFallbackPresentNotPossible,
		}
	}
	return response.MarshalBinary()
}

func BuildPathSwitchRequestFailure(
	amfUeNgapID, ranUeNgapID int64,
	releasedList *ngapIE.PDUSessionResourceReleasedListPSFail,
	criticalityDiagnostics *ngapIE.CriticalityDiagnostics,
) ([]byte, error) {
	if releasedList == nil {
		return nil, fmt.Errorf("PDU session resource released list is nil")
	}
	return (&ngapMessage.PathSwitchRequestFailure{
		AMFUENGAPID:                          &ngapIE.AMFUENGAPID{Value: amfUeNgapID},
		RANUENGAPID:                          &ngapIE.RANUENGAPID{Value: ranUeNgapID},
		PDUSessionResourceReleasedListPSFail: releasedList,
		CriticalityDiagnostics:               criticalityDiagnostics,
	}).MarshalBinary()
}

func BuildDownlinkRanStatusTransfer(
	ue *context.RanUe,
	container ngapIE.RANStatusTransferTransparentContainer,
) ([]byte, error) {
	if ue == nil {
		return nil, fmt.Errorf("ranUe is nil")
	}
	return (&ngapMessage.DownlinkRANStatusTransfer{
		AMFUENGAPID:                           &ngapIE.AMFUENGAPID{Value: ue.AmfUeNgapId},
		RANUENGAPID:                           &ngapIE.RANUENGAPID{Value: ue.RanUeNgapId},
		RANStatusTransferTransparentContainer: &container,
	}).MarshalBinary()
}

func BuildPaging(
	ue *context.AmfUe,
	pagingPriority *ngapIE.PagingPriority,
	pagingOriginNon3GPP bool,
) ([]byte, error) {
	if ue == nil {
		return nil, fmt.Errorf("amfUe is nil")
	}
	amfID, tmsi, err := splitGUTI(ue.Guti)
	if err != nil {
		return nil, err
	}
	_, setID, pointer := ngapConvert.AmfIdToNgap(amfID)
	tmsiBytes, err := hex.DecodeString(tmsi)
	if err != nil {
		return nil, fmt.Errorf("decode 5G-TMSI: %w", err)
	}
	paging := &ngapMessage.Paging{
		UEPagingIdentity: &ngapIE.UEPagingIdentity{Choice: &ngapIE.FiveGSTMSI{
			AMFSetID:   &ngapIE.AMFSetID{Value: setID},
			AMFPointer: &ngapIE.AMFPointer{Value: pointer},
			FiveGTMSI:  &ngapIE.FiveGTMSI{Value: tmsiBytes},
		}},
		TAIListForPaging: &ngapIE.TAIListForPaging{},
		PagingPriority:   pagingPriority,
	}
	registrationArea := ue.RegistrationArea[models.AccessType_3_GPP_ACCESS]
	if len(registrationArea) == 0 {
		return nil, fmt.Errorf("registration area of UE[%s] is empty", ue.Supi)
	}
	for _, tai := range registrationArea {
		if tai.PlmnId == nil {
			continue
		}
		plmn := ngapConvert.PlmnIdToNgap(*tai.PlmnId)
		tac, decodeErr := hex.DecodeString(tai.Tac)
		if decodeErr != nil {
			return nil, fmt.Errorf("decode TAI TAC: %w", decodeErr)
		}
		paging.TAIListForPaging.List = append(paging.TAIListForPaging.List, ngapIE.TAIListForPagingItem{
			TAI: &ngapIE.TAI{PLMNIdentity: &plmn, TAC: &ngapIE.TAC{Value: tac}},
		})
	}
	paging.UERadioCapabilityForPaging = buildUERadioCapabilityForPaging(ue)
	paging.AssistanceDataForPaging = buildAssistanceDataForPaging(ue)
	if pagingOriginNon3GPP {
		paging.PagingOrigin = &ngapIE.PagingOrigin{Value: ngapIE.PagingOriginPresentNon3gpp}
	}
	return paging.MarshalBinary()
}

func BuildRerouteNasRequest(
	ue *context.AmfUe,
	anType models.AccessType,
	amfUeNgapID *int64,
	encodedNGAPMessage []byte,
	allowedNSSAI *ngapIE.AllowedNSSAI,
) ([]byte, error) {
	if ue == nil || ue.GetRanUe(anType) == nil {
		return nil, fmt.Errorf("amfUe or ranUe for %s is nil", anType)
	}
	amfID, _, err := splitGUTI(ue.Guti)
	if err != nil {
		return nil, err
	}
	_, setID, _ := ngapConvert.AmfIdToNgap(amfID)
	messageValue := ngapAper.OctetString(encodedNGAPMessage)
	request := &ngapMessage.RerouteNASRequest{
		RANUENGAPID:  &ngapIE.RANUENGAPID{Value: ue.GetRanUe(anType).RanUeNgapId},
		NGAPMessage:  &messageValue,
		AMFSetID:     &ngapIE.AMFSetID{Value: setID},
		AllowedNSSAI: allowedNSSAI,
	}
	if amfUeNgapID != nil {
		request.AMFUENGAPID = &ngapIE.AMFUENGAPID{Value: *amfUeNgapID}
	}
	return request.MarshalBinary()
}

func BuildRanConfigurationUpdateAcknowledge(
	criticalityDiagnostics *ngapIE.CriticalityDiagnostics,
) ([]byte, error) {
	return (&ngapMessage.RANConfigurationUpdateAcknowledge{
		CriticalityDiagnostics: criticalityDiagnostics,
	}).MarshalBinary()
}

func BuildRanConfigurationUpdateFailure(
	cause ngapIE.Cause,
	criticalityDiagnostics *ngapIE.CriticalityDiagnostics,
) ([]byte, error) {
	return (&ngapMessage.RANConfigurationUpdateFailure{
		Cause:                  &cause,
		TimeToWait:             &ngapIE.TimeToWait{Value: ngapIE.TimeToWaitPresentV1s},
		CriticalityDiagnostics: criticalityDiagnostics,
	}).MarshalBinary()
}

func BuildAMFStatusIndication(unavailableGUAMIList ngapIE.UnavailableGUAMIList) ([]byte, error) {
	logger.NgapLog.Trace("Build AMF Status Indication message")
	return (&ngapMessage.AMFStatusIndication{
		UnavailableGUAMIList: &unavailableGUAMIList,
	}).MarshalBinary()
}

func BuildOverloadStart(
	amfOverloadResponse *ngapIE.OverloadResponse,
	amfTrafficLoadReductionIndication int64,
	overloadStartNSSAIList *ngapIE.OverloadStartNSSAIList,
) ([]byte, error) {
	request := &ngapMessage.OverloadStart{
		AMFOverloadResponse:    amfOverloadResponse,
		OverloadStartNSSAIList: overloadStartNSSAIList,
	}
	if amfTrafficLoadReductionIndication != 0 {
		request.AMFTrafficLoadReductionIndication = &ngapIE.TrafficLoadReductionIndication{
			Value: amfTrafficLoadReductionIndication,
		}
	}
	return request.MarshalBinary()
}

func BuildOverloadStop() ([]byte, error) {
	return (&ngapMessage.OverloadStop{}).MarshalBinary()
}

func BuildDownlinkRanConfigurationTransfer(
	transfer *ngapIE.SONConfigurationTransfer,
) ([]byte, error) {
	return (&ngapMessage.DownlinkRANConfigurationTransfer{
		SONConfigurationTransferDL: transfer,
	}).MarshalBinary()
}

func BuildDownlinkNonUEAssociatedNRPPATransport(
	ue *context.RanUe,
	nrppaPDU ngapIE.NRPPaPDU,
) ([]byte, error) {
	if ue == nil {
		return nil, fmt.Errorf("ranUe is nil")
	}
	routingID, err := hex.DecodeString(ue.RoutingID)
	if err != nil {
		return nil, fmt.Errorf("decode routing ID: %w", err)
	}
	return (&ngapMessage.DownlinkNonUEAssociatedNRPPaTransport{
		RoutingID: &ngapIE.RoutingID{Value: routingID},
		NRPPaPDU:  &nrppaPDU,
	}).MarshalBinary()
}

func BuildTraceStart() ([]byte, error) {
	return nil, fmt.Errorf("BuildTraceStart is not implemented")
}

func BuildDeactivateTrace(amfUe *context.AmfUe, anType models.AccessType) ([]byte, error) {
	if amfUe == nil || amfUe.GetRanUe(anType) == nil {
		return nil, fmt.Errorf("amfUe or ranUe for %s is nil", anType)
	}
	ranUe := amfUe.GetRanUe(anType)
	if amfUe.TraceData == nil {
		return nil, fmt.Errorf("trace data is nil")
	}
	trace := ngapConvert.TraceDataToNgap(*amfUe.TraceData, ranUe.Trsr)
	if trace.NGRANTraceID == nil {
		return nil, fmt.Errorf("invalid trace data")
	}
	return (&ngapMessage.DeactivateTrace{
		AMFUENGAPID:  &ngapIE.AMFUENGAPID{Value: ranUe.AmfUeNgapId},
		RANUENGAPID:  &ngapIE.RANUENGAPID{Value: ranUe.RanUeNgapId},
		NGRANTraceID: trace.NGRANTraceID,
	}).MarshalBinary()
}

func BuildLocationReportingControl(
	ue *context.RanUe,
	aoiList *ngapIE.AreaOfInterestList,
	locationReportingReferenceIDToBeCancelled int64,
	eventType ngapIE.EventType,
) ([]byte, error) {
	if ue == nil {
		return nil, fmt.Errorf("ranUe is nil")
	}
	requestType := &ngapIE.LocationReportingRequestType{
		EventType:  &eventType,
		ReportArea: &ngapIE.ReportArea{Value: ngapIE.ReportAreaPresentCell},
	}
	if aoiList != nil {
		requestType.AreaOfInterestList = aoiList
	}
	if eventType.Value == ngapIE.EventTypePresentStopUePresenceInAreaOfInterest {
		requestType.LocationReportingReferenceIDToBeCancelled = &ngapIE.LocationReportingReferenceID{
			Value: locationReportingReferenceIDToBeCancelled,
		}
	}
	return (&ngapMessage.LocationReportingControl{
		AMFUENGAPID:                  &ngapIE.AMFUENGAPID{Value: ue.AmfUeNgapId},
		RANUENGAPID:                  &ngapIE.RANUENGAPID{Value: ue.RanUeNgapId},
		LocationReportingRequestType: requestType,
	}).MarshalBinary()
}

func BuildUETNLABindingReleaseRequest(ue *context.RanUe) ([]byte, error) {
	if ue == nil {
		return nil, fmt.Errorf("ranUe is nil")
	}
	return (&ngapMessage.UETNLABindingReleaseRequest{
		AMFUENGAPID: &ngapIE.AMFUENGAPID{Value: ue.AmfUeNgapId},
		RANUENGAPID: &ngapIE.RANUENGAPID{Value: ue.RanUeNgapId},
	}).MarshalBinary()
}

func BuildAMFConfigurationUpdate(
	tnlAssociationUsage ngapIE.TNLAssociationUsage,
	tnlAddressWeightFactor ngapIE.TNLAddressWeightFactor,
) ([]byte, error) {
	amfSelf := context.GetSelf()
	address := ngapConvert.IPAddressToNgap(amfSelf.RegisterIPv4, amfSelf.HttpIPv6Address)
	transport := &ngapIE.CPTransportLayerInformation{Choice: &address}
	return (&ngapMessage.AMFConfigurationUpdate{
		AMFName:             &ngapIE.AMFName{Value: ngapAper.PrintableString(amfSelf.Name)},
		ServedGUAMIList:     buildServedGUAMIList(amfSelf.ServedGuamiList),
		RelativeAMFCapacity: &ngapIE.RelativeAMFCapacity{Value: amfSelf.RelativeCapacity},
		PLMNSupportList:     buildPLMNSupportList(amfSelf.PlmnSupportList),
		AMFTNLAssociationToAddList: &ngapIE.AMFTNLAssociationToAddList{
			List: []ngapIE.AMFTNLAssociationToAddItem{{
				AMFTNLAssociationAddress: transport,
				TNLAssociationUsage:      &tnlAssociationUsage,
				TNLAddressWeightFactor:   &tnlAddressWeightFactor,
			}},
		},
		AMFTNLAssociationToRemoveList: &ngapIE.AMFTNLAssociationToRemoveList{
			List: []ngapIE.AMFTNLAssociationToRemoveItem{{
				AMFTNLAssociationAddress: transport,
			}},
		},
		AMFTNLAssociationToUpdateList: &ngapIE.AMFTNLAssociationToUpdateList{
			List: []ngapIE.AMFTNLAssociationToUpdateItem{{
				AMFTNLAssociationAddress: transport,
				TNLAssociationUsage:      &tnlAssociationUsage,
				TNLAddressWeightFactor:   &tnlAddressWeightFactor,
			}},
		},
	}).MarshalBinary()
}

func BuildDownlinkUEAssociatedNRPPaTransport(
	ue *context.RanUe,
	nrppaPDU ngapIE.NRPPaPDU,
) ([]byte, error) {
	if ue == nil {
		return nil, fmt.Errorf("ranUe is nil")
	}
	routingID, err := hex.DecodeString(ue.RoutingID)
	if err != nil {
		return nil, fmt.Errorf("decode routing ID: %w", err)
	}
	return (&ngapMessage.DownlinkUEAssociatedNRPPaTransport{
		AMFUENGAPID: &ngapIE.AMFUENGAPID{Value: ue.AmfUeNgapId},
		RANUENGAPID: &ngapIE.RANUENGAPID{Value: ue.RanUeNgapId},
		RoutingID:   &ngapIE.RoutingID{Value: routingID},
		NRPPaPDU:    &nrppaPDU,
	}).MarshalBinary()
}

func newUEAggregateMaximumBitRate(uplink, downlink string) *ngapIE.UEAggregateMaximumBitRate {
	return &ngapIE.UEAggregateMaximumBitRate{
		UEAggregateMaximumBitRateUL: &ngapIE.BitRate{Value: ngapConvert.UEAmbrToInt64(uplink)},
		UEAggregateMaximumBitRateDL: &ngapIE.BitRate{Value: ngapConvert.UEAmbrToInt64(downlink)},
	}
}

func buildGUAMI(guami models.Guami) *ngapIE.GUAMI {
	plmn := ngapConvert.PlmnIdToNgap(util.PlmnIdNidToModelsPlmnId(*guami.PlmnId))
	region, set, pointer := ngapConvert.AmfIdToNgap(guami.AmfId)
	return &ngapIE.GUAMI{
		PLMNIdentity: &plmn,
		AMFRegionID:  &ngapIE.AMFRegionID{Value: region},
		AMFSetID:     &ngapIE.AMFSetID{Value: set},
		AMFPointer:   &ngapIE.AMFPointer{Value: pointer},
	}
}

func buildServedGUAMIList(values []models.Guami) *ngapIE.ServedGUAMIList {
	result := &ngapIE.ServedGUAMIList{}
	for _, value := range values {
		result.List = append(result.List, ngapIE.ServedGUAMIItem{GUAMI: buildGUAMI(value)})
	}
	return result
}

func buildPLMNSupportList(values []factory.PlmnSupportItem) *ngapIE.PLMNSupportList {
	result := &ngapIE.PLMNSupportList{}
	for _, value := range values {
		if value.PlmnId == nil {
			continue
		}
		plmn := ngapConvert.PlmnIdToNgap(*value.PlmnId)
		item := ngapIE.PLMNSupportItem{
			PLMNIdentity:     &plmn,
			SliceSupportList: &ngapIE.SliceSupportList{},
		}
		for _, modelSNSSAI := range value.SNssaiList {
			snssai := ngapConvert.SNssaiToNgap(modelSNSSAI)
			item.SliceSupportList.List = append(item.SliceSupportList.List, ngapIE.SliceSupportItem{
				SNSSAI: &snssai,
			})
		}
		result.List = append(result.List, item)
	}
	return result
}

func buildAllowedNSSAI(values []models.Nssf_NSSel_AllowedSnssai) *ngapIE.AllowedNSSAI {
	result := ngapConvert.AllowedNssaiToNgap(values)
	return &result
}

func buildAllowedNSSAIFromModels(values []models.Snssai) *ngapIE.AllowedNSSAI {
	result := &ngapIE.AllowedNSSAI{}
	for _, value := range values {
		snssai := ngapConvert.SNssaiToNgap(value)
		result.List = append(result.List, ngapIE.AllowedNSSAIItem{SNSSAI: &snssai})
	}
	return result
}

func buildUESecurityCapabilities(amfUe *context.AmfUe) *ngapIE.UESecurityCapabilities {
	nrEncryption := []byte{0, 0}
	if amfUe.UESecurityCapability.EA1_128_5G {
		nrEncryption[0] |= 1 << 7
	}
	if amfUe.UESecurityCapability.EA2_128_5G {
		nrEncryption[0] |= 1 << 6
	}
	if amfUe.UESecurityCapability.EA3_128_5G {
		nrEncryption[0] |= 1 << 5
	}
	nrIntegrity := []byte{0, 0}
	if amfUe.UESecurityCapability.IA1_128_5G {
		nrIntegrity[0] |= 1 << 7
	}
	if amfUe.UESecurityCapability.IA2_128_5G {
		nrIntegrity[0] |= 1 << 6
	}
	if amfUe.UESecurityCapability.IA3_128_5G {
		nrIntegrity[0] |= 1 << 5
	}
	return &ngapIE.UESecurityCapabilities{
		NRencryptionAlgorithms: &ngapIE.NRencryptionAlgorithms{
			Value: ngapConvert.ByteToBitString(nrEncryption, 16),
		},
		NRintegrityProtectionAlgorithms: &ngapIE.NRintegrityProtectionAlgorithms{
			Value: ngapConvert.ByteToBitString(nrIntegrity, 16),
		},
		EUTRAencryptionAlgorithms: &ngapIE.EUTRAencryptionAlgorithms{
			Value: ngapConvert.ByteToBitString([]byte{0, 0}, 16),
		},
		EUTRAintegrityProtectionAlgorithms: &ngapIE.EUTRAintegrityProtectionAlgorithms{
			Value: ngapConvert.ByteToBitString([]byte{0, 0}, 16),
		},
	}
}

func buildSecurityKey(amfUe *context.AmfUe, anType models.AccessType) *ngapIE.SecurityKey {
	key := amfUe.Kgnb
	if anType == models.AccessType_NON_3_GPP_ACCESS {
		key = amfUe.Kn3iwf
	}
	return &ngapIE.SecurityKey{Value: ngapConvert.ByteToBitString(key, 256)}
}

func buildSecurityContext(amfUe *context.AmfUe) *ngapIE.SecurityContext {
	return &ngapIE.SecurityContext{
		NextHopChainingCount: &ngapIE.NextHopChainingCount{Value: int64(amfUe.NCC)},
		NextHopNH: &ngapIE.SecurityKey{
			Value: ngapConvert.ByteToBitString(amfUe.NH, 256),
		},
	}
}

func buildMaskedIMEISV(amfUe *context.AmfUe) *ngapIE.MaskedIMEISV {
	config := factory.AmfConfig.GetNgapIEMaskedIMEISV()
	if config == nil || !config.Enable || !strings.HasPrefix(amfUe.Pei, "imeisv-") {
		return nil
	}
	imei, err := hex.DecodeString(strings.TrimPrefix(amfUe.Pei, "imeisv-"))
	if err != nil || len(imei) < 8 {
		logger.NgapLog.Errorf("Decode IMEISV failed: %v", err)
		return nil
	}
	masked := append([]byte{}, imei[:5]...)
	masked = append(masked, 0xff, 0xff, imei[7])
	return &ngapIE.MaskedIMEISV{
		Value: ngapAper.BitString{Bytes: masked, BitLength: 64},
	}
}

func buildUERadioCapabilityForPaging(amfUe *context.AmfUe) *ngapIE.UERadioCapabilityForPaging {
	if amfUe.UeRadioCapabilityForPaging == nil {
		return nil
	}
	result := &ngapIE.UERadioCapabilityForPaging{}
	if value, err := hex.DecodeString(amfUe.UeRadioCapabilityForPaging.NR); err == nil &&
		len(value) != 0 {
		result.UERadioCapabilityForPagingOfNR = &ngapIE.UERadioCapabilityForPagingOfNR{Value: value}
	}
	if value, err := hex.DecodeString(amfUe.UeRadioCapabilityForPaging.EUTRA); err == nil &&
		len(value) != 0 {
		result.UERadioCapabilityForPagingOfEUTRA = &ngapIE.UERadioCapabilityForPagingOfEUTRA{Value: value}
	}
	return result
}

func buildAssistanceDataForPaging(amfUe *context.AmfUe) *ngapIE.AssistanceDataForPaging {
	info := amfUe.InfoOnRecommendedCellsAndRanNodesForPaging
	if info == nil {
		return nil
	}
	list := &ngapIE.RecommendedCellList{}
	for _, recommended := range info.RecommendedCells {
		item := ngapIE.RecommendedCellItem{
			NGRANCGI:         &ngapIE.NGRANCGI{},
			TimeStayedInCell: recommended.TimeStayedInCell,
		}
		switch recommended.NgRanCGI.Present {
		case context.NgRanCgiPresentNRCGI:
			if recommended.NgRanCGI.NRCGI == nil || recommended.NgRanCGI.NRCGI.PlmnId == nil {
				continue
			}
			plmn := ngapConvert.PlmnIdToNgap(*recommended.NgRanCGI.NRCGI.PlmnId)
			item.NGRANCGI.Choice = &ngapIE.NRCGI{
				PLMNIdentity: &plmn,
				NRCellIdentity: &ngapIE.NRCellIdentity{
					Value: ngapConvert.HexToBitString(recommended.NgRanCGI.NRCGI.NrCellId, 36),
				},
			}
		case context.NgRanCgiPresentEUTRACGI:
			if recommended.NgRanCGI.EUTRACGI == nil || recommended.NgRanCGI.EUTRACGI.PlmnId == nil {
				continue
			}
			plmn := ngapConvert.PlmnIdToNgap(*recommended.NgRanCGI.EUTRACGI.PlmnId)
			item.NGRANCGI.Choice = &ngapIE.EUTRACGI{
				PLMNIdentity: &plmn,
				EUTRACellIdentity: &ngapIE.EUTRACellIdentity{
					Value: ngapConvert.HexToBitString(recommended.NgRanCGI.EUTRACGI.EutraCellId, 28),
				},
			}
		default:
			continue
		}
		list.List = append(list.List, item)
	}
	return &ngapIE.AssistanceDataForPaging{
		AssistanceDataForRecommendedCells: &ngapIE.AssistanceDataForRecommendedCells{
			RecommendedCellsForPaging: &ngapIE.RecommendedCellsForPaging{
				RecommendedCellList: list,
			},
		},
	}
}

func splitGUTI(guti string) (string, string, error) {
	switch len(guti) {
	case 19:
		return guti[5:11], guti[11:], nil
	case 20:
		return guti[6:12], guti[12:], nil
	default:
		return "", "", fmt.Errorf("invalid GUTI length: %d", len(guti))
	}
}
