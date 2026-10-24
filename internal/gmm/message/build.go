package message

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/amf/internal/nas/nas_security"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	nas_message "github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

const protectedAndCiphered = nas_message.SecHdrTypeIntegrityProtectedAndCiphered

func secCtxType(value models.Amf_Comm_ScType) ie.SecCtxType {
	if value == models.Amf_Comm_ScType_MAPPED {
		return ie.SecCtxTypeMapped
	}
	return ie.SecCtxTypeNative
}

func BuildDLNASTransport(
	ue *context.AmfUe,
	accessType models.AccessType,
	payloadContainerType uint8,
	nasPdu []byte,
	pduSessionID uint8,
	cause *uint8,
	backoffTimerUnit *uint8,
	backoffTimer uint8,
) ([]byte, error) {
	msg := &nas_message.DLNASTransport{
		PayloadCntrType: &ie.PayloadCntrType{Value: payloadContainerType},
		PayloadCntr: &ie.PayloadCntr{
			Pct:      payloadContainerType,
			Contents: nasPdu,
		},
	}
	if pduSessionID != 0 {
		msg.PDUSessID = &ie.PDUSessId2{Value: pduSessionID}
	}
	if cause != nil {
		msg.Cause5GMM = &ie.Cause5GMM{Value: *cause}
	}
	if backoffTimerUnit != nil {
		msg.BackoffTimerValue = &ie.GPRSTimer3{
			Unit:  ie.GPRSTimer3UnitType(*backoffTimerUnit),
			Value: backoffTimer,
		}
	}
	return nas_security.Encode(ue, msg, accessType, protectedAndCiphered)
}

func BuildNotification(ue *context.AmfUe, accessType models.AccessType) ([]byte, error) {
	nasAccessType := ie.AccessType_Non3gpp
	if accessType == models.AccessType_3_GPP_ACCESS {
		nasAccessType = ie.AccessType_3gpp
	}
	msg := &nas_message.Notif{AccessType: &ie.AccessType{Value: nasAccessType}}
	return nas_security.Encode(ue, msg, accessType, protectedAndCiphered)
}

func BuildIdentityRequest(
	ue *context.AmfUe,
	accessType models.AccessType,
	typeOfIdentity uint8,
) ([]byte, error) {
	msg := &nas_message.IdReq{IdType: &ie.IdType5GS{IdType: typeOfIdentity}}
	securityHeaderType := nas_message.SecHdrTypePlainNas
	if ue != nil && ue.SecurityContextAvailable {
		securityHeaderType = protectedAndCiphered
	}
	return nas_security.Encode(ue, msg, accessType, securityHeaderType)
}

func BuildAuthenticationRequest(ue *context.AmfUe, accessType models.AccessType) ([]byte, error) {
	msg := &nas_message.AuthReq{
		Ngksi: &ie.NASKeySetId{
			Tsc: secCtxType(ue.NgKsi.Tsc),
			Ksi: uint8(ue.NgKsi.Ksi),
		},
		ABBA: &ie.ABBA{Abba: ue.ABBA},
	}

	switch ue.AuthenticationCtx.AuthType {
	case models.Ausf_UEAU_AuthType_5_G_AKA:
		var av5gAka models.Ausf_UEAU_Av5gAka
		if err := mapstructure.Decode(ue.AuthenticationCtx.Var5gAuthData, &av5gAka); err != nil {
			logger.GmmLog.Error("Var5gAuthData Convert Type Error")
			return nil, err
		}
		rand, err := hex.DecodeString(av5gAka.Rand)
		if err != nil {
			return nil, err
		}
		autn, err := hex.DecodeString(av5gAka.Autn)
		if err != nil {
			return nil, err
		}
		msg.AuthParamRAND5GAuthChlg = &ie.AuthParamRAND{Rand: rand}
		msg.AuthParamAUTN5GAuthChlg = &ie.AuthParamAUTN{Autn: autn}
	case models.Ausf_UEAU_AuthType_EAP_AKA_PRIME:
		eapMessage, ok := ue.AuthenticationCtx.Var5gAuthData.(string)
		if !ok {
			return nil, fmt.Errorf("EAP-AKA' authentication data has type %T", ue.AuthenticationCtx.Var5gAuthData)
		}
		rawEAPMessage, err := base64.StdEncoding.DecodeString(eapMessage)
		if err != nil {
			return nil, err
		}
		msg.EAPMsg = &ie.EAPMsg{Eap: rawEAPMessage}
	}

	return nas_security.Encode(ue, msg, accessType, protectedAndCiphered)
}

func BuildServiceAccept(
	ue *context.AmfUe,
	accessType models.AccessType,
	pduSessionStatus *[16]bool,
	reactivationResult *[16]bool,
	errPduSessionID, errCause []uint8,
) ([]byte, error) {
	msg := &nas_message.SvcAccept{}
	if pduSessionStatus != nil {
		msg.PDUSessStatus = &ie.PDUSessStatus{Psi: ie.Psi{PSI: *pduSessionStatus}}
	}
	if reactivationResult != nil {
		msg.PDUSessReactivationResult = &ie.PDUSessReactivationResult{Psi: ie.Psi{PSI: *reactivationResult}}
	}
	msg.PDUSessReactivationResultErrCause = pduSessionErrorCauses(errPduSessionID, errCause)
	return nas_security.Encode(ue, msg, accessType, protectedAndCiphered)
}

func BuildAuthenticationReject(
	ue *context.AmfUe,
	accessType models.AccessType,
	eapMsg string,
) ([]byte, error) {
	msg := &nas_message.AuthRej{}
	if eapMsg != "" {
		rawEAPMessage, err := base64.StdEncoding.DecodeString(eapMsg)
		if err != nil {
			return nil, err
		}
		msg.EAPMsg = &ie.EAPMsg{Eap: rawEAPMessage}
	}
	return nas_security.Encode(ue, msg, accessType, protectedAndCiphered)
}

func BuildAuthenticationResult(
	ue *context.AmfUe,
	accessType models.AccessType,
	eapSuccess bool,
	eapMsg string,
) ([]byte, error) {
	rawEAPMessage, err := base64.StdEncoding.DecodeString(eapMsg)
	if err != nil {
		return nil, err
	}
	msg := &nas_message.AuthResult{
		Ngksi: &ie.NASKeySetId{
			Tsc: secCtxType(ue.NgKsi.Tsc),
			Ksi: uint8(ue.NgKsi.Ksi),
		},
		EAPMsg: &ie.EAPMsg{Eap: rawEAPMessage},
	}
	if eapSuccess {
		msg.ABBA = &ie.ABBA{Abba: ue.ABBA}
	}
	return nas_security.Encode(ue, msg, accessType, protectedAndCiphered)
}

// T3346 timer and EAP are not supported.
func BuildServiceReject(
	ue *context.AmfUe,
	accessType models.AccessType,
	pduSessionStatus *[16]bool,
	cause uint8,
) ([]byte, error) {
	msg := &nas_message.SvcRej{Cause5GMM: &ie.Cause5GMM{Value: cause}}
	if pduSessionStatus != nil {
		msg.PDUSessStatus = &ie.PDUSessStatus{Psi: ie.Psi{PSI: *pduSessionStatus}}
	}
	return nas_security.Encode(ue, msg, accessType, protectedAndCiphered)
}

// T3346 timer is not supported.
func BuildRegistrationReject(
	ue *context.AmfUe,
	accessType models.AccessType,
	cause5GMM uint8,
	eapMessage string,
) ([]byte, error) {
	msg := &nas_message.RegRej{Cause5GMM: &ie.Cause5GMM{Value: cause5GMM}}
	t3502Value := context.GetSelf().T3502Value
	if ue != nil {
		t3502Value = ue.T3502Value
	}
	if t3502Value != 0 {
		msg.T3502Value = new(ie.GPRSTimer2)
		msg.T3502Value.Set(uint32(t3502Value))
	}
	if eapMessage != "" {
		rawEAPMessage, err := base64.StdEncoding.DecodeString(eapMessage)
		if err != nil {
			return nil, err
		}
		msg.EAPMsg = &ie.EAPMsg{Eap: rawEAPMessage}
	}

	securityHeaderType := nas_message.SecHdrTypePlainNas
	if ue != nil && ue.SecurityContextAvailable {
		securityHeaderType = protectedAndCiphered
	}
	return nas_security.Encode(ue, msg, accessType, securityHeaderType)
}

// BuildSecurityModeCommand implements TS 24.501 section 8.2.25.
func BuildSecurityModeCommand(
	ue *context.AmfUe,
	accessType models.AccessType,
	eapSuccess bool,
	eapMessage string,
) ([]byte, error) {
	msg := &nas_message.SecModeCmd{
		SelectedNASSecAlgos: &ie.NASSecAlgos{
			CipheringAlgo: ie.AlgCiphering(ue.CipheringAlg),
			MsgIntAlgo:    ie.AlgIntegrity(ue.IntegrityAlg),
		},
		Ngksi: &ie.NASKeySetId{
			Tsc: secCtxType(ue.NgKsi.Tsc),
			Ksi: uint8(ue.NgKsi.Ksi),
		},
		ReplayedUESecCapabilities: &ue.UESecurityCapability,
		IMEISVReq: &ie.IMEISVReq{
			Value: ie.IMEISV_Requested,
		},
		Additional5GSecInfo: &ie.Additional5GSecInfo{
			RINMR: ue.RetransmissionOfInitialNASMsg,
			HDP: ue.RegistrationType5GS == ie.RegType_MobilityRegUpdating ||
				ue.RegistrationType5GS == ie.RegType_PeriodicRegUpdating,
		},
	}
	if ue.Pei != "" {
		msg.IMEISVReq.Value = ie.IMEISV_NotRequested
	}
	if eapMessage != "" {
		rawEAPMessage, err := base64.StdEncoding.DecodeString(eapMessage)
		if err != nil {
			return nil, err
		}
		msg.EAPMsg = &ie.EAPMsg{Eap: rawEAPMessage}
		if eapSuccess {
			msg.ABBA = &ie.ABBA{Abba: ue.ABBA}
		}
	}

	ue.SecurityContextAvailable = true
	payload, err := nas_security.Encode(
		ue,
		msg,
		accessType,
		nas_message.SecHdrTypeIntegrityProtectedWithNew5gNasSecCtx,
	)
	if err != nil {
		ue.SecurityContextAvailable = false
		return nil, err
	}
	return payload, nil
}

// T3346 timer is not supported.
func BuildDeregistrationRequest(
	ue *context.RanUe,
	accessType uint8,
	reRegistrationRequired bool,
	cause5GMM uint8,
) ([]byte, error) {
	msg := &nas_message.DeregReqUETerm{
		DeregType: &ie.DeregType{
			AccessType:    accessType,
			ReregRequired: reRegistrationRequired,
		},
	}
	if cause5GMM != 0 {
		msg.Cause5GMM = &ie.Cause5GMM{Value: cause5GMM}
	}

	anType := models.AccessType_3_GPP_ACCESS
	if accessType == ie.AccessType_Non3gpp {
		anType = models.AccessType_NON_3_GPP_ACCESS
	}
	if ue.Ran != nil {
		anType = ue.Ran.AnType
	}
	amfUe := ue.GetAmfUe()
	if amfUe != nil {
		return nas_security.Encode(amfUe, msg, anType, protectedAndCiphered)
	}
	return nas_security.Encode(nil, msg, anType, nas_message.SecHdrTypePlainNas)
}

func BuildDeregistrationAccept(
	ue *context.AmfUe,
	accessType models.AccessType,
) ([]byte, error) {
	return nas_security.Encode(
		ue,
		&nas_message.DeregAcceptUEOrig{},
		accessType,
		protectedAndCiphered,
	)
}

func BuildRegistrationAccept(
	ue *context.AmfUe,
	accessType models.AccessType,
	pduSessionStatus *[16]bool,
	reactivationResult *[16]bool,
	errPduSessionID, errCause []uint8,
) ([]byte, error) {
	msg := &nas_message.RegAccept{RegResult5GS: &ie.RegResult5GS{}}
	if accessType == models.AccessType_3_GPP_ACCESS {
		msg.RegResult5GS.Value = ie.RegResult_3gpp
		if ue.State[models.AccessType_NON_3_GPP_ACCESS].Is(context.Registered) {
			msg.RegResult5GS.Value = ie.RegResult_3gppAndNon3gpp
		}
	} else {
		msg.RegResult5GS.Value = ie.RegResult_Non3gpp
		if ue.State[models.AccessType_3_GPP_ACCESS].Is(context.Registered) {
			msg.RegResult5GS.Value = ie.RegResult_3gppAndNon3gpp
		}
	}

	if ue.Guti != "" {
		msg.GUTI5G = new(ie.MobileId5GS)
		if err := msg.GUTI5G.FromGUTIStr(ue.Guti); err != nil {
			return nil, fmt.Errorf("encode GUTI failed: %w", err)
		}
	}

	amfSelf := context.GetSelf()
	if len(amfSelf.PlmnSupportList) > 1 {
		msg.EquivalentPlmns = &ie.PLMNList{}
		for _, item := range amfSelf.PlmnSupportList {
			msg.EquivalentPlmns.PlmnIds = append(
				msg.EquivalentPlmns.PlmnIds,
				ie.PlmnId{MCC: item.PlmnId.Mcc, MNC: item.PlmnId.Mnc},
			)
		}
	}
	if len(ue.RegistrationArea[accessType]) > 0 {
		msg.TAIList = trackingAreaList(ue.RegistrationArea[accessType])
	}
	if len(ue.AllowedNssai[accessType]) > 0 {
		msg.AllowedNSSAI = &ie.NSSAI{}
		for _, allowed := range ue.AllowedNssai[accessType] {
			msg.AllowedNSSAI.SNSSAIs = append(msg.AllowedNSSAI.SNSSAIs, snssai(*allowed.AllowedSnssai))
		}
	}
	msg.RejectedNSSAI = rejectedNSSAI(ue)
	if includeConfiguredNssaiCheck(ue) {
		msg.ConfiguredNSSAI = configuredNSSAI(ue)
	}

	if cfg := factory.AmfConfig.GetNasIENetworkFeatureSupport5GS(); cfg != nil && cfg.Enable {
		msg.NwFeatureSupport5GS = &ie.NwFeatureSupport5GS{
			Length: cfg.Length,
			EMC:    cfg.Emc,
			EMF:    cfg.Emf,
			IWKN26: cfg.IwkN26 == 1,
			MPSI:   cfg.Mpsi == 1,
			EMCN3:  cfg.EmcN3 == 1,
			MCSI:   cfg.Mcsi == 1,
		}
		if accessType == models.AccessType_3_GPP_ACCESS {
			msg.NwFeatureSupport5GS.IMSVoPS3GPP = cfg.ImsVoPS == 1
		} else {
			msg.NwFeatureSupport5GS.IMSVoPSN3GPP = cfg.ImsVoPS == 1
		}
	}
	if pduSessionStatus != nil {
		msg.PDUSessStatus = &ie.PDUSessStatus{Psi: ie.Psi{PSI: *pduSessionStatus}}
	}
	if reactivationResult != nil {
		msg.PDUSessReactivationResult = &ie.PDUSessReactivationResult{Psi: ie.Psi{PSI: *reactivationResult}}
	}
	msg.PDUSessReactivationResultErrCause = pduSessionErrorCauses(errPduSessionID, errCause)
	msg.LADNInfo = ladnInformation(ue)

	if ue.NetworkSlicingSubscriptionChanged {
		msg.NwSlicingInd = &ie.NwSlicingInd{NSSCI: true}
		ue.NetworkSlicingSubscriptionChanged = false
	}
	if accessType == models.AccessType_3_GPP_ACCESS &&
		ue.AmPolicyAssociation != nil &&
		ue.AmPolicyAssociation.ServAreaRes != nil {
		msg.SvcAreaList = serviceAreaList(ue.PlmnId, *ue.AmPolicyAssociation.ServAreaRes)
	}
	if accessType == models.AccessType_3_GPP_ACCESS && ue.T3512Value != 0 {
		msg.T3512Value = new(ie.GPRSTimer3)
		msg.T3512Value.Set(uint32(ue.T3512Value))
	}
	if accessType == models.AccessType_NON_3_GPP_ACCESS {
		msg.Non3GppDeregTimerValue = new(ie.GPRSTimer2)
		msg.Non3GppDeregTimerValue.Set(uint32(ue.Non3gppDeregTimerValue))
	}
	if ue.T3502Value != 0 {
		msg.T3502Value = new(ie.GPRSTimer2)
		msg.T3502Value.Set(uint32(ue.T3502Value))
	}
	if ie.DRXValue(ue.UESpecificDRX) != ie.DRXValueNotSpecified {
		msg.NegotiatedDRXParams = &ie.DRXParams5GS{Value: ie.DRXValue(ue.UESpecificDRX)}
	}
	return nas_security.Encode(ue, msg, accessType, protectedAndCiphered)
}

func includeConfiguredNssaiCheck(ue *context.AmfUe) bool {
	if len(ue.ConfiguredNssai) == 0 {
		return false
	}
	registrationRequest := ue.RegistrationRequest
	if registrationRequest == nil || registrationRequest.ReqNSSAI == nil {
		return true
	}
	if ue.NetworkSliceInfo != nil && len(ue.NetworkSliceInfo.RejectedNssaiInPlmn) != 0 {
		return true
	}
	return registrationRequest.NwSlicingInd != nil && registrationRequest.NwSlicingInd.DCNI
}

func BuildStatus5GMM(
	ue *context.AmfUe,
	accessType models.AccessType,
	cause uint8,
) ([]byte, error) {
	msg := &nas_message.Status5GMM{Cause5GMM: &ie.Cause5GMM{Value: cause}}
	return nas_security.Encode(ue, msg, accessType, protectedAndCiphered)
}

// BuildConfigurationUpdateCommand implements TS 24.501 section 5.4.4.
func BuildConfigurationUpdateCommand(
	ue *context.AmfUe,
	accessType models.AccessType,
	flags *context.ConfigurationUpdateCommandFlags,
) ([]byte, error, bool) {
	msg := &nas_message.CfgUpdateCmd{}
	needTimer := false

	if flags.NeedNetworkSlicingIndication {
		msg.NwSlicingInd = &ie.NwSlicingInd{NSSCI: true}
	}
	if flags.NeedGUTI {
		if ue.Guti == "" {
			logger.GmmLog.Warn("Require 5G-GUTI, but got nothing.")
		} else {
			msg.GUTI5G = new(ie.MobileId5GS)
			if err := msg.GUTI5G.FromGUTIStr(ue.Guti); err != nil {
				return nil, fmt.Errorf("encode GUTI failed: %w", err), false
			}
		}
	}
	if flags.NeedAllowedNSSAI {
		if len(ue.AllowedNssai[accessType]) == 0 {
			logger.GmmLog.Warn("Require Allowed NSSAI, but got nothing.")
		} else {
			msg.AllowedNSSAI = &ie.NSSAI{}
			for _, allowed := range ue.AllowedNssai[accessType] {
				msg.AllowedNSSAI.SNSSAIs = append(msg.AllowedNSSAI.SNSSAIs, snssai(*allowed.AllowedSnssai))
			}
		}
	}
	if flags.NeedConfiguredNSSAI {
		if len(ue.ConfiguredNssai) == 0 {
			logger.GmmLog.Warn("Require Configured NSSAI, but got nothing.")
		} else {
			msg.ConfiguredNSSAI = configuredNSSAI(ue)
		}
	}
	if flags.NeedRejectNSSAI {
		msg.RejectedNSSAI = rejectedNSSAI(ue)
		if msg.RejectedNSSAI == nil {
			logger.GmmLog.Warn("Require Rejected NSSAI, but got nothing.")
		}
	}
	if flags.NeedTaiList && accessType == models.AccessType_3_GPP_ACCESS {
		if len(ue.RegistrationArea[accessType]) == 0 {
			logger.GmmLog.Warn("Require TAI List, but got nothing.")
		} else {
			msg.TAIList = trackingAreaList(ue.RegistrationArea[accessType])
		}
	}
	if flags.NeedServiceAreaList && accessType == models.AccessType_3_GPP_ACCESS {
		if ue.AmPolicyAssociation == nil || ue.AmPolicyAssociation.ServAreaRes == nil {
			logger.GmmLog.Warn("Require Service Area List, but got nothing.")
		} else {
			msg.SvcAreaList = serviceAreaList(ue.PlmnId, *ue.AmPolicyAssociation.ServAreaRes)
		}
	}
	if flags.NeedLadnInformation && accessType == models.AccessType_3_GPP_ACCESS {
		msg.LADNInfo = ladnInformation(ue)
		if msg.LADNInfo == nil {
			logger.GmmLog.Warn("Require LADN Information, but got nothing.")
		}
	}

	amfSelf := context.GetSelf()
	if flags.NeedNITZ {
		if amfSelf.NetworkName.Full != "" {
			msg.FullNameForNw = &ie.NwName{
				Ext:        1,
				CodeScheme: ie.CodeScheme_Default,
				TextStr:    amfSelf.NetworkName.Full,
			}
		} else {
			logger.GmmLog.Warn("Require Full Network Name, but got nothing.")
		}
		if amfSelf.NetworkName.Short != "" {
			msg.ShortNameForNw = &ie.NwName{
				Ext:        1,
				CodeScheme: ie.CodeScheme_Default,
				TextStr:    amfSelf.NetworkName.Short,
			}
		} else {
			logger.GmmLog.Warn("Require Short Network Name, but got nothing.")
		}
		now := time.Now()
		msg.UniversalTimeAndLocalTimeZone = &ie.TimeZoneAndTime{Time: now}
		if ue.TimeZone != amfSelf.TimeZone {
			ue.TimeZone = amfSelf.TimeZone
			msg.LocalTimeZone = &ie.TimeZone{Value: ue.TimeZone}
			switch {
			case strings.HasSuffix(ue.TimeZone, "+1"):
				msg.NwDST = &ie.DST{Value: uint8(ie.HourAdjustment_1)}
			case strings.HasSuffix(ue.TimeZone, "+2"):
				msg.NwDST = &ie.DST{Value: uint8(ie.HourAdjustment_2)}
			default:
				msg.NwDST = &ie.DST{Value: uint8(ie.NoAdjustment)}
			}
		}
	}

	hasAckParameter := msg.GUTI5G != nil ||
		msg.TAIList != nil ||
		msg.AllowedNSSAI != nil ||
		msg.LADNInfo != nil ||
		msg.SvcAreaList != nil ||
		msg.MICOInd != nil ||
		msg.ConfiguredNSSAI != nil ||
		msg.RejectedNSSAI != nil ||
		msg.NwSlicingInd != nil ||
		msg.OperatorDefinedAccessCategoryDefs != nil ||
		msg.SMSInd != nil
	if hasAckParameter {
		msg.CfgUpdateInd = &ie.CfgUpdateInd{ACK: true}
		needTimer = true
	}
	if msg.MICOInd != nil {
		if msg.CfgUpdateInd == nil {
			msg.CfgUpdateInd = new(ie.CfgUpdateInd)
		}
		msg.CfgUpdateInd.RED = true
	}

	if msg.CfgUpdateInd == nil &&
		msg.FullNameForNw == nil &&
		msg.ShortNameForNw == nil &&
		msg.UniversalTimeAndLocalTimeZone == nil &&
		msg.LocalTimeZone == nil &&
		msg.NwDST == nil {
		return nil, fmt.Errorf("configuration update command is invalid"), false
	}

	payload, err := nas_security.Encode(ue, msg, accessType, protectedAndCiphered)
	if err != nil {
		return nil, fmt.Errorf("BuildConfigurationUpdateCommand: %w", err), false
	}
	return payload, nil, needTimer
}

func pduSessionErrorCauses(ids, causes []uint8) *ie.PDUSessReactivationResultErrCause {
	if len(ids) == 0 {
		return nil
	}
	result := &ie.PDUSessReactivationResultErrCause{}
	for index, id := range ids {
		if index >= len(causes) {
			break
		}
		result.IdCause = append(result.IdCause, ie.SessIdCausePair{
			PDUSessID: id,
			Value:     causes[index],
		})
	}
	return result
}

func trackingAreaList(tais []models.Tai) *ie.TrackingAreaIdList5GS {
	result := &ie.TrackingAreaIdList5GS{}
	for _, tai := range tais {
		if tai.PlmnId == nil {
			continue
		}
		result.TAI = append(result.TAI, ie.TrackingAreaId5GS{
			PlmnId: ie.PlmnId{MCC: tai.PlmnId.Mcc, MNC: tai.PlmnId.Mnc},
			TAC:    tai.Tac,
		})
	}
	return result
}

func snssai(value models.Snssai) ie.SNSSAI {
	return ie.SNSSAI{SST: uint8(value.Sst), SD: value.Sd}
}

func configuredNSSAI(ue *context.AmfUe) *ie.NSSAI {
	result := &ie.NSSAI{}
	for _, configured := range ue.ConfiguredNssai {
		if configured.ConfiguredSnssai != nil {
			result.SNSSAIs = append(result.SNSSAIs, snssai(*configured.ConfiguredSnssai))
		}
	}
	return result
}

func rejectedNSSAI(ue *context.AmfUe) *ie.RejectedNSSAI {
	if ue.NetworkSliceInfo == nil ||
		(len(ue.NetworkSliceInfo.RejectedNssaiInPlmn) == 0 &&
			len(ue.NetworkSliceInfo.RejectedNssaiInTa) == 0) {
		return nil
	}
	result := &ie.RejectedNSSAI{}
	for _, value := range ue.NetworkSliceInfo.RejectedNssaiInPlmn {
		result.Append(ie.SNSSAIRej_NotAvailInCurrPLMN, uint8(value.Sst), value.Sd)
	}
	for _, value := range ue.NetworkSliceInfo.RejectedNssaiInTa {
		result.Append(ie.SNSSAIRej_NotAvailInCurrRegArea, uint8(value.Sst), value.Sd)
	}
	return result
}

func serviceAreaList(plmnID models.PlmnId, restriction models.ServiceAreaRestriction) *ie.SvcAreaList {
	result := &ie.SvcAreaList{}
	target := &result.DeniedList
	if restriction.RestrictionType == models.RestrictionType_ALLOWED_AREAS {
		target = &result.AllowedList
	}
	for _, area := range restriction.Areas {
		for _, tac := range area.Tacs {
			target.TAI = append(target.TAI, ie.TrackingAreaId5GS{
				PlmnId: ie.PlmnId{MCC: plmnID.Mcc, MNC: plmnID.Mnc},
				TAC:    tac,
			})
		}
	}
	return result
}

func ladnInformation(ue *context.AmfUe) *ie.LADNInfo {
	if len(ue.LadnInfo) == 0 {
		return nil
	}
	result := &ie.LADNInfo{}
	for _, ladn := range ue.LadnInfo {
		result.DnnTai = append(result.DnnTai, ie.DNN_TAI{
			DNN:                   ie.DNN{Value: ladn.Dnn},
			TrackingAreaIdList5GS: *trackingAreaList(ladn.TaiList),
		})
	}
	return result
}
