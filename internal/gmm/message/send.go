package message

import (
	"github.com/free5gc/amf/internal/context"
	gmm_common "github.com/free5gc/amf/internal/gmm/common"
	"github.com/free5gc/amf/internal/logger"
	ngap_message "github.com/free5gc/amf/internal/ngap/message"
	"github.com/free5gc/amf/internal/sbi/producer/callback"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/openapi/models"
)

// backOffTimerUint = 7 means backoffTimer is null
func SendDLNASTransport(ue *context.RanUe, payloadContainerType uint8, nasPdu []byte,
	pduSessionId int32, cause uint8, backOffTimerUint *uint8, backOffTimer uint8) {
	if ue == nil {
		logger.GmmLog.Error("SendDLNASTransport: RanUe is nil")
		return
	}
	if ue.AmfUe == nil {
		logger.GmmLog.Error("SendDLNASTransport: AmfUe is nil")
		return
	}
	amfUe := ue.AmfUe
	amfUe.GmmLog.Info("Send DL NAS Transport")

	var causePtr *uint8
	if cause != 0 {
		causePtr = &cause
	}
	nasMsg, err := BuildDLNASTransport(amfUe, ue.Ran.AnType, payloadContainerType, nasPdu,
		uint8(pduSessionId), causePtr, backOffTimerUint, backOffTimer)
	if err != nil {
		amfUe.GmmLog.Error(err.Error())
		return
	}
	ngap_message.SendDownlinkNasTransport(ue, nasMsg, nil)
}

func SendNotification(ue *context.RanUe, nasMsg []byte) {
	if ue == nil {
		logger.GmmLog.Error("SendNotification: RanUe is nil")
		return
	}
	if ue.AmfUe == nil {
		logger.GmmLog.Error("SendNotification: AmfUe is nil")
		return
	}
	amfUe := ue.AmfUe
	amfUe.GmmLog.Info("Send Notification")

	if context.AMF_Self().T3565Cfg.Enable {
		cfg := context.AMF_Self().T3565Cfg
		amfUe.T3565 = context.NewTimer(cfg.ExpireTime, cfg.MaxRetryTimes, func(expireTimes int32) {
			amfUe.GmmLog.Warnf("T3565 expires, retransmit Notification (retry: %d)", expireTimes)
			ngap_message.SendDownlinkNasTransport(ue, nasMsg, nil)
		}, func() {
			amfUe.GmmLog.Warnf("T3565 Expires %d times, abort notification procedure", cfg.MaxRetryTimes)
			if amfUe.OnGoing(models.AccessType__3_GPP_ACCESS).Procedure != context.OnGoingProcedureN2Handover {
				callback.SendN1N2TransferFailureNotification(amfUe, models.N1N2MessageTransferCause_UE_NOT_RESPONDING)
			}
			amfUe.T3565 = nil // clear the timer
		})
	}
}

func SendIdentityRequest(ue *context.RanUe, accessType models.AccessType, typeOfIdentity uint8) {
	if ue == nil {
		logger.GmmLog.Error("SendIdentityRequest: RanUe is nil")
		return
	}
	if ue.AmfUe == nil {
		logger.GmmLog.Error("SendIdentityRequest: AmfUe is nil")
		return
	}
	amfUe := ue.AmfUe
	amfUe.GmmLog.Info("Send Identity Request")

	nasMsg, err := BuildIdentityRequest(amfUe, accessType, typeOfIdentity)
	if err != nil {
		amfUe.GmmLog.Error(err.Error())
		return
	}
	ngap_message.SendDownlinkNasTransport(ue, nasMsg, nil)

	amfUe.RequestIdentityType = typeOfIdentity

	if context.AMF_Self().T3570Cfg.Enable {
		cfg := context.AMF_Self().T3570Cfg
		amfUe.T3570 = context.NewTimer(cfg.ExpireTime, cfg.MaxRetryTimes, func(expireTimes int32) {
			amfUe.GmmLog.Warnf("T3570 expires, retransmit Identity Request (retry: %d)", expireTimes)
			ngap_message.SendDownlinkNasTransport(ue, nasMsg, nil)
		}, func() {
			amfUe.GmmLog.Warnf("T3570 Expires %d times, abort identification procedure & ongoing 5GMM procedure",
				cfg.MaxRetryTimes)
			gmm_common.RemoveAmfUe(amfUe)
		})
	}
}

func SendAuthenticationRequest(ue *context.RanUe) {
	if ue == nil {
		logger.GmmLog.Error("SendAuthenticationRequest: RanUe is nil")
		return
	}
	if ue.AmfUe == nil {
		logger.GmmLog.Error("SendAuthenticationRequest: AmfUe is nil")
		return
	}
	amfUe := ue.AmfUe
	amfUe.GmmLog.Infof("Send Authentication Request")

	if amfUe.AuthenticationCtx == nil {
		amfUe.GmmLog.Error("Authentication Context of UE is nil")
		return
	}

	nasMsg, err := BuildAuthenticationRequest(amfUe)
	if err != nil {
		amfUe.GmmLog.Error(err.Error())
		return
	}
	ngap_message.SendDownlinkNasTransport(ue, nasMsg, nil)

	if context.AMF_Self().T3560Cfg.Enable {
		cfg := context.AMF_Self().T3560Cfg
		amfUe.T3560 = context.NewTimer(cfg.ExpireTime, cfg.MaxRetryTimes, func(expireTimes int32) {
			amfUe.GmmLog.Warnf("T3560 expires, retransmit Authentication Request (retry: %d)", expireTimes)
			ngap_message.SendDownlinkNasTransport(ue, nasMsg, nil)
		}, func() {
			amfUe.GmmLog.Warnf("T3560 Expires %d times, abort authentication procedure & ongoing 5GMM procedure",
				cfg.MaxRetryTimes)
			gmm_common.RemoveAmfUe(amfUe)
		})
	}
}

func SendServiceAccept(ue *context.RanUe, anType models.AccessType, pDUSessionStatus *[16]bool,
	reactivationResult *[16]bool, errPduSessionId, errCause []uint8) {
	if ue == nil {
		logger.GmmLog.Error("SendServiceAccept: RanUe is nil")
		return
	}
	if ue.AmfUe == nil {
		logger.GmmLog.Error("SendServiceAccept: AmfUe is nil")
		return
	}
	amfUe := ue.AmfUe
	amfUe.GmmLog.Info("Send Service Accept")

	nasMsg, err := BuildServiceAccept(amfUe, anType, pDUSessionStatus, reactivationResult,
		errPduSessionId, errCause)
	if err != nil {
		amfUe.GmmLog.Error(err.Error())
		return
	}
	ngap_message.SendDownlinkNasTransport(ue, nasMsg, nil)
}

func SendConfigurationUpdateCommand(amfUe *context.AmfUe, accessType models.AccessType,
	networkSlicingIndication *nasType.NetworkSlicingIndication) {
	if amfUe == nil {
		logger.GmmLog.Error("SendConfigurationUpdateCommand: AmfUe is nil")
		return
	}
	if amfUe.RanUe[accessType] == nil {
		logger.GmmLog.Error("SendConfigurationUpdateCommand: RanUe is nil")
		return
	}
	amfUe.GmmLog.Info("Configuration Update Command")

	nasMsg, err := BuildConfigurationUpdateCommand(amfUe, accessType, networkSlicingIndication)
	if err != nil {
		amfUe.GmmLog.Error(err.Error())
		return
	}
	mobilityRestrictionList := ngap_message.BuildIEMobilityRestrictionList(amfUe)
	ngap_message.SendDownlinkNasTransport(amfUe.RanUe[accessType], nasMsg, &mobilityRestrictionList)
}

func SendAuthenticationReject(ue *context.RanUe, eapMsg string) {
	if ue == nil {
		logger.GmmLog.Error("SendAuthenticationReject: RanUe is nil")
		return
	}
	if ue.AmfUe == nil {
		logger.GmmLog.Error("SendAuthenticationReject: AmfUe is nil")
		return
	}
	amfUe := ue.AmfUe
	amfUe.GmmLog.Info("Send Authentication Reject")

	nasMsg, err := BuildAuthenticationReject(amfUe, eapMsg)
	if err != nil {
		amfUe.GmmLog.Error(err.Error())
		return
	}
	ngap_message.SendDownlinkNasTransport(ue, nasMsg, nil)
}

func SendAuthenticationResult(ue *context.RanUe, eapSuccess bool, eapMsg string) {
	if ue == nil {
		logger.GmmLog.Error("SendAuthenticationResult: RanUe is nil")
		return
	}
	if ue.AmfUe == nil {
		logger.GmmLog.Error("SendAuthenticationResult: AmfUe is nil")
		return
	}
	amfUe := ue.AmfUe
	amfUe.GmmLog.Info("Send Authentication Result")

	nasMsg, err := BuildAuthenticationResult(amfUe, eapSuccess, eapMsg)
	if err != nil {
		amfUe.GmmLog.Error(err.Error())
		return
	}
	ngap_message.SendDownlinkNasTransport(ue, nasMsg, nil)
}

func SendServiceReject(ue *context.RanUe, pDUSessionStatus *[16]bool, cause uint8) {
	if ue == nil {
		logger.GmmLog.Error("SendServiceReject: RanUe is nil")
		return
	}
	if ue.AmfUe == nil {
		logger.GmmLog.Error("SendServiceReject: AmfUe is nil")
		return
	}
	amfUe := ue.AmfUe
	amfUe.GmmLog.Info("Send Service Reject")

	nasMsg, err := BuildServiceReject(pDUSessionStatus, cause)
	if err != nil {
		amfUe.GmmLog.Error(err.Error())
		return
	}
	ngap_message.SendDownlinkNasTransport(ue, nasMsg, nil)
}

// T3502: This IE may be included to indicate a value for timer T3502 during the initial registration
// eapMessage: if the REGISTRATION REJECT message is used to convey EAP-failure message
func SendRegistrationReject(ue *context.RanUe, cause5GMM uint8, eapMessage string) {
	if ue == nil {
		logger.GmmLog.Error("SendRegistrationReject: RanUe is nil")
		return
	}
	if ue.AmfUe == nil {
		logger.GmmLog.Error("SendRegistrationReject: AmfUe is nil")
		return
	}
	amfUe := ue.AmfUe
	amfUe.GmmLog.Info("Send Registration Reject")

	nasMsg, err := BuildRegistrationReject(amfUe, cause5GMM, eapMessage)
	if err != nil {
		amfUe.GmmLog.Error(err.Error())
		return
	}
	ngap_message.SendDownlinkNasTransport(ue, nasMsg, nil)
}

// eapSuccess: only used when authType is EAP-AKA', set the value to false if authType is not EAP-AKA'
// eapMessage: only used when authType is EAP-AKA', set the value to "" if authType is not EAP-AKA'
func SendSecurityModeCommand(ue *context.RanUe, accessType models.AccessType, eapSuccess bool, eapMessage string) {
	if ue == nil {
		logger.GmmLog.Error("SendSecurityModeCommand: RanUe is nil")
		return
	}
	if ue.AmfUe == nil {
		logger.GmmLog.Error("SendSecurityModeCommand: AmfUe is nil")
		return
	}
	amfUe := ue.AmfUe
	amfUe.GmmLog.Info("Send Security Mode Command")

	nasMsg, err := BuildSecurityModeCommand(amfUe, accessType, eapSuccess, eapMessage)
	if err != nil {
		amfUe.GmmLog.Error(err.Error())
		return
	}
	ngap_message.SendDownlinkNasTransport(ue, nasMsg, nil)

	if context.AMF_Self().T3560Cfg.Enable {
		cfg := context.AMF_Self().T3560Cfg
		amfUe.T3560 = context.NewTimer(cfg.ExpireTime, cfg.MaxRetryTimes, func(expireTimes int32) {
			amfUe.GmmLog.Warnf("T3560 expires, retransmit Security Mode Command (retry: %d)", expireTimes)
			ngap_message.SendDownlinkNasTransport(ue, nasMsg, nil)
		}, func() {
			amfUe.GmmLog.Warnf("T3560 Expires %d times, abort security mode control procedure", cfg.MaxRetryTimes)
			gmm_common.RemoveAmfUe(amfUe)
		})
	}
}

func SendDeregistrationRequest(ue *context.RanUe, accessType uint8, reRegistrationRequired bool, cause5GMM uint8) {
	if ue == nil {
		logger.GmmLog.Error("SendDeregistrationRequest: RanUe is nil")
		return
	}
	if ue.AmfUe == nil {
		logger.GmmLog.Error("SendDeregistrationRequest: AmfUe is nil")
		return
	}
	amfUe := ue.AmfUe
	amfUe.GmmLog.Info("Send Deregistration Request")

	nasMsg, err := BuildDeregistrationRequest(ue, accessType, reRegistrationRequired, cause5GMM)
	if err != nil {
		amfUe.GmmLog.Error(err.Error())
		return
	}
	ngap_message.SendDownlinkNasTransport(ue, nasMsg, nil)

	if context.AMF_Self().T3522Cfg.Enable {
		cfg := context.AMF_Self().T3522Cfg
		amfUe.T3522 = context.NewTimer(cfg.ExpireTime, cfg.MaxRetryTimes, func(expireTimes int32) {
			amfUe.GmmLog.Warnf("T3522 expires, retransmit Deregistration Request (retry: %d)", expireTimes)
			ngap_message.SendDownlinkNasTransport(ue, nasMsg, nil)
		}, func() {
			amfUe.GmmLog.Warnf("T3522 Expires %d times, abort deregistration procedure", cfg.MaxRetryTimes)
			amfUe.T3522 = nil // clear the timer
			if accessType == nasMessage.AccessType3GPP {
				amfUe.GmmLog.Warnln("UE accessType[3GPP] transfer to Deregistered state")
				amfUe.State[models.AccessType__3_GPP_ACCESS].Set(context.Deregistered)
			} else if accessType == nasMessage.AccessTypeNon3GPP {
				amfUe.GmmLog.Warnln("UE accessType[Non3GPP] transfer to Deregistered state")
				amfUe.State[models.AccessType_NON_3_GPP_ACCESS].Set(context.Deregistered)
			} else {
				amfUe.GmmLog.Warnln("UE accessType[3GPP] transfer to Deregistered state")
				amfUe.State[models.AccessType__3_GPP_ACCESS].Set(context.Deregistered)
				amfUe.GmmLog.Warnln("UE accessType[Non3GPP] transfer to Deregistered state")
				amfUe.State[models.AccessType_NON_3_GPP_ACCESS].Set(context.Deregistered)
			}
		})
	}
}

func SendDeregistrationAccept(ue *context.RanUe) {
	if ue == nil {
		logger.GmmLog.Error("SendDeregistrationAccept: RanUe is nil")
		return
	}
	if ue.AmfUe == nil {
		logger.GmmLog.Error("SendDeregistrationAccept: AmfUe is nil")
		return
	}
	amfUe := ue.AmfUe
	amfUe.GmmLog.Info("Send Deregistration Accept")

	nasMsg, err := BuildDeregistrationAccept()
	if err != nil {
		amfUe.GmmLog.Error(err.Error())
		return
	}
	ngap_message.SendDownlinkNasTransport(ue, nasMsg, nil)
}

func SendRegistrationAccept(
	amfUe *context.AmfUe,
	anType models.AccessType,
	pDUSessionStatus *[16]bool,
	reactivationResult *[16]bool,
	errPduSessionId, errCause []uint8,
	pduSessionResourceSetupList *ngapType.PDUSessionResourceSetupListCxtReq) {
	if amfUe == nil {
		logger.GmmLog.Error("SendRegistrationAccept: AmfUe is nil")
		return
	}
	if amfUe.RanUe[anType] == nil {
		logger.GmmLog.Error("SendRegistrationAccept: RanUe is nil")
		return
	}
	amfUe.GmmLog.Info("Send Registration Accept")

	nasMsg, err := BuildRegistrationAccept(amfUe, anType, pDUSessionStatus, reactivationResult, errPduSessionId, errCause)
	if err != nil {
		amfUe.GmmLog.Error(err.Error())
		return
	}

	if amfUe.RanUe[anType].UeContextRequest {
		ngap_message.SendInitialContextSetupRequest(amfUe, anType, nasMsg, pduSessionResourceSetupList, nil, nil, nil)
	} else {
		ngap_message.SendDownlinkNasTransport(amfUe.RanUe[models.AccessType__3_GPP_ACCESS], nasMsg, nil)
	}

	if context.AMF_Self().T3550Cfg.Enable {
		cfg := context.AMF_Self().T3550Cfg
		amfUe.T3550 = context.NewTimer(cfg.ExpireTime, cfg.MaxRetryTimes, func(expireTimes int32) {
			if amfUe.RanUe[anType] == nil {
				amfUe.GmmLog.Warnf("[NAS] UE Context released, abort retransmission of Registration Accept")
				amfUe.T3550 = nil
			} else {
				amfUe.GmmLog.Warnf("T3550 expires, retransmit Registration Accept (retry: %d)", expireTimes)
				ngap_message.SendDownlinkNasTransport(amfUe.RanUe[anType], nasMsg, nil)
			}
		}, func() {
			amfUe.GmmLog.Warnf("T3550 Expires %d times, abort retransmission of Registration Accept", cfg.MaxRetryTimes)
			amfUe.T3550 = nil // clear the timer
			// TS 24.501 5.5.1.2.8 case c, 5.5.1.3.8 case c
			amfUe.State[anType].Set(context.Registered)
			amfUe.ClearRegistrationRequestData(anType)
		})
	}
}

func SendStatus5GMM(ue *context.RanUe, cause uint8) {
	if ue == nil {
		logger.GmmLog.Error("SendStatus5GMM: RanUe is nil")
		return
	}
	if ue.AmfUe == nil {
		logger.GmmLog.Error("SendStatus5GMM: AmfUe is nil")
		return
	}
	amfUe := ue.AmfUe
	amfUe.GmmLog.Info("Send Status 5GMM")

	nasMsg, err := BuildStatus5GMM(cause)
	if err != nil {
		amfUe.GmmLog.Error(err.Error())
		return
	}
	ngap_message.SendDownlinkNasTransport(ue, nasMsg, nil)
}
