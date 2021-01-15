package gmm

import (
	"free5gc/lib/fsm"
	"free5gc/lib/nas"
	"free5gc/lib/nas/nasMessage"
	"free5gc/lib/openapi/models"
	"free5gc/src/amf/context"
	gmm_message "free5gc/src/amf/gmm/message"
	"free5gc/src/amf/logger"
)

func DeRegistered(state *fsm.State, event fsm.EventType, args fsm.ArgsType) {
	logger.GmmLog.Debugln("UE in GMM State[DeRegistered]")

	switch event {
	case fsm.EntryEvent:
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		accessType := args[ArgAccessType].(models.AccessType)
		amfUe.ClearRegistrationRequestData(accessType)
	case GmmMessageEvent:
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		procedureCode := args[ArgProcedureCode].(int64)
		gmmMessage := args[ArgNASMessage].(*nas.GmmMessage)
		accessType := args[ArgAccessType].(models.AccessType)
		switch gmmMessage.GetMessageType() {
		case nas.MsgTypeRegistrationRequest:
			if err := HandleRegistrationRequest(amfUe, accessType, procedureCode, gmmMessage.RegistrationRequest); err != nil {
				logger.GmmLog.Errorln(err)
			} else {
				if err := GmmFSM.SendEvent(state, StartAuthEvent, fsm.ArgsType{
					ArgAmfUe:         amfUe,
					ArgAccessType:    accessType,
					ArgProcedureCode: procedureCode,
				}); err != nil {
					logger.GmmLog.Errorln(err)
				}
			}
		default:
			logger.GmmLog.Errorf("UE state mismatch: receieve gmm message[message type 0x%0x] at %s state",
				gmmMessage.GetMessageType(), state.Current())
		}
	case StartAuthEvent:
		logger.GmmLog.Debugln(event)
	case fsm.ExitEvent:
		logger.GmmLog.Debugln(event)
	default:
		logger.GmmLog.Errorf("Unknown event [%+v]", event)
	}
}

func Registered(state *fsm.State, event fsm.EventType, args fsm.ArgsType) {
	logger.GmmLog.Debugln("UE in GMM State[Registered]")

	switch event {
	case fsm.EntryEvent:
		// clear stored registration request data for this registration
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		accessType := args[ArgAccessType].(models.AccessType)
		amfUe.ClearRegistrationRequestData(accessType)
	case GmmMessageEvent:
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		procedureCode := args[ArgProcedureCode].(int64)
		gmmMessage := args[ArgNASMessage].(*nas.GmmMessage)
		accessType := args[ArgAccessType].(models.AccessType)
		switch gmmMessage.GetMessageType() {
		// Mobility Registration update / Periodic Registration update
		case nas.MsgTypeRegistrationRequest:
			if err := HandleRegistrationRequest(amfUe, accessType, procedureCode, gmmMessage.RegistrationRequest); err != nil {
				logger.GmmLog.Errorln(err)
			} else {
				if err := GmmFSM.SendEvent(state, StartAuthEvent, fsm.ArgsType{
					ArgAmfUe:         amfUe,
					ArgAccessType:    accessType,
					ArgProcedureCode: procedureCode,
				}); err != nil {
					logger.GmmLog.Errorln(err)
				}
			}
		case nas.MsgTypeULNASTransport:
			if err := HandleULNASTransport(amfUe, accessType, gmmMessage.ULNASTransport); err != nil {
				logger.GmmLog.Errorln(err)
			}
		case nas.MsgTypeConfigurationUpdateComplete:
			if err := HandleConfigurationUpdateComplete(amfUe, gmmMessage.ConfigurationUpdateComplete); err != nil {
				logger.GmmLog.Errorln(err)
			}
		case nas.MsgTypeServiceRequest:
			if err := HandleServiceRequest(amfUe, accessType, gmmMessage.ServiceRequest); err != nil {
				logger.GmmLog.Errorln(err)
			}
		case nas.MsgTypeNotificationResponse:
			if err := HandleNotificationResponse(amfUe, gmmMessage.NotificationResponse); err != nil {
				logger.GmmLog.Errorln(err)
			}
		case nas.MsgTypeDeregistrationRequestUEOriginatingDeregistration:
			if err := GmmFSM.SendEvent(state, InitDeregistrationEvent, fsm.ArgsType{
				ArgAmfUe:      amfUe,
				ArgAccessType: accessType,
				ArgNASMessage: gmmMessage,
			}); err != nil {
				logger.GmmLog.Errorln(err)
			}
		case nas.MsgTypeStatus5GMM:
			if err := HandleStatus5GMM(amfUe, accessType, gmmMessage.Status5GMM); err != nil {
				logger.GmmLog.Errorln(err)
			}
		default:
			logger.GmmLog.Errorf("UE state mismatch: receieve gmm message[message type 0x%0x] at %s state",
				gmmMessage.GetMessageType(), state.Current())
		}
	case StartAuthEvent:
		logger.GmmLog.Debugln(event)
	case InitDeregistrationEvent:
		logger.GmmLog.Debugln(event)
	case fsm.ExitEvent:
		logger.GmmLog.Debugln(event)
	default:
		logger.GmmLog.Errorf("Unknown event [%+v]", event)
	}
}

func Authentication(state *fsm.State, event fsm.EventType, args fsm.ArgsType) {
	logger.GmmLog.Debugln("UE in GMM State [Authentication]")

	switch event {
	case fsm.EntryEvent:
		fallthrough
	case AuthRestartEvent:
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		accessType := args[ArgAccessType].(models.AccessType)

		pass, err := AuthenticationProcedure(amfUe, accessType)
		if err != nil {
			logger.GmmLog.Errorln(err)
		}
		if pass {
			if err := GmmFSM.SendEvent(state, AuthSuccessEvent, fsm.ArgsType{
				ArgAmfUe:      amfUe,
				ArgAccessType: accessType,
			}); err != nil {
				logger.GmmLog.Errorln(err)
			}
		}
	case GmmMessageEvent:
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		gmmMessage := args[ArgNASMessage].(*nas.GmmMessage)
		accessType := args[ArgAccessType].(models.AccessType)

		switch gmmMessage.GetMessageType() {
		case nas.MsgTypeIdentityResponse:
			if err := HandleIdentityResponse(amfUe, gmmMessage.IdentityResponse); err != nil {
				logger.GmmLog.Errorln(err)
			}
			err := GmmFSM.SendEvent(state, AuthRestartEvent, fsm.ArgsType{ArgAmfUe: amfUe, ArgAccessType: accessType})
			if err != nil {
				logger.GmmLog.Errorln(err)
			}
		case nas.MsgTypeAuthenticationResponse:
			if err := HandleAuthenticationResponse(amfUe, accessType, gmmMessage.AuthenticationResponse); err != nil {
				logger.GmmLog.Errorln(err)
			}
		case nas.MsgTypeAuthenticationFailure:
			if err := HandleAuthenticationFailure(amfUe, accessType, gmmMessage.AuthenticationFailure); err != nil {
				logger.GmmLog.Errorln(err)
			}
		case nas.MsgTypeStatus5GMM:
			if err := HandleStatus5GMM(amfUe, accessType, gmmMessage.Status5GMM); err != nil {
				logger.GmmLog.Errorln(err)
			}
		default:
			logger.GmmLog.Errorf("UE state mismatch: receieve gmm message[message type 0x%0x] at %s state",
				gmmMessage.GetMessageType(), state.Current())
		}
	case AuthSuccessEvent:
		logger.GmmLog.Debugln(event)
	case AuthFailEvent:
		logger.GmmLog.Debugln(event)
		logger.GmmLog.Warnln("Reject authentication")
	case fsm.ExitEvent:
		// clear authentication related data at exit
		logger.GmmLog.Debugln(event)
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		amfUe.AuthenticationCtx = nil
		amfUe.AuthFailureCauseSynchFailureTimes = 0
	default:
		logger.GmmLog.Errorf("Unknown event [%+v]", event)
	}
}

func SecurityMode(state *fsm.State, event fsm.EventType, args fsm.ArgsType) {
	logger.GmmLog.Debugln("UE in GMM State[SecurityMode]")

	switch event {
	case fsm.EntryEvent:
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		accessType := args[ArgAccessType].(models.AccessType)
		if amfUe.SecurityContextIsValid() {
			logger.GmmLog.Debugln("UE has a valid security context - skip security mode control procedure")
			if err := GmmFSM.SendEvent(state, SecurityModeSuccessEvent, fsm.ArgsType{
				ArgAmfUe:      amfUe,
				ArgAccessType: accessType,
				ArgNASMessage: amfUe.RegistrationRequest,
			}); err != nil {
				logger.GmmLog.Errorln(err)
			}
		} else {
			eapSuccess := args[ArgEAPSuccess].(bool)
			eapMessage := args[ArgEAPMessage].(string)
			// Select enc/int algorithm based on ue security capability & amf's policy,
			amfSelf := context.AMF_Self()
			amfUe.SelectSecurityAlg(amfSelf.SecurityAlgorithm.IntegrityOrder, amfSelf.SecurityAlgorithm.CipheringOrder)
			// Generate KnasEnc, KnasInt
			amfUe.DerivateAlgKey()
			gmm_message.SendSecurityModeCommand(amfUe.RanUe[accessType], eapSuccess, eapMessage)
		}
	case GmmMessageEvent:
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		procedureCode := args[ArgProcedureCode].(int64)
		gmmMessage := args[ArgNASMessage].(*nas.GmmMessage)
		accessType := args[ArgAccessType].(models.AccessType)
		switch gmmMessage.GetMessageType() {
		case nas.MsgTypeSecurityModeComplete:
			if err := HandleSecurityModeComplete(amfUe, accessType, procedureCode, gmmMessage.SecurityModeComplete); err != nil {
				logger.GmmLog.Errorln(err)
			}
		case nas.MsgTypeSecurityModeReject:
			if err := HandleSecurityModeReject(amfUe, accessType, gmmMessage.SecurityModeReject); err != nil {
				logger.GmmLog.Errorln(err)
			}
			err := GmmFSM.SendEvent(state, SecurityModeFailEvent, fsm.ArgsType{
				ArgAmfUe:      amfUe,
				ArgAccessType: accessType,
			})
			if err != nil {
				logger.GmmLog.Errorln(err)
			}
		case nas.MsgTypeStatus5GMM:
			if err := HandleStatus5GMM(amfUe, accessType, gmmMessage.Status5GMM); err != nil {
				logger.GmmLog.Errorln(err)
			}
		default:
			logger.GmmLog.Errorf("UE state mismatch: receieve gmm message[message type 0x%0x] at %s state",
				gmmMessage.GetMessageType(), state.Current())
		}
	case SecurityModeSuccessEvent:
		logger.GmmLog.Debugln(event)
	case SecurityModeFailEvent:
		logger.GmmLog.Debugln(event)
	case fsm.ExitEvent:
		logger.GmmLog.Debugln(event)
		return
	default:
		logger.GmmLog.Errorf("Unknown event [%+v]", event)
	}
}

func ContextSetup(state *fsm.State, event fsm.EventType, args fsm.ArgsType) {
	logger.GmmLog.Debugln("UE in GMM State[ContextSetup]")

	switch event {
	case fsm.EntryEvent:
		logger.GmmLog.Debugln("EntryEvent")
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		gmmMessage := args[ArgNASMessage]
		accessType := args[ArgAccessType].(models.AccessType)

		switch message := gmmMessage.(type) {
		case *nasMessage.RegistrationRequest:
			amfUe.RegistrationRequest = message
			switch amfUe.RegistrationType5GS {
			case nasMessage.RegistrationType5GSInitialRegistration:
				if err := HandleInitialRegistration(amfUe, accessType); err != nil {
					logger.GmmLog.Errorln(err)
				}
			case nasMessage.RegistrationType5GSMobilityRegistrationUpdating:
				fallthrough
			case nasMessage.RegistrationType5GSPeriodicRegistrationUpdating:
				if err := HandleMobilityAndPeriodicRegistrationUpdating(amfUe, accessType); err != nil {
					logger.GmmLog.Errorln(err)
				}
			}
		case *nasMessage.ServiceRequest:
			if err := HandleServiceRequest(amfUe, accessType, message); err != nil {
				logger.GmmLog.Errorln(err)
			}
		default:
			logger.GmmLog.Errorf("UE state mismatch: receieve wrong gmm message")
		}
	case GmmMessageEvent:
		logger.GmmLog.Debugln("GmmMessageEvent")
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		gmmMessage := args[ArgNASMessage].(*nas.GmmMessage)
		accessType := args[ArgAccessType].(models.AccessType)
		switch gmmMessage.GetMessageType() {
		case nas.MsgTypeIdentityResponse:
			if err := HandleIdentityResponse(amfUe, gmmMessage.IdentityResponse); err != nil {
				logger.GmmLog.Errorln(err)
			}
			switch amfUe.RegistrationType5GS {
			case nasMessage.RegistrationType5GSInitialRegistration:
				if err := HandleInitialRegistration(amfUe, accessType); err != nil {
					logger.GmmLog.Errorln(err)
					err = GmmFSM.SendEvent(state, ContextSetupFailEvent, fsm.ArgsType{
						ArgAmfUe:      amfUe,
						ArgAccessType: accessType,
					})
					if err != nil {
						logger.GmmLog.Errorln(err)
					}
				}
			case nasMessage.RegistrationType5GSMobilityRegistrationUpdating:
				fallthrough
			case nasMessage.RegistrationType5GSPeriodicRegistrationUpdating:
				if err := HandleMobilityAndPeriodicRegistrationUpdating(amfUe, accessType); err != nil {
					logger.GmmLog.Errorln(err)
					err = GmmFSM.SendEvent(state, ContextSetupFailEvent, fsm.ArgsType{
						ArgAmfUe:      amfUe,
						ArgAccessType: accessType,
					})
					if err != nil {
						logger.GmmLog.Errorln(err)
					}
				}
			}
		case nas.MsgTypeRegistrationComplete:
			if err := HandleRegistrationComplete(amfUe, accessType, gmmMessage.RegistrationComplete); err != nil {
				logger.GmmLog.Errorln(err)
			}
		case nas.MsgTypeStatus5GMM:
			if err := HandleStatus5GMM(amfUe, accessType, gmmMessage.Status5GMM); err != nil {
				logger.GmmLog.Errorln(err)
			}
		default:
			logger.GmmLog.Errorln("UE state mismatch")
		}
	case ContextSetupSuccessEvent:
		logger.GmmLog.Debugln(event)
	case ContextSetupFailEvent:
		logger.GmmLog.Debugln(event)
	case fsm.ExitEvent:
		logger.GmmLog.Debugln(event)
	default:
		logger.GmmLog.Errorf("Unknown event [%+v]", event)
	}
}

func DeregisteredInitiated(state *fsm.State, event fsm.EventType, args fsm.ArgsType) {
	logger.GmmLog.Debugln("UE in GMM State[DeregisteredInitiated]")

	switch event {
	case fsm.EntryEvent:
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		gmmMessage := args[ArgNASMessage].(*nas.GmmMessage)
		accessType := args[ArgAccessType].(models.AccessType)
		if err := HandleDeregistrationRequest(amfUe, accessType,
			gmmMessage.DeregistrationRequestUEOriginatingDeregistration); err != nil {
			logger.GmmLog.Errorln(err)
		}
	case GmmMessageEvent:
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		gmmMessage := args[ArgNASMessage].(*nas.GmmMessage)
		accessType := args[ArgAccessType].(models.AccessType)
		switch gmmMessage.GetMessageType() {
		case nas.MsgTypeDeregistrationAcceptUETerminatedDeregistration:
			if err := HandleDeregistrationAccept(amfUe, accessType,
				gmmMessage.DeregistrationAcceptUETerminatedDeregistration); err != nil {
				logger.GmmLog.Errorln(err)
			}
		default:
			logger.GmmLog.Errorf("UE state mismatch: receieve gmm message[message type 0x%0x] at %s state",
				gmmMessage.GetMessageType(), state.Current())
		}
	case DeregistrationAcceptEvent:
		logger.GmmLog.Debugln(event)
	case fsm.ExitEvent:
		logger.GmmLog.Debugln(event)
	default:
		logger.GmmLog.Errorf("Unknown event [%+v]", event)
	}
}
