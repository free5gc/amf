package gmm

import (
	"time"

	"github.com/free5gc/amf/internal/context"
	gmm_common "github.com/free5gc/amf/internal/gmm/common"
	gmm_message "github.com/free5gc/amf/internal/gmm/message"
	"github.com/free5gc/amf/internal/logger"
	business_metrics "github.com/free5gc/amf/internal/metrics/business"
	ngap_message "github.com/free5gc/amf/internal/ngap/message"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/nas/ie"
	nas_message "github.com/free5gc/nas/message"
	ngapType "github.com/free5gc/ngap/ie"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/fsm"
)

func DeRegistered(state *fsm.State, event fsm.EventType, args fsm.ArgsType) {
	switch event {
	case fsm.EntryEvent:
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		accessType := args[ArgAccessType].(models.AccessType)
		amfUe.ClearRegistrationRequestData(accessType)
		amfUe.GmmLog.Debugln("EntryEvent at GMM State[DeRegistered]")
	case GmmMessageEvent:
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		procedureCode := args[ArgProcedureCode].(int64)
		gmmMessage := args[ArgNASMessage].(nas_message.Message)
		accessType := args[ArgAccessType].(models.AccessType)
		amfUe.GmmLog.Debugln("GmmMessageEvent at GMM State[DeRegistered]")
		switch msg := gmmMessage.(type) {
		case *nas_message.RegReq:
			if err := HandleRegistrationRequest(amfUe, accessType, procedureCode, msg); err != nil {
				logger.GmmLog.Errorln(err)
			} else {
				if errSendEvent := GmmFSM.SendEvent(state, StartAuthEvent, fsm.ArgsType{
					ArgAmfUe:         amfUe,
					ArgAccessType:    accessType,
					ArgProcedureCode: procedureCode,
				}, logger.GmmLog); errSendEvent != nil {
					logger.GmmLog.Errorln(errSendEvent)
				}
			}
		// If UE that considers itself Registared and CM-IDLE throws a ServiceRequest
		case *nas_message.SvcReq:
			if err := HandleServiceRequest(amfUe, accessType, msg); err != nil {
				logger.GmmLog.Errorln(err)
			}
		default:
			amfUe.GmmLog.Errorf("state mismatch: receieve gmm message[message type 0x%0x] at %s state",
				gmmMessage.MsgType(), state.Current())
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
	accessType := args[ArgAccessType].(models.AccessType)
	switch event {
	case fsm.EntryEvent:
		business_metrics.IncrGmmStateGauge(string(accessType), string(state.Current()))
		// clear stored registration request data for this registration
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		amfUe.GmmStateEnterTime = time.Now()
		amfUe.ClearRegistrationRequestData(accessType)
		amfUe.GmmLog.Debugln("EntryEvent at GMM State[Registered]")
		// If we have a radio connection, and we enter the registered state, then we increase the gauge
		if amfUe.CmConnect(accessType) {
			business_metrics.IncrUeConnectivityGauge(accessType)
		}

	case GmmMessageEvent:
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		procedureCode := args[ArgProcedureCode].(int64)
		gmmMessage := args[ArgNASMessage].(nas_message.Message)
		accessType = args[ArgAccessType].(models.AccessType)
		amfUe.GmmLog.Debugln("GmmMessageEvent at GMM State[Registered]")
		switch msg := gmmMessage.(type) {
		// Mobility Registration update / Periodic Registration update
		case *nas_message.RegReq:
			if err := HandleRegistrationRequest(amfUe, accessType, procedureCode, msg); err != nil {
				logger.GmmLog.Errorln(err)
			} else {
				if errSendEvent := GmmFSM.SendEvent(state, StartAuthEvent, fsm.ArgsType{
					ArgAmfUe:         amfUe,
					ArgAccessType:    accessType,
					ArgProcedureCode: procedureCode,
				}, logger.GmmLog); errSendEvent != nil {
					logger.GmmLog.Errorln(errSendEvent)
				}
			}
		case *nas_message.ULNASTransport:
			if err := HandleULNASTransport(amfUe, accessType, msg); err != nil {
				logger.GmmLog.Errorln(err)
			}
		case *nas_message.CfgUpdateComplete:
			if err := HandleConfigurationUpdateComplete(amfUe, msg); err != nil {
				logger.GmmLog.Errorln(err)
			}
		case *nas_message.SvcReq:
			if err := HandleServiceRequest(amfUe, accessType, msg); err != nil {
				logger.GmmLog.Errorln(err)
			}
		case *nas_message.NotifRsp:
			if err := HandleNotificationResponse(amfUe, msg); err != nil {
				logger.GmmLog.Errorln(err)
			}
		case *nas_message.DeregReqUEOrig:
			if err := GmmFSM.SendEvent(state, InitDeregistrationEvent, fsm.ArgsType{
				ArgAmfUe:      amfUe,
				ArgAccessType: accessType,
				ArgNASMessage: msg,
			}, logger.GmmLog); err != nil {
				logger.GmmLog.Errorln(err)
			}
		case *nas_message.Status5GMM:
			if err := HandleStatus5GMM(amfUe, accessType, msg); err != nil {
				logger.GmmLog.Errorln(err)
			}
		default:
			amfUe.GmmLog.Errorf("state mismatch: receieve gmm message[message type 0x%0x] at %s state",
				gmmMessage.MsgType(), state.Current())
		}
	case StartAuthEvent:
		logger.GmmLog.Debugln(event)
	case InitDeregistrationEvent:
		logger.GmmLog.Debugln(event)
	case fsm.ExitEvent:
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		entryTime := amfUe.GmmStateEnterTime
		logger.GmmLog.Debugln(event)
		business_metrics.DecrGmmStateGauge(string(accessType), string(state.Current()), entryTime)
		// As we are no longer considered registered, we decrease the ue connectivity counter
		if amfUe.CmConnect(accessType) {
			business_metrics.DecrUeConnectivityGauge(accessType)
		}
	default:
		logger.GmmLog.Errorf("Unknown event [%+v]", event)
	}
}

func Authentication(state *fsm.State, event fsm.EventType, args fsm.ArgsType) {
	var amfUe *context.AmfUe
	accessType := args[ArgAccessType].(models.AccessType)
	switch event {
	case fsm.EntryEvent:
		business_metrics.IncrGmmStateGauge(string(accessType), string(state.Current()))
		amfUe = args[ArgAmfUe].(*context.AmfUe)
		amfUe.GmmStateEnterTime = time.Now()
		amfUe.GmmLog.Debugln("EntryEvent at GMM State[Authentication]")
		fallthrough
	case AuthRestartEvent:
		amfUe = args[ArgAmfUe].(*context.AmfUe)
		amfUe.GmmLog.Debugln("AuthRestartEvent at GMM State[Authentication]")

		pass, err := AuthenticationProcedure(amfUe, accessType)
		if err != nil {
			if errSendEvent := GmmFSM.SendEvent(state, AuthErrorEvent, fsm.ArgsType{
				ArgAmfUe:      amfUe,
				ArgAccessType: accessType,
			}, logger.GmmLog); errSendEvent != nil {
				logger.GmmLog.Errorln(errSendEvent)
			}
		}
		if pass {
			if errSendEvent := GmmFSM.SendEvent(state, AuthSuccessEvent, fsm.ArgsType{
				ArgAmfUe:      amfUe,
				ArgAccessType: accessType,
			}, logger.GmmLog); errSendEvent != nil {
				logger.GmmLog.Errorln(errSendEvent)
			}
		}
	case GmmMessageEvent:
		amfUe = args[ArgAmfUe].(*context.AmfUe)
		gmmMessage := args[ArgNASMessage].(nas_message.Message)
		accessType = args[ArgAccessType].(models.AccessType)
		amfUe.GmmLog.Debugln("GmmMessageEvent at GMM State[Authentication]")

		switch msg := gmmMessage.(type) {
		case *nas_message.IdRsp:
			if err := HandleIdentityResponse(amfUe, msg); err != nil {
				logger.GmmLog.Errorln(err)
			} else {
				// update identity type used for reauthentication
				amfUe.IdentityTypeUsedForRegistration = msg.MobileId.TypeOfId

				errSendEvent := GmmFSM.SendEvent(
					state,
					AuthRestartEvent,
					fsm.ArgsType{
						ArgAmfUe:      amfUe,
						ArgAccessType: accessType,
					}, logger.GmmLog,
				)
				if errSendEvent != nil {
					logger.GmmLog.Errorln(errSendEvent)
				}
			}
		case *nas_message.AuthRsp:
			if err := HandleAuthenticationResponse(amfUe, accessType, msg); err != nil {
				logger.GmmLog.Errorln(err)
			}
		case *nas_message.AuthFailure:
			if err := HandleAuthenticationFailure(amfUe, accessType, msg); err != nil {
				logger.GmmLog.Errorln(err)
			}
		case *nas_message.Status5GMM:
			if err := HandleStatus5GMM(amfUe, accessType, msg); err != nil {
				logger.GmmLog.Errorln(err)
			}
		default:
			logger.GmmLog.Errorf("UE state mismatch: receieve gmm message[message type 0x%0x] at %s state",
				gmmMessage.MsgType(), state.Current())
		}
	case AuthSuccessEvent:
		logger.GmmLog.Debugln(event)
	case AuthErrorEvent:
		amfUe = args[ArgAmfUe].(*context.AmfUe)
		accessType = args[ArgAccessType].(models.AccessType)
		logger.GmmLog.Debugln(event)
		if err := HandleAuthenticationError(amfUe, accessType); err != nil {
			logger.GmmLog.Errorln(err)
		}
	case AuthFailEvent:
		logger.GmmLog.Debugln(event)
		logger.GmmLog.Warnln("Reject authentication")
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		accessType = args[ArgAccessType].(models.AccessType)
		if amfUe.GetRanUe(accessType) != nil {
			ngap_message.SendUEContextReleaseCommand(amfUe.GetRanUe(accessType), context.UeContextN2NormalRelease,
				ngap_message.CauseChoiceNas, ngapType.CauseNasPresentAuthenticationFailure)
			err := amfUe.GetRanUe(accessType).Remove()
			if err != nil {
				logger.GmmLog.Errorln(err)
			}
		}
		gmm_common.RemoveAmfUe(amfUe, true)
	case fsm.ExitEvent:
		// clear authentication related data at exit
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		amfUe.GmmLog.Debugln(event)
		amfUe.AuthenticationCtx = nil
		amfUe.AuthFailureCauseSynchFailureTimes = 0
		amfUe.IdentityRequestSendTimes = 0
		business_metrics.DecrGmmStateGauge(string(accessType), string(state.Current()), amfUe.GmmStateEnterTime)
	default:
		logger.GmmLog.Errorf("Unknown event [%+v]", event)
	}
}

func SecurityMode(state *fsm.State, event fsm.EventType, args fsm.ArgsType) {
	accessType := args[ArgAccessType].(models.AccessType)
	switch event {
	case fsm.EntryEvent:
		business_metrics.IncrGmmStateGauge(string(accessType), string(state.Current()))
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		amfUe.GmmStateEnterTime = time.Now()
		// set log information
		amfUe.UpdateLogFields(accessType)

		amfUe.GmmLog.Debugln("EntryEvent at GMM State[SecurityMode]")
		if amfUe.SecurityContextIsValid() {
			amfUe.GmmLog.Debugln("UE has a valid security context - skip security mode control procedure")
			if err := GmmFSM.SendEvent(state, SecurityModeSuccessEvent, fsm.ArgsType{
				ArgAmfUe:      amfUe,
				ArgAccessType: accessType,
				ArgNASMessage: amfUe.RegistrationRequest,
			}, logger.GmmLog); err != nil {
				logger.GmmLog.Errorln(err)
			}
		} else {
			eapSuccess := args[ArgEAPSuccess].(bool)
			eapMessage := args[ArgEAPMessage].(string)
			// Select enc/int algorithm based on ue security capability & amf's policy,
			amfSelf := context.GetSelf()
			if err := amfUe.SelectSecurityAlg(amfSelf.SecurityAlgorithm.IntegrityOrder,
				amfSelf.SecurityAlgorithm.CipheringOrder); err != nil {
				amfUe.GmmLog.Errorf("Select security algorithm failed: %s", err)
				gmm_message.SendRegistrationReject(amfUe.GetRanUe(accessType), ie.Cause5GMM_UESecCapabilitiesMismatch, "")
				err = GmmFSM.SendEvent(state, SecurityModeFailEvent, fsm.ArgsType{
					ArgAmfUe:      amfUe,
					ArgAccessType: accessType,
				}, logger.GmmLog)
				if err != nil {
					logger.GmmLog.Errorln(err)
				}
				return
			}
			// Generate KnasEnc, KnasInt
			amfUe.DerivateAlgKey()
			gmm_message.SendSecurityModeCommand(amfUe.GetRanUe(accessType), accessType, eapSuccess, eapMessage)
		}
	case GmmMessageEvent:
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		procedureCode := args[ArgProcedureCode].(int64)
		gmmMessage := args[ArgNASMessage].(nas_message.Message)
		amfUe.GmmLog.Debugln("GmmMessageEvent to GMM State[SecurityMode]")
		switch msg := gmmMessage.(type) {
		case *nas_message.SecModeComplete:
			if err := HandleSecurityModeComplete(amfUe, accessType, procedureCode, msg); err != nil {
				logger.GmmLog.Errorln(err)
			}
		case *nas_message.SecModeRej:
			if err := HandleSecurityModeReject(amfUe, accessType, msg); err != nil {
				logger.GmmLog.Errorln(err)
			}
			err := GmmFSM.SendEvent(state, SecurityModeFailEvent, fsm.ArgsType{
				ArgAmfUe:      amfUe,
				ArgAccessType: accessType,
			}, logger.GmmLog)
			if err != nil {
				logger.GmmLog.Errorln(err)
			}
		case *nas_message.Status5GMM:
			if err := HandleStatus5GMM(amfUe, accessType, msg); err != nil {
				logger.GmmLog.Errorln(err)
			}
		default:
			amfUe.GmmLog.Errorf("state mismatch: receieve gmm message[message type 0x%0x] at %s state",
				gmmMessage.MsgType(), state.Current())
		}
	case SecurityModeSuccessEvent:
		logger.GmmLog.Debugln(event)
	case SecurityModeFailEvent:
		logger.GmmLog.Debugln(event)
	case fsm.ExitEvent:
		logger.GmmLog.Debugln(event)
		entryTime := args[ArgAmfUe].(*context.AmfUe).GmmStateEnterTime
		business_metrics.DecrGmmStateGauge(string(accessType), string(state.Current()), entryTime)
		return
	default:
		logger.GmmLog.Errorf("Unknown event [%+v]", event)
	}
}

func ContextSetup(state *fsm.State, event fsm.EventType, args fsm.ArgsType) {
	accessType := args[ArgAccessType].(models.AccessType)
	switch event {
	case fsm.EntryEvent:
		business_metrics.IncrGmmStateGauge(string(accessType), string(state.Current()))
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		amfUe.GmmStateEnterTime = time.Now()
		gmmMessage := args[ArgNASMessage]
		amfUe.GmmLog.Debugln("EntryEvent at GMM State[ContextSetup]")

		switch message := gmmMessage.(type) {
		case *nas_message.RegReq:
			amfUe.RegistrationRequest = message
			switch amfUe.RegistrationType5GS {
			case ie.RegType_InitialReg:
				if err := HandleInitialRegistration(amfUe, accessType); err != nil {
					logger.GmmLog.Errorln(err)
					err = GmmFSM.SendEvent(state, ContextSetupFailEvent, fsm.ArgsType{
						ArgAmfUe:      amfUe,
						ArgAccessType: accessType,
					}, logger.GmmLog)
					if err != nil {
						logger.GmmLog.Errorln(err)
					}
				}
			case ie.RegType_MobilityRegUpdating:
				fallthrough
			case ie.RegType_PeriodicRegUpdating:
				if err := HandleMobilityAndPeriodicRegistrationUpdating(amfUe, accessType); err != nil {
					logger.GmmLog.Errorln(err)
					err = GmmFSM.SendEvent(state, ContextSetupFailEvent, fsm.ArgsType{
						ArgAmfUe:      amfUe,
						ArgAccessType: accessType,
					}, logger.GmmLog)
					if err != nil {
						logger.GmmLog.Errorln(err)
					}
				}
			}
		case *nas_message.SvcReq:
			if err := HandleServiceRequest(amfUe, accessType, message); err != nil {
				logger.GmmLog.Errorln(err)
			}
		default:
			logger.GmmLog.Errorf("UE state mismatch: receieve wrong gmm message")
		}
	case GmmMessageEvent:
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		gmmMessage := args[ArgNASMessage].(nas_message.Message)
		amfUe.GmmLog.Debugln("GmmMessageEvent at GMM State[ContextSetup]")
		switch msg := gmmMessage.(type) {
		case *nas_message.IdRsp:
			if err := HandleIdentityResponse(amfUe, msg); err != nil {
				logger.GmmLog.Errorln(err)
			} else {
				switch amfUe.RegistrationType5GS {
				case ie.RegType_InitialReg:
					if err2 := HandleInitialRegistration(amfUe, accessType); err2 != nil {
						logger.GmmLog.Errorln(err2)
						err2 = GmmFSM.SendEvent(state, ContextSetupFailEvent, fsm.ArgsType{
							ArgAmfUe:      amfUe,
							ArgAccessType: accessType,
						}, logger.GmmLog)
						if err2 != nil {
							logger.GmmLog.Errorln(err2)
						}
					}
				case ie.RegType_MobilityRegUpdating:
					fallthrough
				case ie.RegType_PeriodicRegUpdating:
					if err2 := HandleMobilityAndPeriodicRegistrationUpdating(amfUe, accessType); err2 != nil {
						logger.GmmLog.Errorln(err2)
						err2 = GmmFSM.SendEvent(state, ContextSetupFailEvent, fsm.ArgsType{
							ArgAmfUe:      amfUe,
							ArgAccessType: accessType,
						}, logger.GmmLog)
						if err2 != nil {
							logger.GmmLog.Errorln(err2)
						}
					}
				}
			}
		case *nas_message.RegComplete:
			if err := HandleRegistrationComplete(amfUe, accessType, msg); err != nil {
				logger.GmmLog.Errorln(err)
			}
		case *nas_message.Status5GMM:
			if err := HandleStatus5GMM(amfUe, accessType, msg); err != nil {
				logger.GmmLog.Errorln(err)
			}
		default:
			amfUe.GmmLog.Errorf("state mismatch: receieve gmm message[message type 0x%0x] at %s state",
				gmmMessage.MsgType(), state.Current())
		}
	case ContextSetupSuccessEvent:
		logger.GmmLog.Debugln(event)
	case ContextSetupFailEvent:
		logger.GmmLog.Debugln(event)
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		if amfUe.UeCmRegistered[accessType] {
			problemDetails, err := consumer.GetConsumer().UeCmDeregistration(amfUe, accessType)
			if problemDetails != nil {
				if problemDetails.Cause != "CONTEXT_NOT_FOUND" {
					amfUe.GmmLog.Errorf("UECM_Registration Failed Problem[%+v]", problemDetails)
				}
			} else if err != nil {
				amfUe.GmmLog.Errorf("UECM_Registration Error[%+v]", err)
			}
		}
	case fsm.ExitEvent:
		logger.GmmLog.Debugln(event)
		entryTime := args[ArgAmfUe].(*context.AmfUe).GmmStateEnterTime
		business_metrics.DecrGmmStateGauge(string(accessType), string(state.Current()), entryTime)
	default:
		logger.GmmLog.Errorf("Unknown event [%+v]", event)
	}
}

func DeregisteredInitiated(state *fsm.State, event fsm.EventType, args fsm.ArgsType) {
	accessType := args[ArgAccessType].(models.AccessType)
	switch event {
	case fsm.EntryEvent:
		business_metrics.IncrGmmStateGauge(string(accessType), string(state.Current()))
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		gmmMessage, ok := args[ArgNASMessage].(*nas_message.DeregReqUEOrig)
		if !ok {
			amfUe.GmmLog.Errorf("expected deregistration request, got %T", args[ArgNASMessage])
			return
		}
		amfUe.GmmLog.Debugln("EntryEvent at GMM State[DeregisteredInitiated]")
		if err := HandleDeregistrationRequest(amfUe, accessType,
			gmmMessage); err != nil {
			logger.GmmLog.Errorln(err)
		}
	case GmmMessageEvent:
		amfUe := args[ArgAmfUe].(*context.AmfUe)
		gmmMessage := args[ArgNASMessage].(nas_message.Message)
		amfUe.GmmLog.Debugln("GmmMessageEvent at GMM State[DeregisteredInitiated]")
		switch msg := gmmMessage.(type) {
		case *nas_message.DeregAcceptUETerm:
			if err := HandleDeregistrationAccept(amfUe, accessType,
				msg); err != nil {
				logger.GmmLog.Errorln(err)
			}
		default:
			amfUe.GmmLog.Errorf("state mismatch: receieve gmm message[message type 0x%0x] at %s state",
				gmmMessage.MsgType(), state.Current())
		}
	case DeregistrationAcceptEvent:
		logger.GmmLog.Debugln(event)
	case fsm.ExitEvent:
		entryTime := args[ArgAmfUe].(*context.AmfUe).GmmStateEnterTime
		business_metrics.DecrGmmStateGauge(string(accessType), string(state.Current()), entryTime)
		logger.GmmLog.Debugln(event)
	default:
		logger.GmmLog.Errorf("Unknown event [%+v]", event)
	}
}
