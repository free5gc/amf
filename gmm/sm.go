package gmm

import (
	"fmt"
	"free5gc/lib/fsm"
	"free5gc/lib/nas"
	"free5gc/lib/nas/nasMessage"
	"free5gc/lib/openapi/models"
	"free5gc/src/amf/amf_context"
	"free5gc/src/amf/gmm/gmm_event"
	"free5gc/src/amf/logger"
	"github.com/sirupsen/logrus"
)

var GmmLog *logrus.Entry

func init() {
	GmmLog = logger.GmmLog
}

func DeRegistered_3gpp(sm *fsm.FSM, event fsm.Event, args fsm.Args) error {
	return register_event_3gpp(sm, event, args)
}
func Registered_3gpp(sm *fsm.FSM, event fsm.Event, args fsm.Args) error {
	return register_event_3gpp(sm, event, args)
}

func register_event_3gpp(sm *fsm.FSM, event fsm.Event, args fsm.Args) error {
	var amfUe *amf_context.AmfUe
	var procedureCode int64
	switch event {
	case fsm.EVENT_ENTRY:
		return nil
	case gmm_event.EVENT_GMM_MESSAGE:
		amfUe = args[gmm_event.AMF_UE].(*amf_context.AmfUe)
		procedureCode = args[gmm_event.PROCEDURE_CODE].(int64)
		gmmMessage := args[gmm_event.GMM_MESSAGE].(*nas.GmmMessage)
		switch gmmMessage.GetMessageType() {
		case nas.MsgTypeULNASTransport:
			return HandleULNASTransport(amfUe, models.AccessType__3_GPP_ACCESS, gmmMessage.ULNASTransport)
		case nas.MsgTypeRegistrationRequest:
			if err := HandleRegistrationRequest(amfUe, models.AccessType__3_GPP_ACCESS, procedureCode, gmmMessage.RegistrationRequest); err != nil {
				return err
			}
		case nas.MsgTypeIdentityResponse:
			if err := HandleIdentityResponse(amfUe, gmmMessage.IdentityResponse); err != nil {
				return err
			}
		case nas.MsgTypeConfigurationUpdateComplete:
			if err := HandleConfigurationUpdateComplete(amfUe, gmmMessage.ConfigurationUpdateComplete); err != nil {
				return err
			}
		case nas.MsgTypeServiceRequest:
			if err := HandleServiceRequest(amfUe, models.AccessType__3_GPP_ACCESS, procedureCode, gmmMessage.ServiceRequest); err != nil {
				return err
			}
		case nas.MsgTypeDeregistrationRequestUEOriginatingDeregistration:
			return HandleDeregistrationRequest(amfUe, models.AccessType__3_GPP_ACCESS, gmmMessage.DeregistrationRequestUEOriginatingDeregistration)
		case nas.MsgTypeDeregistrationAcceptUETerminatedDeregistration:
			return HandleDeregistrationAccept(amfUe, models.AccessType__3_GPP_ACCESS, gmmMessage.DeregistrationAcceptUETerminatedDeregistration)
		case nas.MsgTypeStatus5GMM:
			if err := HandleStatus5GMM(amfUe, models.AccessType__3_GPP_ACCESS, gmmMessage.Status5GMM); err != nil {
				return err
			}
		default:
			GmmLog.Errorf("Unknown GmmMessage[%d]\n", gmmMessage.GetMessageType())
		}
	default:
		return fmt.Errorf("Unknown Event[%s]\n", event)
	}

	GmmLog.Trace("amfUe.RegistrationType5GS\n", amfUe.RegistrationType5GS)
	switch amfUe.RegistrationType5GS {
	case nasMessage.RegistrationType5GSInitialRegistration:
		return HandleInitialRegistration(amfUe, models.AccessType__3_GPP_ACCESS)
	case nasMessage.RegistrationType5GSMobilityRegistrationUpdating:
		fallthrough
	case nasMessage.RegistrationType5GSPeriodicRegistrationUpdating:
		return HandleMobilityAndPeriodicRegistrationUpdating(amfUe, models.AccessType__3_GPP_ACCESS, procedureCode)
	}
	GmmLog.Trace("register_event_3gpp end\n")
	return nil
}

func Authentication_3gpp(sm *fsm.FSM, event fsm.Event, args fsm.Args) error {
	switch event {
	case fsm.EVENT_ENTRY:
	case gmm_event.EVENT_GMM_MESSAGE:
		amfUe := args[gmm_event.AMF_UE].(*amf_context.AmfUe)
		gmmMessage := args[gmm_event.GMM_MESSAGE].(*nas.GmmMessage)
		switch gmmMessage.GetMessageType() {
		case nas.MsgTypeAuthenticationResponse:
			return HandleAuthenticationResponse(amfUe, models.AccessType__3_GPP_ACCESS, gmmMessage.AuthenticationResponse)
		case nas.MsgTypeAuthenticationFailure:
			return HandleAuthenticationFailure(amfUe, models.AccessType__3_GPP_ACCESS, gmmMessage.AuthenticationFailure)
		case nas.MsgTypeStatus5GMM:
			return HandleStatus5GMM(amfUe, models.AccessType__3_GPP_ACCESS, gmmMessage.Status5GMM)
		}
	default:
		GmmLog.Errorf("Unknown Event[%s]\n", event)
	}
	return nil
}

func SecurityMode_3gpp(sm *fsm.FSM, event fsm.Event, args fsm.Args) error {
	switch event {
	case fsm.EVENT_ENTRY:
	case gmm_event.EVENT_GMM_MESSAGE:
		amfUe := args[gmm_event.AMF_UE].(*amf_context.AmfUe)
		procedureCode := args[gmm_event.PROCEDURE_CODE].(int64)
		gmmMessage := args[gmm_event.GMM_MESSAGE].(*nas.GmmMessage)
		switch gmmMessage.GetMessageType() {
		case nas.MsgTypeSecurityModeComplete:
			return HandleSecurityModeComplete(amfUe, models.AccessType__3_GPP_ACCESS, procedureCode, gmmMessage.SecurityModeComplete)
		case nas.MsgTypeSecurityModeReject:
			return HandleSecurityModeReject(amfUe, models.AccessType__3_GPP_ACCESS, gmmMessage.SecurityModeReject)
		case nas.MsgTypeStatus5GMM:
			return HandleStatus5GMM(amfUe, models.AccessType__3_GPP_ACCESS, gmmMessage.Status5GMM)
		}
	default:
		GmmLog.Errorf("Unknown Event[%s]\n", event)
	}
	return nil
}

func InitialContextSetup_3gpp(sm *fsm.FSM, event fsm.Event, args fsm.Args) error {
	switch event {
	case fsm.EVENT_ENTRY:
	case gmm_event.EVENT_GMM_MESSAGE:
		amfUe := args[gmm_event.AMF_UE].(*amf_context.AmfUe)
		gmmMessage := args[gmm_event.GMM_MESSAGE].(*nas.GmmMessage)
		switch gmmMessage.GetMessageType() {
		case nas.MsgTypeRegistrationComplete:
			return HandleRegistrationComplete(amfUe, models.AccessType__3_GPP_ACCESS, gmmMessage.RegistrationComplete)
		case nas.MsgTypeStatus5GMM:
			return HandleStatus5GMM(amfUe, models.AccessType__3_GPP_ACCESS, gmmMessage.Status5GMM)
		}
	default:
		GmmLog.Errorf("Unknown Event[%s]\n", event)
	}
	return nil
}

func DeRegistered_non_3gpp(sm *fsm.FSM, event fsm.Event, args fsm.Args) error {
	return register_event_non_3gpp(sm, event, args)
}
func Registered_non_3gpp(sm *fsm.FSM, event fsm.Event, args fsm.Args) error {
	return register_event_non_3gpp(sm, event, args)
}

func register_event_non_3gpp(sm *fsm.FSM, event fsm.Event, args fsm.Args) error {
	var amfUe *amf_context.AmfUe
	var procedureCode int64
	switch event {
	case fsm.EVENT_ENTRY:
		return nil
	case gmm_event.EVENT_GMM_MESSAGE:
		amfUe = args[gmm_event.AMF_UE].(*amf_context.AmfUe)
		gmmMessage := args[gmm_event.GMM_MESSAGE].(*nas.GmmMessage)
		procedureCode = args[gmm_event.PROCEDURE_CODE].(int64)
		switch gmmMessage.GetMessageType() {
		case nas.MsgTypeULNASTransport:
			return HandleULNASTransport(amfUe, models.AccessType_NON_3_GPP_ACCESS, gmmMessage.ULNASTransport)
		case nas.MsgTypeRegistrationRequest:
			if err := HandleRegistrationRequest(amfUe, models.AccessType_NON_3_GPP_ACCESS, procedureCode, gmmMessage.RegistrationRequest); err != nil {
				return nil
			}
		case nas.MsgTypeIdentityResponse:
			if err := HandleIdentityResponse(amfUe, gmmMessage.IdentityResponse); err != nil {
				return err
			}
		case nas.MsgTypeNotificationResponse:
			if err := HandleNotificationResponse(amfUe, gmmMessage.NotificationResponse); err != nil {
				return err
			}
		case nas.MsgTypeConfigurationUpdateComplete:
			if err := HandleConfigurationUpdateComplete(amfUe, gmmMessage.ConfigurationUpdateComplete); err != nil {
				return err
			}
		case nas.MsgTypeServiceRequest:
			if err := HandleServiceRequest(amfUe, models.AccessType_NON_3_GPP_ACCESS, procedureCode, gmmMessage.ServiceRequest); err != nil {
				return err
			}
		case nas.MsgTypeDeregistrationRequestUEOriginatingDeregistration:
			return HandleDeregistrationRequest(amfUe, models.AccessType_NON_3_GPP_ACCESS, gmmMessage.DeregistrationRequestUEOriginatingDeregistration)
		case nas.MsgTypeDeregistrationAcceptUETerminatedDeregistration:
			return HandleDeregistrationAccept(amfUe, models.AccessType_NON_3_GPP_ACCESS, gmmMessage.DeregistrationAcceptUETerminatedDeregistration)
		case nas.MsgTypeStatus5GMM:
			if err := HandleStatus5GMM(amfUe, models.AccessType_NON_3_GPP_ACCESS, gmmMessage.Status5GMM); err != nil {
				return err
			}
		default:
			GmmLog.Errorf("Unknown GmmMessage[%d]\n", gmmMessage.GetMessageType())
		}
	default:
		GmmLog.Errorf("Unknown Event[%s]\n", event)
	}

	switch amfUe.RegistrationType5GS {
	case nasMessage.RegistrationType5GSInitialRegistration:
		return HandleInitialRegistration(amfUe, models.AccessType_NON_3_GPP_ACCESS)
	case nasMessage.RegistrationType5GSMobilityRegistrationUpdating:
		fallthrough
	case nasMessage.RegistrationType5GSPeriodicRegistrationUpdating:
		return HandleMobilityAndPeriodicRegistrationUpdating(amfUe, models.AccessType_NON_3_GPP_ACCESS, procedureCode)
	}
	return nil
}

func Authentication_non_3gpp(sm *fsm.FSM, event fsm.Event, args fsm.Args) error {
	switch event {
	case fsm.EVENT_ENTRY:
	case gmm_event.EVENT_GMM_MESSAGE:
		amfUe := args[gmm_event.AMF_UE].(*amf_context.AmfUe)
		gmmMessage := args[gmm_event.GMM_MESSAGE].(*nas.GmmMessage)
		switch gmmMessage.GetMessageType() {
		case nas.MsgTypeAuthenticationResponse:
			return HandleAuthenticationResponse(amfUe, models.AccessType_NON_3_GPP_ACCESS, gmmMessage.AuthenticationResponse)
		case nas.MsgTypeAuthenticationFailure:
			return HandleAuthenticationFailure(amfUe, models.AccessType_NON_3_GPP_ACCESS, gmmMessage.AuthenticationFailure)
		case nas.MsgTypeStatus5GMM:
			return HandleStatus5GMM(amfUe, models.AccessType_NON_3_GPP_ACCESS, gmmMessage.Status5GMM)
		}
	default:
		GmmLog.Errorf("Unknown Event[%s]\n", event)
	}
	return nil
}

func SecurityMode_non_3gpp(sm *fsm.FSM, event fsm.Event, args fsm.Args) error {
	switch event {
	case fsm.EVENT_ENTRY:
	case gmm_event.EVENT_GMM_MESSAGE:
		amfUe := args[gmm_event.AMF_UE].(*amf_context.AmfUe)
		procedureCode := args[gmm_event.PROCEDURE_CODE].(int64)
		gmmMessage := args[gmm_event.GMM_MESSAGE].(*nas.GmmMessage)
		switch gmmMessage.GetMessageType() {
		case nas.MsgTypeSecurityModeComplete:
			return HandleSecurityModeComplete(amfUe, models.AccessType_NON_3_GPP_ACCESS, procedureCode, gmmMessage.SecurityModeComplete)
		case nas.MsgTypeSecurityModeReject:
			return HandleSecurityModeReject(amfUe, models.AccessType_NON_3_GPP_ACCESS, gmmMessage.SecurityModeReject)
		case nas.MsgTypeStatus5GMM:
			return HandleStatus5GMM(amfUe, models.AccessType_NON_3_GPP_ACCESS, gmmMessage.Status5GMM)
		}
	default:
		GmmLog.Errorf("Unknown Event[%s]\n", event)
	}
	return nil
}

func InitialContextSetup_non_3gpp(sm *fsm.FSM, event fsm.Event, args fsm.Args) error {
	switch event {
	case fsm.EVENT_ENTRY:
	case gmm_event.EVENT_GMM_MESSAGE:
		amfUe := args[gmm_event.AMF_UE].(*amf_context.AmfUe)
		gmmMessage := args[gmm_event.GMM_MESSAGE].(*nas.GmmMessage)
		switch gmmMessage.GetMessageType() {
		case nas.MsgTypeRegistrationComplete:
			return HandleRegistrationComplete(amfUe, models.AccessType_NON_3_GPP_ACCESS, gmmMessage.RegistrationComplete)
		case nas.MsgTypeStatus5GMM:
			return HandleStatus5GMM(amfUe, models.AccessType_NON_3_GPP_ACCESS, gmmMessage.Status5GMM)
		}
	default:
		GmmLog.Errorf("Unknown Event[%s]\n", event)
	}
	return nil
}

func Exception(sm *fsm.FSM, event fsm.Event, args fsm.Args) error {
	switch event {
	case fsm.EVENT_ENTRY:
	default:
		GmmLog.Errorf("Unknown Event[%s]\n", event)
	}
	return nil
}
