package gmm

import (
	"fmt"
	"free5gc/lib/fsm"
	"free5gc/lib/nas"
	"free5gc/lib/nas/nasMessage"
	"free5gc/lib/openapi/models"
	"free5gc/src/amf/context"
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
	var amfUe *context.AmfUe
	var procedureCode int64
	switch event {
	case fsm.EVENT_ENTRY:
		return nil
	case EVENT_GMM_MESSAGE:
		amfUe = args[AMF_UE].(*context.AmfUe)
		procedureCode = args[PROCEDURE_CODE].(int64)
		nasMessage := args[NAS_MESSAGE].(*nas.Message)
		gmmMessage := nasMessage.GmmMessage
		switch gmmMessage.GetMessageType() {
		case nas.MsgTypeULNASTransport:
			return HandleULNASTransport(amfUe, models.AccessType__3_GPP_ACCESS, procedureCode, gmmMessage.ULNASTransport, nasMessage.SecurityHeaderType)
		case nas.MsgTypeRegistrationRequest:
			if err := HandleRegistrationRequest(amfUe, models.AccessType__3_GPP_ACCESS, procedureCode, gmmMessage.RegistrationRequest, nasMessage.SecurityHeaderType); err != nil {
				return err
			}
		case nas.MsgTypeIdentityResponse:
			if err := HandleIdentityResponse(amfUe, gmmMessage.IdentityResponse, nasMessage.SecurityHeaderType); err != nil {
				return err
			}
		case nas.MsgTypeConfigurationUpdateComplete:
			if err := HandleConfigurationUpdateComplete(amfUe, gmmMessage.ConfigurationUpdateComplete, nasMessage.SecurityHeaderType); err != nil {
				return err
			}
		case nas.MsgTypeServiceRequest:
			if err := HandleServiceRequest(amfUe, models.AccessType__3_GPP_ACCESS, procedureCode, gmmMessage.ServiceRequest, nasMessage.SecurityHeaderType); err != nil {
				return err
			}
		case nas.MsgTypeDeregistrationRequestUEOriginatingDeregistration:
			return HandleDeregistrationRequest(amfUe, models.AccessType__3_GPP_ACCESS, gmmMessage.DeregistrationRequestUEOriginatingDeregistration, nasMessage.SecurityHeaderType)
		case nas.MsgTypeDeregistrationAcceptUETerminatedDeregistration:
			return HandleDeregistrationAccept(amfUe, models.AccessType__3_GPP_ACCESS, gmmMessage.DeregistrationAcceptUETerminatedDeregistration, nasMessage.SecurityHeaderType)
		case nas.MsgTypeStatus5GMM:
			if err := HandleStatus5GMM(amfUe, models.AccessType__3_GPP_ACCESS, gmmMessage.Status5GMM, nasMessage.SecurityHeaderType); err != nil {
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
	case EVENT_GMM_MESSAGE:
		amfUe := args[AMF_UE].(*context.AmfUe)
		nasMessage := args[NAS_MESSAGE].(*nas.Message)
		gmmMessage := nasMessage.GmmMessage
		switch gmmMessage.GetMessageType() {
		case nas.MsgTypeAuthenticationResponse:
			return HandleAuthenticationResponse(amfUe, models.AccessType__3_GPP_ACCESS, gmmMessage.AuthenticationResponse)
		case nas.MsgTypeAuthenticationFailure:
			return HandleAuthenticationFailure(amfUe, models.AccessType__3_GPP_ACCESS, gmmMessage.AuthenticationFailure)
		case nas.MsgTypeStatus5GMM:
			return HandleStatus5GMM(amfUe, models.AccessType__3_GPP_ACCESS, gmmMessage.Status5GMM, nasMessage.SecurityHeaderType)
		}
	default:
		GmmLog.Errorf("Unknown Event[%s]\n", event)
	}
	return nil
}

func SecurityMode_3gpp(sm *fsm.FSM, event fsm.Event, args fsm.Args) error {
	switch event {
	case fsm.EVENT_ENTRY:
	case EVENT_GMM_MESSAGE:
		amfUe := args[AMF_UE].(*context.AmfUe)
		procedureCode := args[PROCEDURE_CODE].(int64)
		nasMessage := args[NAS_MESSAGE].(*nas.Message)
		gmmMessage := nasMessage.GmmMessage
		switch gmmMessage.GetMessageType() {
		case nas.MsgTypeSecurityModeComplete:
			return HandleSecurityModeComplete(amfUe, models.AccessType__3_GPP_ACCESS, procedureCode, gmmMessage.SecurityModeComplete, nasMessage.SecurityHeaderType)
		case nas.MsgTypeSecurityModeReject:
			return HandleSecurityModeReject(amfUe, models.AccessType__3_GPP_ACCESS, gmmMessage.SecurityModeReject, nasMessage.SecurityHeaderType)
		case nas.MsgTypeStatus5GMM:
			return HandleStatus5GMM(amfUe, models.AccessType__3_GPP_ACCESS, gmmMessage.Status5GMM, nasMessage.SecurityHeaderType)
		}
	default:
		GmmLog.Errorf("Unknown Event[%s]\n", event)
	}
	return nil
}

func InitialContextSetup_3gpp(sm *fsm.FSM, event fsm.Event, args fsm.Args) error {
	switch event {
	case fsm.EVENT_ENTRY:
	case EVENT_GMM_MESSAGE:
		amfUe := args[AMF_UE].(*context.AmfUe)
		nasMessage := args[NAS_MESSAGE].(*nas.Message)
		gmmMessage := nasMessage.GmmMessage
		switch gmmMessage.GetMessageType() {
		case nas.MsgTypeRegistrationComplete:
			return HandleRegistrationComplete(amfUe, models.AccessType__3_GPP_ACCESS, gmmMessage.RegistrationComplete, nasMessage.SecurityHeaderType)
		case nas.MsgTypeStatus5GMM:
			return HandleStatus5GMM(amfUe, models.AccessType__3_GPP_ACCESS, gmmMessage.Status5GMM, nasMessage.SecurityHeaderType)
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
	var amfUe *context.AmfUe
	var procedureCode int64
	switch event {
	case fsm.EVENT_ENTRY:
		return nil
	case EVENT_GMM_MESSAGE:
		amfUe = args[AMF_UE].(*context.AmfUe)
		nasMessage := args[NAS_MESSAGE].(*nas.Message)
		gmmMessage := nasMessage.GmmMessage
		procedureCode = args[PROCEDURE_CODE].(int64)
		switch gmmMessage.GetMessageType() {
		case nas.MsgTypeULNASTransport:
			return HandleULNASTransport(amfUe, models.AccessType_NON_3_GPP_ACCESS, procedureCode, gmmMessage.ULNASTransport, nasMessage.SecurityHeaderType)
		case nas.MsgTypeRegistrationRequest:
			if err := HandleRegistrationRequest(amfUe, models.AccessType_NON_3_GPP_ACCESS, procedureCode, gmmMessage.RegistrationRequest, nasMessage.SecurityHeaderType); err != nil {
				return nil
			}
		case nas.MsgTypeIdentityResponse:
			if err := HandleIdentityResponse(amfUe, gmmMessage.IdentityResponse, nasMessage.SecurityHeaderType); err != nil {
				return err
			}
		case nas.MsgTypeNotificationResponse:
			if err := HandleNotificationResponse(amfUe, gmmMessage.NotificationResponse, nasMessage.SecurityHeaderType); err != nil {
				return err
			}
		case nas.MsgTypeConfigurationUpdateComplete:
			if err := HandleConfigurationUpdateComplete(amfUe, gmmMessage.ConfigurationUpdateComplete, nasMessage.SecurityHeaderType); err != nil {
				return err
			}
		case nas.MsgTypeServiceRequest:
			if err := HandleServiceRequest(amfUe, models.AccessType_NON_3_GPP_ACCESS, procedureCode, gmmMessage.ServiceRequest, nasMessage.SecurityHeaderType); err != nil {
				return err
			}
		case nas.MsgTypeDeregistrationRequestUEOriginatingDeregistration:
			return HandleDeregistrationRequest(amfUe, models.AccessType_NON_3_GPP_ACCESS, gmmMessage.DeregistrationRequestUEOriginatingDeregistration, nasMessage.SecurityHeaderType)
		case nas.MsgTypeDeregistrationAcceptUETerminatedDeregistration:
			return HandleDeregistrationAccept(amfUe, models.AccessType_NON_3_GPP_ACCESS, gmmMessage.DeregistrationAcceptUETerminatedDeregistration, nasMessage.SecurityHeaderType)
		case nas.MsgTypeStatus5GMM:
			if err := HandleStatus5GMM(amfUe, models.AccessType_NON_3_GPP_ACCESS, gmmMessage.Status5GMM, nasMessage.SecurityHeaderType); err != nil {
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
	case EVENT_GMM_MESSAGE:
		amfUe := args[AMF_UE].(*context.AmfUe)
		nasMessage := args[NAS_MESSAGE].(*nas.Message)
		gmmMessage := nasMessage.GmmMessage
		switch gmmMessage.GetMessageType() {
		case nas.MsgTypeAuthenticationResponse:
			return HandleAuthenticationResponse(amfUe, models.AccessType_NON_3_GPP_ACCESS, gmmMessage.AuthenticationResponse)
		case nas.MsgTypeAuthenticationFailure:
			return HandleAuthenticationFailure(amfUe, models.AccessType_NON_3_GPP_ACCESS, gmmMessage.AuthenticationFailure)
		case nas.MsgTypeStatus5GMM:
			return HandleStatus5GMM(amfUe, models.AccessType_NON_3_GPP_ACCESS, gmmMessage.Status5GMM, nasMessage.SecurityHeaderType)
		}
	default:
		GmmLog.Errorf("Unknown Event[%s]\n", event)
	}
	return nil
}

func SecurityMode_non_3gpp(sm *fsm.FSM, event fsm.Event, args fsm.Args) error {
	switch event {
	case fsm.EVENT_ENTRY:
	case EVENT_GMM_MESSAGE:
		amfUe := args[AMF_UE].(*context.AmfUe)
		procedureCode := args[PROCEDURE_CODE].(int64)
		nasMessage := args[NAS_MESSAGE].(*nas.Message)
		gmmMessage := nasMessage.GmmMessage
		switch gmmMessage.GetMessageType() {
		case nas.MsgTypeSecurityModeComplete:
			return HandleSecurityModeComplete(amfUe, models.AccessType_NON_3_GPP_ACCESS, procedureCode, gmmMessage.SecurityModeComplete, nasMessage.SecurityHeaderType)
		case nas.MsgTypeSecurityModeReject:
			return HandleSecurityModeReject(amfUe, models.AccessType_NON_3_GPP_ACCESS, gmmMessage.SecurityModeReject, nasMessage.SecurityHeaderType)
		case nas.MsgTypeStatus5GMM:
			return HandleStatus5GMM(amfUe, models.AccessType_NON_3_GPP_ACCESS, gmmMessage.Status5GMM, nasMessage.SecurityHeaderType)
		}
	default:
		GmmLog.Errorf("Unknown Event[%s]\n", event)
	}
	return nil
}

func InitialContextSetup_non_3gpp(sm *fsm.FSM, event fsm.Event, args fsm.Args) error {
	switch event {
	case fsm.EVENT_ENTRY:
	case EVENT_GMM_MESSAGE:
		amfUe := args[AMF_UE].(*context.AmfUe)
		nasMessage := args[NAS_MESSAGE].(*nas.Message)
		gmmMessage := nasMessage.GmmMessage
		switch gmmMessage.GetMessageType() {
		case nas.MsgTypeRegistrationComplete:
			return HandleRegistrationComplete(amfUe, models.AccessType_NON_3_GPP_ACCESS, gmmMessage.RegistrationComplete, nasMessage.SecurityHeaderType)
		case nas.MsgTypeStatus5GMM:
			return HandleStatus5GMM(amfUe, models.AccessType_NON_3_GPP_ACCESS, gmmMessage.Status5GMM, nasMessage.SecurityHeaderType)
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
