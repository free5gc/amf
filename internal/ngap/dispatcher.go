package ngap

import (
	"errors"
	"net"
	"reflect"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	ngap_message "github.com/free5gc/amf/internal/ngap/message"
	ngapIE "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/sctp"
)

func Dispatch(conn net.Conn, msg []byte) {
	amfSelf := context.GetSelf()

	if len(msg) == 0 {
		ran, ok := amfSelf.AmfRanFindByConn(conn)
		if !ok {
			logger.NgapLog.Warnf("Connection closed before NGSetup: %v", conn.RemoteAddr())
			return
		}
		ran.Log.Infof("RAN close the connection.")
		removeRan(ran)
		return
	}

	decoded, err := ngapMessage.Parse(msg)
	if err != nil {
		logger.NgapLog.Errorf("NGAP decode error: %+v", err)
		if ran, ok := amfSelf.AmfRanFindByConn(conn); ok {
			handleDecodeError(ran, decoded, err)
		}
		return
	}
	if decoded == nil {
		logger.NgapLog.Error("NGAP Message is nil")
		return
	}
	ran, ok := amfSelf.AmfRanFindByConn(conn)
	if !ok {
		_, isNGSetup := decoded.(*ngapMessage.NGSetupRequest)
		if isNGSetup {
			addr := conn.RemoteAddr()
			if addr == nil {
				logger.NgapLog.Warn("Addr of new NG connection is nil")
				return
			}
			logger.NgapLog.Infof("Create a new NG connection for: %s", addr.String())
			ran = amfSelf.NewAmfRan(conn)
		} else {
			logger.NgapLog.Warn("Received non-NGSetup on new connection")
			return
		}
	}

	dispatchMain(ran, decoded, msg)
}

func handleDecodeError(ran *context.AmfRan, decoded ngapMessage.Message, decodeErr error) {
	var cause *ngapIE.Cause
	var criticalityDiagnostics *ngapIE.CriticalityDiagnostics

	var transferSyntaxErr *ngapIE.TransferSyntaxErr
	var abstractSyntaxErr *ngapIE.AbstractSyntaxErr
	switch {
	case errors.As(decodeErr, &transferSyntaxErr):
		cause = transferSyntaxErr.GetCause()
	case errors.As(decodeErr, &abstractSyntaxErr):
		var err error
		cause, err = abstractSyntaxErr.GetCause()
		if err != nil {
			ran.Log.Warnf("Failed to derive cause from NGAP decode error: %v", err)
		}
		criticalityDiagnostics, err = abstractSyntaxErr.GetCritDiag(true)
		if err != nil {
			ran.Log.Warnf("Failed to derive criticality diagnostics from NGAP decode error: %v", err)
		}
	default:
		return
	}
	if cause == nil && criticalityDiagnostics == nil {
		return
	}

	amfID, ranID := messageUEIDs(decoded)
	ngap_message.SendErrorIndication(ran, amfID, ranID, cause, criticalityDiagnostics)
}

func messageUEIDs(decoded ngapMessage.Message) (*ngapIE.AMFUENGAPID, *ngapIE.RANUENGAPID) {
	if decoded == nil {
		return nil, nil
	}
	value := reflect.ValueOf(decoded)
	if value.Kind() != reflect.Pointer || value.IsNil() {
		return nil, nil
	}
	value = value.Elem()

	var amfID *ngapIE.AMFUENGAPID
	if field := value.FieldByName("AMFUENGAPID"); field.IsValid() && field.Kind() == reflect.Pointer &&
		!field.IsNil() {
		amfID, _ = field.Interface().(*ngapIE.AMFUENGAPID)
	}
	var ranID *ngapIE.RANUENGAPID
	if field := value.FieldByName("RANUENGAPID"); field.IsValid() && field.Kind() == reflect.Pointer &&
		!field.IsNil() {
		ranID, _ = field.Interface().(*ngapIE.RANUENGAPID)
	}
	return amfID, ranID
}

func HandleSCTPNotification(conn net.Conn, notification sctp.Notification) {
	amfSelf := context.GetSelf()

	logger.NgapLog.Infof("Handle SCTP Notification[addr: %+v]", conn.RemoteAddr())

	ran, ok := amfSelf.AmfRanFindByConn(conn)
	if !ok {
		logger.NgapLog.Warnf("RAN context has been removed[addr: %+v]", conn.RemoteAddr())
		return
	}

	switch notification.Type() {
	case sctp.SCTP_ASSOC_CHANGE:
		ran.Log.Infof("SCTP_ASSOC_CHANGE notification")
		event := notification.(*sctp.SCTPAssocChangeEvent)
		switch event.State() {
		case sctp.SCTP_COMM_LOST:
			ran.Log.Infof("SCTP state is SCTP_COMM_LOST, close the connection")
			removeRan(ran)
		case sctp.SCTP_SHUTDOWN_COMP:
			ran.Log.Infof("SCTP state is SCTP_SHUTDOWN_COMP, close the connection")
			removeRan(ran)
		default:
			ran.Log.Warnf("SCTP state[%+v] is not handled", event.State())
		}
	case sctp.SCTP_SHUTDOWN_EVENT:
		ran.Log.Infof("SCTP_SHUTDOWN_EVENT notification, close the connection")
		removeRan(ran)
	default:
		ran.Log.Warnf("Non handled notification type: 0x%x", notification.Type())
	}
}

func HandleSCTPConnError(conn net.Conn) {
	amfSelf := context.GetSelf()

	logger.NgapLog.Infof("Handle SCTP Connection Error[addr: %+v] - remove RAN", conn.RemoteAddr())

	ran, ok := amfSelf.AmfRanFindByConn(conn)
	if !ok {
		logger.NgapLog.Warnf("RAN context has been removed[addr: %+v]", conn.RemoteAddr())
		return
	}
	removeRan(ran)
}
