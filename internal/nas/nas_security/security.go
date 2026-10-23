package nas_security

import (
	"errors"
	"fmt"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

func Encode(
	ue *context.AmfUe,
	msg message.Message,
	accessType models.AccessType,
	securityHeaderType message.SecHdrType,
) ([]byte, error) {
	if msg == nil {
		return nil, fmt.Errorf("NAS message is nil")
	}

	if ue == nil || !ue.SecurityContextAvailable {
		if err := validatePlainMessage(msg); err != nil {
			return nil, err
		}
		return message.Marshal(msg, nil, message.SecHdrTypePlainNas)
	}

	if securityHeaderType == message.SecHdrTypePlainNas {
		return nil, fmt.Errorf("NAS message %s cannot be sent plain when security context is available", msg.MsgType())
	}

	switch securityHeaderType {
	case message.SecHdrTypeIntegrityProtected:
		ue.NASLog.Debugln("Security header type: Integrity Protected")
	case message.SecHdrTypeIntegrityProtectedAndCiphered:
		ue.NASLog.Debugln("Security header type: Integrity Protected And Ciphered")
	case message.SecHdrTypeIntegrityProtectedWithNew5gNasSecCtx:
		ue.NASLog.Debugln("Security header type: Integrity Protected With New 5G Security Context")
		ue.ULCount.Set(0, 0)
		ue.DLCount.Set(0, 0)
	case message.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx:
		ue.NASLog.Debugln("Security header type: Integrity Protected And Ciphered With New 5G Security Context")
		ue.ULCount.Set(0, 0)
		ue.DLCount.Set(0, 0)
	default:
		return nil, fmt.Errorf("wrong security header type: 0x%0x", securityHeaderType)
	}

	return message.Marshal(msg, newSecurityContext(ue, accessType), securityHeaderType)
}

func validatePlainMessage(msg message.Message) error {
	switch msg.MsgType() {
	case message.MsgTypeIdReq:
		identityRequest, ok := msg.(*message.IdReq)
		if !ok || identityRequest.IdType == nil {
			return fmt.Errorf("identity request has no identity type")
		}
		if identityRequest.IdType.IdType != ie.IdType_5GS_SUCI {
			return fmt.Errorf(
				"identity request (%d) requires security, but security context is not available",
				identityRequest.IdType.IdType,
			)
		}
	case message.MsgTypeAuthReq,
		message.MsgTypeAuthResult,
		message.MsgTypeAuthRej,
		message.MsgTypeRegRej,
		message.MsgTypeDeregAcceptUEOrig,
		message.MsgTypeSvcRej:
	default:
		return fmt.Errorf(
			"NAS message type %d requires security, but security context is not available",
			msg.MsgType(),
		)
	}
	return nil
}

/*
Decode accepts either a security-protected 5GS NAS message or a plain 5GS NAS
message as defined by TS 24.501 section 9.1.1. In addition to decoding, it
enforces the AMF-side security-header policy for each uplink procedure.
*/
func Decode(
	ue *context.AmfUe,
	accessType models.AccessType,
	payload []byte,
	initialMessage bool,
) (msg message.Message, integrityProtected bool, err error) {
	if ue == nil {
		return nil, false, fmt.Errorf("amfUe is nil")
	}
	if len(payload) == 0 {
		return nil, false, fmt.Errorf("NAS payload is empty")
	}
	if len(payload) < 2 {
		return nil, false, fmt.Errorf("NAS payload is too short")
	}

	securityHeaderType := message.GetSecHdrType(payload)
	ue.NASLog.Traceln("securityHeaderType is ", securityHeaderType)

	var securityContext *message.SecCtx
	if ue.SecurityContextAvailable {
		securityContext = newSecurityContext(ue, accessType)
	}

	msg, parseErr := message.Parse(payload, securityContext)
	if parseErr != nil {
		var nasErr *message.Error
		if !errors.As(parseErr, &nasErr) || nasErr.MACFailure == nil || len(nasErr.IEToDoList) != 0 || msg == nil {
			return nil, false, parseErr
		}
		ue.NASLog.Warnf(
			"NAS MAC verification failed(received: 0x%08x, expected: 0x%08x)",
			nasErr.MACFailure.Received,
			nasErr.MACFailure.Expected,
		)
	} else if securityHeaderType != message.SecHdrTypePlainNas {
		integrityProtected = true
	}

	if err = validateUplinkSecurity(
		ue,
		msg,
		securityHeaderType,
		integrityProtected,
		initialMessage,
	); err != nil {
		return nil, false, err
	}

	// A received COUNT is accepted once (TS 24.501 §4.4.3.2). message.Parse
	// leaves ue.ULCount at the sequence number it just verified, so advance it
	// here; otherwise the next message may reuse that COUNT and be replayed.
	if integrityProtected {
		ue.ULCount.AddOne()
	}

	return msg, integrityProtected, nil
}

func validateUplinkSecurity(
	ue *context.AmfUe,
	msg message.Message,
	securityHeaderType message.SecHdrType,
	integrityProtected bool,
	initialMessage bool,
) error {
	msgTypeText := func() string {
		if msg == nil {
			return "unknown message"
		}
		return fmt.Sprintf("message type %d", msg.MsgType())
	}
	errNoSecurityContext := func() error {
		return fmt.Errorf("UE Security Context is not Available, %s", msgTypeText())
	}
	errWrongSecurityHeader := func() error {
		return fmt.Errorf("wrong security header type: 0x%0x, %s", securityHeaderType, msgTypeText())
	}
	errMacVerificationFailed := func() error {
		return fmt.Errorf("MAC verification failed, %s", msgTypeText())
	}

	if msg == nil {
		return fmt.Errorf("decoded NAS message is nil")
	}

	if msg.ExtendedProtocolDiscriminator() == message.Epd5GSSessMgmtMsg {
		if !ue.SecurityContextAvailable {
			return errNoSecurityContext()
		}
		if securityHeaderType != message.SecHdrTypeIntegrityProtectedAndCiphered {
			return errWrongSecurityHeader()
		}
		if !integrityProtected {
			return errMacVerificationFailed()
		}
		return nil
	}

	switch msg.MsgType() {
	case message.MsgTypeDeregReqUEOrig, message.MsgTypeRegReq:
		if initialMessage {
			if securityHeaderType == message.SecHdrTypeIntegrityProtectedAndCiphered ||
				securityHeaderType == message.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx {
				return errWrongSecurityHeader()
			}
		} else if ue.SecurityContextAvailable {
			if securityHeaderType != message.SecHdrTypeIntegrityProtectedAndCiphered {
				return errWrongSecurityHeader()
			}
			if !integrityProtected {
				return errMacVerificationFailed()
			}
		}
	case message.MsgTypeSvcReq:
		if initialMessage {
			if securityHeaderType != message.SecHdrTypeIntegrityProtected {
				return errWrongSecurityHeader()
			}
		} else {
			if !ue.SecurityContextAvailable {
				return errNoSecurityContext()
			}
			if securityHeaderType != message.SecHdrTypeIntegrityProtectedAndCiphered {
				return errWrongSecurityHeader()
			}
			if !integrityProtected {
				return errMacVerificationFailed()
			}
		}
	case message.MsgTypeIdRsp:
		identityResponse, ok := msg.(*message.IdRsp)
		if !ok || identityResponse.MobileId == nil {
			return fmt.Errorf("identity response has no mobile identity")
		}
		isSUCI := identityResponse.MobileId.TypeOfId == ie.IdType_5GS_SUCI
		if !isSUCI && !ue.SecurityContextAvailable {
			return errNoSecurityContext()
		}
		if ue.SecurityContextAvailable {
			if securityHeaderType != message.SecHdrTypeIntegrityProtectedAndCiphered {
				return errWrongSecurityHeader()
			}
			if !integrityProtected {
				return errMacVerificationFailed()
			}
		}
	case message.MsgTypeAuthRsp,
		message.MsgTypeAuthFailure,
		message.MsgTypeSecModeRej,
		message.MsgTypeDeregAcceptUETerm:
		if ue.SecurityContextAvailable {
			if securityHeaderType != message.SecHdrTypeIntegrityProtectedAndCiphered {
				return errWrongSecurityHeader()
			}
			if !integrityProtected {
				return errMacVerificationFailed()
			}
		}
	case message.MsgTypeSecModeComplete:
		if !ue.SecurityContextAvailable {
			return errNoSecurityContext()
		}
		if securityHeaderType != message.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx {
			return errWrongSecurityHeader()
		}
		if !integrityProtected {
			return errMacVerificationFailed()
		}
	default:
		if !ue.SecurityContextAvailable {
			return errNoSecurityContext()
		}
		if securityHeaderType != message.SecHdrTypeIntegrityProtectedAndCiphered {
			return errWrongSecurityHeader()
		}
		if !integrityProtected {
			return errMacVerificationFailed()
		}
	}

	return nil
}

// DecodePlainNasNoIntegrityCheck decodes a plain or integrity-only NAS message.
// Ciphered messages are rejected because no security context is supplied.
func DecodePlainNasNoIntegrityCheck(payload []byte) (message.Message, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("NAS payload is empty")
	}
	if len(payload) < 2 {
		return nil, fmt.Errorf("NAS payload is too short")
	}

	securityHeaderType := message.GetSecHdrType(payload)
	if securityHeaderType == message.SecHdrTypeIntegrityProtectedAndCiphered ||
		securityHeaderType == message.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx {
		return nil, fmt.Errorf("NAS payload is ciphered")
	}
	if securityHeaderType != message.SecHdrTypePlainNas {
		if len(payload) < int(message.SecHdrLen) {
			return nil, fmt.Errorf("NAS payload is too short")
		}
		payload = payload[message.SecHdrLen:]
	}

	return message.Parse(payload, nil)
}

func newSecurityContext(ue *context.AmfUe, accessType models.AccessType) *message.SecCtx {
	return &message.SecCtx{
		Side:          message.CoreNetworkSide,
		Bearer:        GetBearerType(accessType),
		UplinkCount:   &ue.ULCount,
		DownlinkCount: &ue.DLCount,
		CipheringAlg:  ie.AlgCiphering(ue.CipheringAlg),
		IntegrityAlg:  ie.AlgIntegrity(ue.IntegrityAlg),
		KnasEnc:       ue.KnasEnc,
		KnasInt:       ue.KnasInt,
	}
}

func GetBearerType(accessType models.AccessType) message.BearerType {
	switch accessType {
	case models.AccessType_3_GPP_ACCESS:
		return message.Bearer3GPP
	case models.AccessType_NON_3_GPP_ACCESS:
		return message.BearerNon3GPP
	default:
		return message.OnlyOneBearer
	}
}
