package nas_security

import (
	"encoding/hex"
	"fmt"
	"free5gc/lib/nas"
	"free5gc/lib/nas/security"
	"free5gc/lib/openapi/models"
	"free5gc/src/amf/context"
	"free5gc/src/amf/logger"
	"reflect"
)

func Encode(ue *context.AmfUe, msg *nas.Message) ([]byte, error) {
	if ue == nil {
		return nil, fmt.Errorf("amfUe is nil")
	}
	if msg == nil {
		return nil, fmt.Errorf("Nas Message is empty")
	}

	// Plain NAS message
	if !ue.SecurityContextAvailable {
		return msg.PlainNasEncode()
	} else {
		// Security protected NAS Message
		// a security protected NAS message must be integrity protected, and ciphering is optional
		needCiphering := false
		switch msg.SecurityHeader.SecurityHeaderType {
		case nas.SecurityHeaderTypeIntegrityProtected:
			logger.NasLog.Debugln("Security header type: Integrity Protected")
		case nas.SecurityHeaderTypeIntegrityProtectedAndCiphered:
			logger.NasLog.Debugln("Security header type: Integrity Protected And Ciphered")
			needCiphering = true
		case nas.SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext:
			logger.NasLog.Debugln("Security header type: Integrity Protected With New 5G Security Context")
			ue.ULCount.Set(0, 0)
			ue.DLCount.Set(0, 0)
		default:
			return nil, fmt.Errorf("Wrong security header type: 0x%0x", msg.SecurityHeader.SecurityHeaderType)
		}

		// encode plain nas first
		payload, err := msg.PlainNasEncode()
		if err != nil {
			return nil, fmt.Errorf("Plain NAS encode error: %+v", err)
		}

		logger.NasLog.Traceln("ue.CipheringAlg", ue.CipheringAlg)
		logger.NasLog.Traceln("ue.DLCount()", ue.DLCount.Get())
		logger.NasLog.Tracef("payload:\n%+v", hex.Dump(payload))

		if needCiphering {
			logger.NasLog.Debugln("Perform NAS encryption")
			if err = security.NASEncrypt(ue.CipheringAlg, ue.KnasEnc, ue.DLCount.Get(), security.Bearer3GPP,
				security.DirectionDownlink, payload); err != nil {
				return nil, fmt.Errorf("Encrypt error: %+v", err)
			}
		}

		// add sequece number
		payload = append([]byte{ue.DLCount.SQN()}, payload[:]...)

		mac32, err := security.NASMacCalculate(ue.IntegrityAlg, ue.KnasInt, ue.DLCount.Get(), security.Bearer3GPP,
			security.DirectionDownlink, payload)
		if err != nil {
			return nil, fmt.Errorf("MAC calcuate error: %+v", err)
		}
		// Add mac value
		logger.NasLog.Traceln("mac32", mac32)
		payload = append(mac32, payload[:]...)

		// Add EPD and Security Type
		msgSecurityHeader := []byte{msg.SecurityHeader.ProtocolDiscriminator, msg.SecurityHeader.SecurityHeaderType}
		payload = append(msgSecurityHeader, payload[:]...)
		logger.NasLog.Traceln("Encode payload", payload)
		// Increase DL Count
		ue.DLCount.AddOne()
		return payload, nil
	}
}

/*
payload either a security protected 5GS NAS message or a plain 5GS NAS message which
format is followed TS 24.501 9.1.1
*/
func Decode(ue *context.AmfUe, accessType models.AccessType, payload []byte) (*nas.Message, error) {
	if ue == nil {
		return nil, fmt.Errorf("amfUe is nil")
	}
	if payload == nil {
		return nil, fmt.Errorf("Nas payload is empty")
	}

	msg := new(nas.Message)
	msg.SecurityHeaderType = uint8(nas.GetSecurityHeaderType(payload) & 0x0f)
	logger.NasLog.Traceln("securityHeaderType is ", msg.SecurityHeaderType)
	if msg.SecurityHeaderType == nas.SecurityHeaderTypePlainNas {
		// RRCEstablishmentCause 0 is for emergency service
		if ue.SecurityContextAvailable && ue.RanUe[accessType].RRCEstablishmentCause != "0" {
			logger.NasLog.Warnln("Received Plain NAS message")
			ue.MacFailed = false
			if err := msg.PlainNasDecode(&payload); err != nil {
				return nil, err
			}

			if msg.GmmMessage == nil {
				return nil, fmt.Errorf("Gmm Message is nil")
			}

			// TS 24.501 4.4.4.3: Except the messages listed below, no NAS signalling messages shall be processed
			// by the receiving 5GMM entity in the AMF or forwarded to the 5GSM entity, unless the secure exchange
			// of NAS messages has been established for the NAS signalling connection
			switch msg.GmmHeader.GetMessageType() {
			case nas.MsgTypeRegistrationRequest:
				return msg, nil
			case nas.MsgTypeIdentityResponse:
				return msg, nil
			case nas.MsgTypeAuthenticationResponse:
				return msg, nil
			case nas.MsgTypeAuthenticationFailure:
				return msg, nil
			case nas.MsgTypeSecurityModeReject:
				return msg, nil
			case nas.MsgTypeDeregistrationRequestUEOriginatingDeregistration:
				return msg, nil
			case nas.MsgTypeDeregistrationAcceptUETerminatedDeregistration:
				return msg, nil
			default:
				return nil, fmt.Errorf(
					"UE can not send plain nas for non-emergency service when there is a valid security context")
			}
		} else {
			ue.MacFailed = false
			err := msg.PlainNasDecode(&payload)
			return msg, err
		}
	} else { // Security protected NAS message
		logger.NasLog.Traceln("securityHeaderType is ", msg.SecurityHeaderType)
		securityHeader := payload[0:6]
		logger.NasLog.Traceln("securityHeader is ", securityHeader)
		sequenceNumber := payload[6]
		logger.NasLog.Traceln("sequenceNumber", sequenceNumber)

		receivedMac32 := securityHeader[2:]
		// remove security Header except for sequece Number
		payload = payload[6:]

		// a security protected NAS message must be integrity protected, and ciphering is optional
		ciphered := false
		switch msg.SecurityHeaderType {
		case nas.SecurityHeaderTypeIntegrityProtected:
			logger.NasLog.Debugln("Security header type: Integrity Protected")
		case nas.SecurityHeaderTypeIntegrityProtectedAndCiphered:
			logger.NasLog.Debugln("Security header type: Integrity Protected And Ciphered")
			ciphered = true
		case nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext:
			logger.NasLog.Debugln("Security header type: Integrity Protected And Ciphered With New 5G Security Context")
			ciphered = true
			ue.ULCount.Set(0, 0)
		default:
			return nil, fmt.Errorf("Wrong security header type: 0x%0x", msg.SecurityHeader.SecurityHeaderType)
		}

		if ue.ULCount.SQN() > sequenceNumber {
			logger.NasLog.Debugf("set ULCount overflow")
			ue.ULCount.SetOverflow(ue.ULCount.Overflow() + 1)
		}
		ue.ULCount.SetSQN(sequenceNumber)

		logger.NasLog.Debugln("Perform NAS mac calculation")
		mac32, err := security.NASMacCalculate(ue.IntegrityAlg, ue.KnasInt, ue.ULCount.Get(), security.Bearer3GPP,
			security.DirectionUplink, payload)
		if err != nil {
			return nil, fmt.Errorf("MAC calcuate error: %+v", err)
		}

		if !reflect.DeepEqual(mac32, receivedMac32) {
			logger.NasLog.Warnf("NAS MAC verification failed(received: 0x%08x, expected: 0x%08x)", receivedMac32, mac32)
			ue.MacFailed = true
		} else {
			logger.NasLog.Tracef("cmac value: 0x%08x", mac32)
			ue.MacFailed = false
		}

		if ciphered {
			logger.NasLog.Debugf("Perform NAS decryption")
			logger.NasLog.Traceln("ue.CipheringAlg", ue.CipheringAlg)
			// decrypt payload without sequence number (payload[1])
			if err = security.NASEncrypt(ue.CipheringAlg, ue.KnasEnc, ue.ULCount.Get(), security.Bearer3GPP,
				security.DirectionUplink, payload[1:]); err != nil {
				return nil, fmt.Errorf("Encrypt error: %+v", err)
			}
		}

		// remove sequece Number
		payload = payload[1:]
		err = msg.PlainNasDecode(&payload)
		return msg, err
	}
}
