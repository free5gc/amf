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

func Encode(ue *context.AmfUe, msg *nas.Message, newSecurityContext bool) (payload []byte, err error) {
	var sequenceNumber uint8
	if ue == nil {
		err = fmt.Errorf("amfUe is nil")
		return
	}
	if msg == nil {
		err = fmt.Errorf("Nas Message is empty")
		return
	}

	if !ue.SecurityContextAvailable {
		return msg.PlainNasEncode()
	} else {
		if newSecurityContext {
			ue.ULCount.Set(0, 0)
			ue.DLCount.Set(0, 0)
		}

		sequenceNumber = ue.DLCount.SQN()

		payload, err = msg.PlainNasEncode()
		if err != nil {
			logger.NasLog.Errorln("err", err)
			return
		}
		logger.NasLog.Traceln("ue.CipheringAlg", ue.CipheringAlg)
		logger.NasLog.Traceln("ue.DLCount()", ue.DLCount.Get())
		logger.NasLog.Traceln("payload", payload)

		if err = security.NASEncrypt(ue.CipheringAlg, ue.KnasEnc, ue.DLCount.Get(), security.Bearer3GPP,
			security.DirectionDownlink, payload); err != nil {
			logger.NasLog.Errorln("err", err)
			return
		}

		// add sequece number
		payload = append([]byte{sequenceNumber}, payload[:]...)
		var mac32 []byte
		mac32, err = security.NASMacCalculate(ue.IntegrityAlg, ue.KnasInt, ue.DLCount.Get(), security.Bearer3GPP, security.DirectionDownlink, payload)
		if err != nil {
			logger.NasLog.Errorln("MAC calcuate error:", err)
			return
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
	}
	return
}

/*
payload either a security protected 5GS NAS message or a plain 5GS NAS message which
format is followed TS 24.501 9.1.1
*/
func Decode(ue *context.AmfUe, accessType models.AccessType, securityHeaderType uint8, payload []byte) (msg *nas.Message, err error) {

	if ue == nil {
		err = fmt.Errorf("amfUe is nil")
		return
	}
	if payload == nil {
		err = fmt.Errorf("Nas payload is empty")
		return
	}

	msg = new(nas.Message)
	msg.SecurityHeaderType = securityHeaderType
	logger.NasLog.Traceln("securityHeaderType is ", securityHeaderType)
	if securityHeaderType == nas.SecurityHeaderTypePlainNas {
		// RRCEstablishmentCause 0 is for emergency service
		if ue.SecurityContextAvailable && ue.RanUe[accessType].RRCEstablishmentCause != "0" {
			logger.NasLog.Warnln("Received Plain NAS message")
			err = fmt.Errorf("UE can not send plain nas for non-emergency service when there is a valid security context")
			return
		} else {
			err = msg.PlainNasDecode(&payload)
			ue.MacFailed = false
			return
		}
	} else { // security protected NAS message
		logger.NasLog.Traceln("securityHeaderType is ", securityHeaderType)
		securityHeader := payload[0:6]
		logger.NasLog.Traceln("securityHeader is ", securityHeader)
		sequenceNumber := payload[6]
		logger.NasLog.Traceln("sequenceNumber", sequenceNumber)

		receivedMac32 := securityHeader[2:]
		// remove security Header except for sequece Number
		payload = payload[6:]

		if securityHeaderType == nas.SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext || securityHeaderType == nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext {
			ue.ULCount.Set(0, 0)
		}

		if ue.ULCount.SQN() > sequenceNumber {
			ue.ULCount.SetOverflow(ue.ULCount.Overflow() + 1)
		}
		ue.ULCount.SetSQN(sequenceNumber)

		if ue.SecurityContextAvailable {
			mac32, err := security.NASMacCalculate(ue.IntegrityAlg, ue.KnasInt, ue.ULCount.Get(), security.Bearer3GPP,
				security.DirectionUplink, payload)
			if err != nil {
				ue.MacFailed = true
			}

			if !reflect.DeepEqual(mac32, receivedMac32) {
				logger.NasLog.Warnf("NAS MAC verification failed(received: 0x%08x, expected: 0x%08x)", receivedMac32, mac32)
				ue.MacFailed = true
			} else {
				logger.NasLog.Traceln("cmac value: 0x\n", mac32)
				ue.MacFailed = false
			}

			// TODO: Support for ue has nas connection in both accessType
			logger.NasLog.Traceln("ue.CipheringAlg", ue.CipheringAlg)
			if securityHeaderType != nas.SecurityHeaderTypeIntegrityProtected {
				// decrypt payload without sequence number (payload[1])
				if err = security.NASEncrypt(ue.CipheringAlg, ue.KnasEnc, ue.ULCount.Get(), security.Bearer3GPP,
					security.DirectionUplink, payload[1:]); err != nil {
					return nil, err
				}
			}
		} else {
			ue.MacFailed = true
		}

		// remove sequece Number
		payload = payload[1:]
		err = msg.PlainNasDecode(&payload)
	}
	return
}

func NasMacCalculateByAesCmac(AlgoID uint8, KnasInt []byte, Count []byte, Bearer uint8, Direction uint8, msg []byte, length int32) ([]byte, error) {
	if len(KnasInt) != 16 {
		return nil, fmt.Errorf("Size of KnasEnc[%d] != 16 bytes)", len(KnasInt))
	}
	if Bearer > 0x1f {
		return nil, fmt.Errorf("Bearer is beyond 5 bits")
	}
	if Direction > 1 {
		return nil, fmt.Errorf("Direction is beyond 1 bits")
	}
	if msg == nil {
		return nil, fmt.Errorf("Nas Payload is nil")
	}

	switch AlgoID {
	case security.AlgIntegrity128NIA0:
		logger.NgapLog.Errorf("NEA1 not implement yet.")
		return nil, nil
	case security.AlgIntegrity128NIA2:
		// Couter[0..32] | BEARER[0..4] | DIRECTION[0] | 0^26
		m := make([]byte, len(msg)+8)

		//First 32 bits are count
		copy(m, Count)
		//Put Bearer and direction together
		m[4] = (Bearer << 3) | (Direction << 2)
		copy(m[8:], msg)
		// var lastBitLen int32

		// lenM := (int32(len(m))) * 8 /* -  lastBitLen*/
		lenM := length
		// fmt.Printf("lenM %d\n", lastBitLen)
		// fmt.Printf("lenM %d\n", lenM)

		logger.NasLog.Debugln("NasMacCalculateByAesCmac", hex.Dump(m))
		logger.NasLog.Debugln("len(m) \n", len(m))

		cmac := make([]byte, 16)

		AesCmacCalculateBit(cmac, KnasInt, m, lenM)
		// only get the most significant 32 bits to be mac value
		return cmac[:4], nil

	case security.AlgIntegrity128NIA3:
		logger.NgapLog.Errorf("NEA3 not implement yet.")
		return nil, nil
	default:
		return nil, fmt.Errorf("Unknown Algorithm Identity[%d]", AlgoID)
	}
}
