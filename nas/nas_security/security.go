package nas_security

import (
	"encoding/hex"
	"fmt"
	"free5gc/lib/nas"
	"free5gc/lib/nas/security"
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
			ue.DLCount = 0
			ue.ULCountOverflow = 0
			ue.ULCountSQN = 0
		}

		sequenceNumber = uint8(ue.DLCount & 0xff)

		payload, err = msg.PlainNasEncode()
		if err != nil {
			logger.NasLog.Errorln("err", err)
			return
		}
		logger.NasLog.Traceln("ue.CipheringAlg", ue.CipheringAlg)
		logger.NasLog.Traceln("ue.GetSecurityDLCount()", ue.GetSecurityDLCount())
		logger.NasLog.Traceln("payload", payload)

		if err = security.NASEncrypt(ue.CipheringAlg, ue.KnasEnc, ue.GetSecurityDLCount(), security.SecurityBearer3GPP,
			security.SecurityDirectionDownlink, payload); err != nil {
			logger.NasLog.Errorln("err", err)
			return
		}

		// add sequece number
		payload = append([]byte{sequenceNumber}, payload[:]...)
		mac32 := make([]byte, 4)
		mac32, err = security.NASMacCalculate(ue.IntegrityAlg, ue.KnasInt, ue.GetSecurityDLCount(), security.SecurityBearer3GPP, security.SecurityDirectionDownlink, payload)
		if err != nil {
			logger.NasLog.Errorln("err", err)
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
		ue.DLCount = (ue.DLCount + 1) & 0xffffff

	}
	return
}

func Decode(ue *context.AmfUe, securityHeaderType uint8, payload []byte) (msg *nas.Message, err error) {

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
		err = msg.PlainNasDecode(&payload)
		return
	} else {
		if ue.IntegrityAlg == security.AlgIntegrity128NIA0 {
			logger.NasLog.Infoln("decode payload is ", payload)
			if ue.CipheringAlg == security.AlgCiphering128NEA0 {
				// remove header
				payload = payload[3:]
				err = msg.PlainNasDecode(&payload)
				return
			} else {
				err = fmt.Errorf("NIA0 is not vaild")
				return nil, err
			}
		}

		if securityHeaderType == nas.SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext || securityHeaderType == nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext {
			ue.ULCountOverflow = 0
			ue.ULCountSQN = 0
		}
		logger.NasLog.Traceln("securityHeaderType is ", securityHeaderType)
		securityHeader := payload[0:6]
		logger.NasLog.Traceln("securityHeader is ", securityHeader)
		sequenceNumber := payload[6]
		logger.NasLog.Traceln("sequenceNumber", sequenceNumber)
		if ue.ULCountSQN > sequenceNumber {
			ue.ULCountOverflow++
		}
		ue.ULCountSQN = sequenceNumber

		receivedMac32 := securityHeader[2:]
		// remove security Header except for sequece Number
		payload = payload[6:]

		mac32, err := security.NASMacCalculate(ue.IntegrityAlg, ue.KnasInt, ue.GetSecurityULCount(), security.SecurityBearer3GPP,
			security.SecurityDirectionUplink, payload)
		if err != nil {
			ue.MacFailed = true
			return nil, err
		}
		if !reflect.DeepEqual(mac32, receivedMac32) {
			logger.NasLog.Errorf("NAS MAC verification failed(0x%x != 0x%x)", mac32, receivedMac32)
			ue.MacFailed = true
			return nil, err
		} else {
			logger.NasLog.Traceln("cmac value: 0x\n", mac32)
		}

		// remove sequece Number
		payload = payload[1:]

		// TODO: Support for ue has nas connection in both accessType
		logger.NasLog.Traceln("ue.CipheringAlg", ue.CipheringAlg)
		if err = security.NASEncrypt(ue.CipheringAlg, ue.KnasEnc, ue.GetSecurityULCount(), security.SecurityBearer3GPP,
			security.SecurityDirectionUplink, payload); err != nil {
			return nil, err
		}
	}
	err = msg.PlainNasDecode(&payload)
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
