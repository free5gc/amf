// +build !debug

package nas_security

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"free5gc/lib/nas"
	"free5gc/src/amf/context"
	"free5gc/src/amf/logger"
	"github.com/aead/cmac"
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

		if err = NasEncrypt(ue.CipheringAlg, ue.KnasEnc, ue.GetSecurityDLCount(), context.SECURITY_BEARER_3GPP,
			context.SECURITY_DIRECTION_DOWNLINK, payload); err != nil {
			logger.NasLog.Errorln("err", err)
			return
		}

		// add sequece number
		payload = append([]byte{sequenceNumber}, payload[:]...)
		mac32 := make([]byte, 4)
		mac32, err = NasMacCalculate(ue.IntegrityAlg, ue.KnasInt, ue.GetSecurityDLCount(), context.SECURITY_BEARER_3GPP, context.SECURITY_DIRECTION_DOWNLINK, payload)
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

		// ue.SecurityContextAvailable = true
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
	logger.NasLog.Traceln("securityHeaderType is ", securityHeaderType)
	if securityHeaderType == nas.SecurityHeaderTypePlainNas {
		err = msg.PlainNasDecode(&payload)
		return
	} else {
		if ue.IntegrityAlg == context.ALG_INTEGRITY_128_NIA0 {
			logger.NasLog.Infoln("decode payload is ", payload)
			if ue.CipheringAlg == context.ALG_CIPHERING_128_NEA0 {
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

		mac32, err := NasMacCalculate(ue.IntegrityAlg, ue.KnasInt, ue.GetSecurityULCount(), context.SECURITY_BEARER_3GPP,
			context.SECURITY_DIRECTION_UPLINK, payload)
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
		if err = NasEncrypt(ue.CipheringAlg, ue.KnasEnc, ue.GetSecurityULCount(), context.SECURITY_BEARER_3GPP,
			context.SECURITY_DIRECTION_UPLINK, payload); err != nil {
			return nil, err
		}
	}
	err = msg.PlainNasDecode(&payload)
	return
}

func NasEncrypt(AlgoID uint8, KnasEnc []byte, Count []byte, Bearer uint8, Direction uint8, plainText []byte) error {

	if len(KnasEnc) != 16 {
		return fmt.Errorf("Size of KnasEnc[%d] != 16 bytes)", len(KnasEnc))
	}
	if Bearer > 0x1f {
		return fmt.Errorf("Bearer is beyond 5 bits")
	}
	if Direction > 1 {
		return fmt.Errorf("Direction is beyond 1 bits")
	}
	if plainText == nil {
		return fmt.Errorf("Nas Payload is nil")
	}

	switch AlgoID {
	case context.ALG_CIPHERING_128_NEA0:
		logger.NgapLog.Warningln("ALG_CIPHERING is ALG_CIPHERING_128_NEA0")
		return nil
	case context.ALG_CIPHERING_128_NEA1:
		logger.NgapLog.Errorf("NEA1 not implement yet.")
		return nil
	case context.ALG_CIPHERING_128_NEA2:
		// Couter[0..32] | BEARER[0..4] | DIRECTION[0] | 0^26 | 0^64
		CouterBlk := make([]byte, 16)
		//First 32 bits are count
		copy(CouterBlk, Count)
		//Put Bearer and direction together
		CouterBlk[4] = (Bearer << 3) | (Direction << 2)

		block, err := aes.NewCipher(KnasEnc)
		if err != nil {
			return err
		}

		ciphertext := make([]byte, len(plainText))

		stream := cipher.NewCTR(block, CouterBlk)
		stream.XORKeyStream(ciphertext, plainText)
		// override plainText with cipherText
		copy(plainText, ciphertext)
		return nil

	case context.ALG_CIPHERING_128_NEA3:
		logger.NgapLog.Errorf("NEA3 not implement yet.")
		return nil
	default:
		return fmt.Errorf("Unknown Algorithm Identity[%d]", AlgoID)
	}

}

func NasMacCalculate(AlgoID uint8, KnasInt []byte, Count []byte, Bearer uint8, Direction uint8, msg []byte) ([]byte, error) {
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
	case context.ALG_INTEGRITY_128_NIA0:
		logger.NgapLog.Warningln("Integrity NIA0 is emergency.")
		return nil, nil
	case context.ALG_INTEGRITY_128_NIA1:
		logger.NgapLog.Errorf("NIA1 not implement yet.")
		return nil, nil
	case context.ALG_INTEGRITY_128_NIA2:
		// Couter[0..32] | BEARER[0..4] | DIRECTION[0] | 0^26
		m := make([]byte, len(msg)+8)
		//First 32 bits are count
		copy(m, Count)
		//Put Bearer and direction together
		m[4] = (Bearer << 3) | (Direction << 2)

		block, err := aes.NewCipher(KnasInt)
		if err != nil {
			return nil, err
		}

		copy(m[8:], msg)

		cmac, err := cmac.Sum(m, block, 16)
		if err != nil {
			return nil, err
		}
		// only get the most significant 32 bits to be mac value
		return cmac[:4], nil

	case context.ALG_INTEGRITY_128_NIA3:
		logger.NgapLog.Errorf("NIA3 not implement yet.")
		return nil, nil
	default:
		return nil, fmt.Errorf("Unknown Algorithm Identity[%d]", AlgoID)
	}

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
	case context.ALG_INTEGRITY_128_NIA1:
		logger.NgapLog.Errorf("NEA1 not implement yet.")
		return nil, nil
	case context.ALG_INTEGRITY_128_NIA2:
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

	case context.ALG_INTEGRITY_128_NIA3:
		logger.NgapLog.Errorf("NEA3 not implement yet.")
		return nil, nil
	default:
		return nil, fmt.Errorf("Unknown Algorithm Identity[%d]", AlgoID)
	}

}
