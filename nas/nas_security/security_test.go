package nas_security_test

import (
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"free5gc/lib/CommonConsumerTestData/AMF/TestAmf"
	"free5gc/lib/nas"
	"free5gc/lib/nas/nasMessage"
	"free5gc/lib/nas/nasType"
	"free5gc/lib/openapi/models"
	"free5gc/src/amf/context"
	"free5gc/src/amf/handler"
	"free5gc/src/amf/nas/nas_security"
	ngap_message "free5gc/src/amf/ngap/message"
	"github.com/aead/cmac"
	"reflect"
	"strings"
	"testing"
)

func init() {
	go handler.Handle()

	TestAmf.SctpSever()

}

func TestMacCalculateTS33401(t *testing.T) {

	for i, testTable := range TestAmf.TestNIA2Table {
		key, err := hex.DecodeString(strings.Repeat(testTable.IK, 1))
		// fmt.Printf("%s", hex.Dump(key))
		if err != nil {
			t.Error(err.Error())
		}

		count, _ := hex.DecodeString(testTable.CountI)

		// fmt.Printf("%s", hex.Dump(count))
		var bearer uint8 = testTable.Bearer
		var direction uint8 = testTable.Direction
		msg, _ := hex.DecodeString(testTable.Message)

		length := testTable.Length

		// fmt.Printf("%s", hex.Dump(msg))
		if err != nil {
			t.Error(err.Error())
		}
		// mac1, err := nas_security.NasMacCalculate(amf_context.ALG_INTEGRITY_128_NIA2, key, count, bearer, direction, msg)
		// if err != nil {
		// 	t.Error(err.Error())
		// }
		expected, _ := hex.DecodeString(testTable.Expected)
		// if !reflect.DeepEqual(mac1, expected) {
		// 	t.Errorf("NIA2Test%s \t mac1[0x%x] \t expected[0x%x]\n", i, mac1, expected)
		// }

		mac2, err := nas_security.NasMacCalculateByAesCmac(amf_context.ALG_INTEGRITY_128_NIA2, key, count, bearer, direction, msg, length)
		// if err != nil {
		// 	t.Error(err.Error())
		// } else if !reflect.DeepEqual(mac1, mac2) {
		// 	// t.Errorf("mac1[0x%x]\nmac2[0x%x]", mac1, mac2)
		// }
		if !reflect.DeepEqual(mac2, expected) {
			t.Errorf("NIA2Test%s \t mac2[0x%x] \t expected[0x%x]\n", i, mac2, expected)
		}

	}

}

func TestMacCalculateNISTSP_800_38B(t *testing.T) {

	for i, testTable := range TestAmf.TestCMACAES128Table {
		KnasInt, err := hex.DecodeString(strings.Repeat(testTable.Key, 1))
		// fmt.Printf("%s", hex.Dump(key))
		if err != nil {
			t.Error(err.Error())
		}

		plainText, _ := hex.DecodeString(testTable.PlainText)

		lengthBlock := testTable.Mlen
		lengthBit := testTable.Mlen * 8
		cmacBlockResult := make([]byte, 16)
		cmacBitResult := make([]byte, 16)
		expected, _ := hex.DecodeString(testTable.Expected)

		nas_security.AesCmacCalculateBlock(cmacBlockResult, KnasInt, plainText, lengthBlock)
		nas_security.AesCmacCalculateBit(cmacBitResult, KnasInt, plainText, lengthBit)
		block, err := aes.NewCipher(KnasInt)

		aead_cmac, _ := cmac.Sum(plainText, block, 16)

		if !reflect.DeepEqual(aead_cmac[:4], expected) {
			t.Errorf("Example%s \t aead_cmac[0x%x] \t expected[0x%x]\n", i, aead_cmac, expected)
		}

		if !reflect.DeepEqual(cmacBlockResult[:4], expected) {
			t.Errorf("Example%s \t cmacBlockResult[0x%x] \t expected[0x%x]\n", i, cmacBlockResult, expected)
		}

		if !reflect.DeepEqual(cmacBitResult[:4], expected) {
			t.Errorf("Example%s \t cmacBitResult[0x%x] \t expected[0x%x]\n", i, cmacBitResult, expected)
		}
	}

}

func TestSecurity(t *testing.T) {
	TestAmf.AmfInit()
	TestAmf.SctpConnectToServer(models.AccessType__3_GPP_ACCESS)
	ue := TestAmf.TestAmf.UePool["imsi-2089300007487"]
	ue.DerivateAlgKey()
	ue.DLCount = 4
	m := getRegistrationComplete(nil)
	nasPdu, err := nas_security.Encode(ue, m)
	if err != nil {
		t.Error(err.Error())
	}
	ngap_message.SendDownlinkNasTransport(ue.RanUe[models.AccessType__3_GPP_ACCESS], nasPdu, nil)
	msg, err := ranDecode(ue, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, nasPdu)
	if err != nil {
		t.Error(err.Error())
	}
	if !reflect.DeepEqual(msg.GmmMessage.RegistrationComplete, m.GmmMessage.RegistrationComplete) {
		t.Errorf("Expect: %s\n Output: %s", TestAmf.Config.Sdump(m.GmmMessage.RegistrationComplete), TestAmf.Config.Sdump(msg.GmmMessage.RegistrationComplete))
	}

}

func getRegistrationComplete(sorTransparentContainer []uint8) *nas.Message {

	m := nas.NewMessage()
	m.SecurityHeader = nas.SecurityHeader{
		ProtocolDiscriminator: nasMessage.Epd5GSMobilityManagementMessage,
		SecurityHeaderType:    nas.SecurityHeaderTypeIntegrityProtectedAndCiphered,
	}
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeRegistrationComplete)

	registrationComplete := nasMessage.NewRegistrationComplete(0)
	registrationComplete.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	registrationComplete.SpareHalfOctetAndSecurityHeaderType.SetSpareHalfOctet(0)
	registrationComplete.RegistrationCompleteMessageIdentity.SetMessageType(nas.MsgTypeRegistrationComplete)

	if sorTransparentContainer != nil {
		registrationComplete.SORTransparentContainer = nasType.NewSORTransparentContainer(nasMessage.RegistrationCompleteSORTransparentContainerType)
		registrationComplete.SORTransparentContainer.SetLen(uint16(len(sorTransparentContainer)))
		registrationComplete.SORTransparentContainer.SetSORContent(sorTransparentContainer)
	}

	m.GmmMessage.RegistrationComplete = registrationComplete

	return m
}

func ranDecode(ue *amf_context.AmfUe, securityHeaderType uint8, payload []byte) (msg *nas.Message, err error) {

	integrityProtected := false
	newSecurityContext := false
	ciphering := false
	if ue == nil {
		err = fmt.Errorf("amfUe is nil")
		return
	}
	if payload == nil {
		err = fmt.Errorf("Nas payload is empty")
		return
	}

	switch securityHeaderType {
	case nas.SecurityHeaderTypePlainNas:
	case nas.SecurityHeaderTypeIntegrityProtected:
		integrityProtected = true
	case nas.SecurityHeaderTypeIntegrityProtectedAndCiphered:
		integrityProtected = true
		ciphering = true
	case nas.SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext:
		integrityProtected = true
		newSecurityContext = true
	case nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext:
		integrityProtected = true
		ciphering = true
		newSecurityContext = true
	default:
		return nil, fmt.Errorf("Security Type[%d] is not be implemented", securityHeaderType)
	}
	msg = new(nas.Message)

	if !ue.SecurityContextAvailable {
		integrityProtected = false
		newSecurityContext = false
		ciphering = false
	}
	if newSecurityContext {
		ue.ULCountOverflow = 0
		ue.ULCountSQN = 0
	}
	if ue.CipheringAlg == amf_context.ALG_CIPHERING_128_NEA0 {
		ciphering = false
	}
	if ue.IntegrityAlg == amf_context.ALG_INTEGRITY_128_NIA0 {
		integrityProtected = false
	}
	if ciphering || integrityProtected {
		securityHeader := payload[0:6]
		// sequenceNumber := payload[6]
		receivedMac32 := securityHeader[2:]
		// remove security Header except for sequece Number
		payload = payload[6:]

		var dlcount = make([]byte, 4)
		binary.BigEndian.PutUint16(dlcount, uint16((ue.DLCount-1)&0xffffff))
		if integrityProtected {
			mac32, err := nas_security.NasMacCalculate(ue.IntegrityAlg, ue.KnasInt, dlcount, amf_context.SECURITY_ONLY_ONE_BEARER,
				amf_context.SECURITY_DIRECTION_DOWNLINK, payload)
			if err != nil {
				ue.MacFailed = true
				return nil, err
			}
			if !reflect.DeepEqual(mac32, receivedMac32) {
				fmt.Printf("NAS MAC verification failed(0x%x != 0x%x)", mac32, receivedMac32)
				ue.MacFailed = true
			} else {
				fmt.Printf("cmac value: 0x%x\n", mac32)
			}
		}
		// remove sequece Number
		payload = payload[1:]

		if ciphering {
			// TODO: Support for ue has nas connection in both accessType

			if err = nas_security.NasEncrypt(ue.CipheringAlg, ue.KnasEnc, dlcount, amf_context.SECURITY_ONLY_ONE_BEARER,
				amf_context.SECURITY_DIRECTION_DOWNLINK, payload); err != nil {
				return
			}
		}
	}
	err = msg.PlainNasDecode(&payload)

	return
}

func TestAesCmac(t *testing.T) {
	// key, _ := hex.DecodeString(strings.Repeat("2bd6459f82c5b300952c49104881ff48", 1))
	key, _ := hex.DecodeString(strings.Repeat("2b7e151628aed2a6abf7158809cf4f3c", 1))

	nas_security.GenerateSubkey(key)
	// fb ee d6 18 35 71 33 66  7c 85 e0 8f 72 36 a8 de
	// fb ee d6 18 35 71 33 66  7c 85 e0 8f 72 36 a8 de
	// f7 dd ac 30 6a e2 66 cc  f9 0b c1 1e e4 6d 51 3b
	// f7 dd ac 30 6a e2 66 cc  f9 0b c1 1e e4 6d 51 3b
	return
}
