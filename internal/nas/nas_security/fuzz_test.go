//go:build go1.18

package nas_security_test

import (
	"fmt"
	"reflect"
	"testing"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/amf/internal/nas/nas_security"
	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

func FuzzNASSecurity(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		// No security.
		ue := newFuzzTestAmfUe()
		//nolint:errcheck // Fuzzing intentionally feeds malformed messages.
		nas_security.Decode(ue, models.AccessType_3_GPP_ACCESS, data, true)

		// With security (NIA0/NEA0).
		ue = newFuzzTestAmfUe()
		ue.SecurityContextAvailable = true
		ue.IntegrityAlg = uint8(message.AlgIntegrity128NIA0)
		ue.CipheringAlg = uint8(message.AlgCiphering128NEA0)
		msg0, integrityProtected0, err0 := nas_security.Decode(
			ue, models.AccessType_3_GPP_ACCESS, data, true)

		if len(data) < int(message.SecHdrLen) {
			return
		}

		// Re-protect the same inner payload with NIA2/NEA2. If both decoders
		// accept it, the decoded NAS message and protection result must agree.
		ue = newFuzzTestAmfUe()
		ue.SecurityContextAvailable = true
		ue.IntegrityAlg = uint8(message.AlgIntegrity128NIA2)
		ue.CipheringAlg = uint8(message.AlgCiphering128NEA2)
		securityContext := message.NewSecCtx(
			message.UESide,
			message.Bearer3GPP,
			ie.AlgCiphering(ue.CipheringAlg),
			ie.AlgIntegrity(ue.IntegrityAlg),
			ue.KnasEnc[:],
			ue.KnasInt[:],
		)
		securityContext.UplinkCount.Set(0, data[6])

		packet := append([]byte(nil), data...)
		encrypted, err := securityContext.NASEncrypt(message.DirectionUplink, packet[7:])
		if err != nil {
			return
		}
		copy(packet[7:], encrypted)
		mac32, err := securityContext.NASMacCalculate(message.DirectionUplink, packet[6:])
		if err != nil {
			return
		}
		copy(packet[2:6], mac32)

		msg2, integrityProtected2, err2 := nas_security.Decode(
			ue, models.AccessType_3_GPP_ACCESS, packet, true)
		securityHeaderType := message.GetSecHdrType(packet)
		if err0 == nil && integrityProtected0 &&
			(securityHeaderType == message.SecHdrTypeIntegrityProtectedAndCiphered ||
				securityHeaderType == message.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx) {
			if err2 != nil {
				panic(fmt.Sprintf("err mismatch: %s", err2))
			}
			if !integrityProtected2 {
				panic("integrityProtected mismatch")
			}
			if !reflect.DeepEqual(msg0, msg2) {
				panic("msg mismatch")
			}
		}
	})
}

func newFuzzTestAmfUe() *amf_context.AmfUe {
	ue := new(amf_context.AmfUe)
	ue.RanUe = make(map[models.AccessType]*amf_context.RanUe)
	ue.RanUe[models.AccessType_3_GPP_ACCESS] = new(amf_context.RanUe)
	ue.RanUe[models.AccessType_3_GPP_ACCESS].SetAmfUe(ue)
	ue.RanUe[models.AccessType_3_GPP_ACCESS].Ran = new(amf_context.AmfRan)
	ue.RanUe[models.AccessType_3_GPP_ACCESS].Ran.AnType = models.AccessType_3_GPP_ACCESS
	ue.NASLog = logger.NasLog
	return ue
}
