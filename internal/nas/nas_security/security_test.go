package nas_security

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

func TestEncodeNewSecurityContextResetsBothCounts(t *testing.T) {
	ue := newSecurityTestUE()
	ue.SecurityContextAvailable = true
	ue.ULCount.Set(3, 9)
	ue.DLCount.Set(4, 10)

	payload, err := Encode(
		ue,
		&message.Status5GMM{Cause5GMM: &ie.Cause5GMM{Value: ie.Cause5GMM_ProtError}},
		models.AccessType_3_GPP_ACCESS,
		message.SecHdrTypeIntegrityProtectedWithNew5gNasSecCtx,
	)
	require.NoError(t, err)
	require.Equal(t, message.SecHdrTypeIntegrityProtectedWithNew5gNasSecCtx,
		message.GetSecHdrType(payload))
	require.Equal(t, uint32(0), ue.ULCount.Get())
	require.Equal(t, uint32(1), ue.DLCount.Get())
}

func TestDecodeIntegrityProtectedServiceRequest(t *testing.T) {
	ue := newSecurityTestUE()
	ue.SecurityContextAvailable = true
	uplinkSecurity := message.NewSecCtx(
		message.UESide,
		message.Bearer3GPP,
		ie.AlgCiphering(ue.CipheringAlg),
		ie.AlgIntegrity(ue.IntegrityAlg),
		ue.KnasEnc[:],
		ue.KnasInt[:],
	)
	serviceRequest := &message.SvcReq{
		Ngksi: &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 1},
		// This spelling is the name exported by the NAS API.
		SvcType: &ie.SvcType{Value: ie.SvcType_Signalling}, //nolint:misspell
		TMSI5GS: &ie.MobileId5GS{
			TypeOfId: ie.IdType_5GS_TMSI,
			TMSI5G:   [4]byte{0, 0, 0, 1},
		},
	}
	payload, err := message.Marshal(
		serviceRequest, uplinkSecurity, message.SecHdrTypeIntegrityProtected)
	require.NoError(t, err)

	decoded, integrityProtected, err := Decode(
		ue, models.AccessType_3_GPP_ACCESS, payload, true)
	require.NoError(t, err)
	require.True(t, integrityProtected)
	require.IsType(t, &message.SvcReq{}, decoded)
	require.Equal(t, uint32(1), ue.ULCount.Get())
}

func TestDecodeRejectsReplayedUplinkCount(t *testing.T) {
	ue := newSecurityTestUE()
	ue.SecurityContextAvailable = true
	ue.ULCount.Set(0, 100)

	sender := message.NewSecCtx(
		message.UESide,
		message.Bearer3GPP,
		ie.AlgCiphering(ue.CipheringAlg),
		ie.AlgIntegrity(ue.IntegrityAlg),
		ue.KnasEnc[:],
		ue.KnasInt[:],
	)
	sender.UplinkCount.Set(0, 100)
	release := &message.PDUSessRelReq{PDUSessId: 5, PTI: 2}
	payload, err := message.Marshal(
		release, sender, message.SecHdrTypeIntegrityProtectedAndCiphered)
	require.NoError(t, err)

	decoded, integrityProtected, err := Decode(
		ue, models.AccessType_3_GPP_ACCESS, payload, false)
	require.NoError(t, err)
	require.True(t, integrityProtected)
	require.IsType(t, &message.PDUSessRelReq{}, decoded)
	require.Equal(t, uint32(101), ue.ULCount.Get())

	_, _, err = Decode(ue, models.AccessType_3_GPP_ACCESS, payload, false)
	require.Error(t, err)
	require.Equal(t, uint32(101), ue.ULCount.Get())
}

func TestDecodeCipheredMACFailureRestoresCount(t *testing.T) {
	ue := newSecurityTestUE()
	ue.SecurityContextAvailable = true
	ue.ULCount.Set(2, 7)
	uplinkSecurity := message.NewSecCtx(
		message.UESide,
		message.Bearer3GPP,
		ie.AlgCiphering(ue.CipheringAlg),
		ie.AlgIntegrity(ue.IntegrityAlg),
		ue.KnasEnc[:],
		ue.KnasInt[:],
	)
	uplinkSecurity.UplinkCount.Set(2, 8)
	status := &message.Status5GMM{
		Cause5GMM: &ie.Cause5GMM{Value: ie.Cause5GMM_ProtError},
	}
	payload, err := message.Marshal(
		status, uplinkSecurity, message.SecHdrTypeIntegrityProtectedAndCiphered)
	require.NoError(t, err)
	payload[2] ^= 0xff

	_, integrityProtected, err := Decode(
		ue, models.AccessType_3_GPP_ACCESS, payload, false)
	require.Error(t, err)
	require.False(t, integrityProtected)
	require.Equal(t, uint32(2<<8|7), ue.ULCount.Get())
}

func newSecurityTestUE() *context.AmfUe {
	ue := &context.AmfUe{
		CipheringAlg: uint8(message.AlgCiphering128NEA2),
		IntegrityAlg: uint8(message.AlgIntegrity128NIA2),
		KnasEnc:      [16]byte{1, 2, 3, 4},
		KnasInt:      [16]byte{5, 6, 7, 8},
		NASLog:       logrus.NewEntry(logrus.New()),
	}
	return ue
}
