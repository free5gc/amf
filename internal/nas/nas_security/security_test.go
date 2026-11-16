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
	require.Equal(t, uint32(0), ue.ULCount.Get())
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

// TS 24.501 4.4.3.2: a given NAS COUNT value is accepted at most one time.
func TestDecodeRejectsReplayedUplinkCount(t *testing.T) {
	ue := newSecurityTestUE()
	ue.SecurityContextAvailable = true
	pduSessionReleaseRequest, err := (&message.PDUSessRelReq{PDUSessId: 5, PTI: 2}).MarshalBinary()
	require.NoError(t, err)
	ulNasTransport := &message.ULNASTransport{
		PayloadCntrType: &ie.PayloadCntrType{Value: ie.PayloadCntrType_N1SMInfo},
		PayloadCntr:     &ie.PayloadCntr{Pct: ie.PayloadCntrType_N1SMInfo, Contents: pduSessionReleaseRequest},
		PDUSessID:       &ie.PDUSessId2{Value: 5},
	}
	encode := func(count uint32) []byte {
		uplinkSecurity := message.NewSecCtx(
			message.UESide,
			message.Bearer3GPP,
			ie.AlgCiphering(ue.CipheringAlg),
			ie.AlgIntegrity(ue.IntegrityAlg),
			ue.KnasEnc[:],
			ue.KnasInt[:],
		)
		uplinkSecurity.UplinkCount.Set(uint16(count>>8), uint8(count))
		payload, marshalErr := message.Marshal(
			ulNasTransport, uplinkSecurity, message.SecHdrTypeIntegrityProtectedAndCiphered)
		require.NoError(t, marshalErr)
		return payload
	}
	atCount100 := encode(100)

	decoded, integrityProtected, err := Decode(ue, models.AccessType_3_GPP_ACCESS, atCount100, false)
	require.NoError(t, err)
	require.True(t, integrityProtected)
	require.IsType(t, &message.ULNASTransport{}, decoded)
	require.Equal(t, uint32(100), ue.ULCount.Get())

	_, integrityProtected, err = Decode(ue, models.AccessType_3_GPP_ACCESS, atCount100, false)
	require.Error(t, err)
	require.False(t, integrityProtected)
	require.Equal(t, uint32(100), ue.ULCount.Get())

	_, integrityProtected, err = Decode(ue, models.AccessType_3_GPP_ACCESS, encode(101), false)
	require.NoError(t, err)
	require.True(t, integrityProtected)
	require.Equal(t, uint32(101), ue.ULCount.Get())
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
