package nas_security

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

// VerifyIntegrity checks an initial NAS message against a copy of the uplink NAS COUNT: the stored
// COUNT is not written, so Decode then accepts the message, and its COUNT, once (TS 24.501 4.4.3.2).
func TestVerifyIntegrityLeavesUplinkCount(t *testing.T) {
	ue := newSecurityTestUE()
	ue.SecurityContextAvailable = true
	ue.ULCount.Set(0, 4)
	stored := ue.ULCount
	sender := message.NewSecCtx(message.UESide, message.Bearer3GPP,
		ie.AlgCiphering(ue.CipheringAlg), ie.AlgIntegrity(ue.IntegrityAlg), ue.KnasEnc[:], ue.KnasInt[:])
	sender.UplinkCount.Set(0, 5)
	serviceRequest, err := message.Marshal(&message.SvcReq{
		Ngksi: &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 1},
		// This spelling is the name exported by the NAS API.
		SvcType: &ie.SvcType{Value: ie.SvcType_Signalling}, //nolint:misspell
		TMSI5GS: &ie.MobileId5GS{TypeOfId: ie.IdType_5GS_TMSI, TMSI5G: [4]byte{0, 0, 0, 1}},
	}, sender, message.SecHdrTypeIntegrityProtected)
	require.NoError(t, err)

	for i := 0; i < 2; i++ {
		macVerified, verifyErr := VerifyIntegrity(ue, models.AccessType_3_GPP_ACCESS, serviceRequest, true)
		require.NoError(t, verifyErr)
		require.True(t, macVerified)
		require.Equal(t, stored, ue.ULCount)
	}

	forged := append([]byte(nil), serviceRequest...)
	forged[2] ^= 0xff
	macVerified, err := VerifyIntegrity(ue, models.AccessType_3_GPP_ACCESS, forged, true)
	require.NoError(t, err)
	require.False(t, macVerified)
	require.Equal(t, stored, ue.ULCount)

	_, integrityProtected, err := Decode(ue, models.AccessType_3_GPP_ACCESS, serviceRequest, true)
	require.NoError(t, err)
	require.True(t, integrityProtected)
	require.Equal(t, uint32(5), ue.ULCount.Get())
}
