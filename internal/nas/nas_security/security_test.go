package nas_security

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/fsm"
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

// TS 24.501 4.4.4.3: until the secure exchange of NAS messages has been established, that is while the AMF
// authenticates the UE or runs the security mode control, it processes the messages of the clause's list that are not
// integrity protected; once it has been established, it discards them.
func TestDecodePlainMessagesBeforeSecureExchange(t *testing.T) {
	testCases := []struct {
		name  string
		state fsm.StateType
		msg   message.Message
	}{
		{
			name:  "authentication response",
			state: context.Authentication,
			msg:   &message.AuthRsp{AuthRspParam: &ie.AuthRspParam{Res: make([]byte, 16)}},
		},
		{
			name:  "identity response with the SUCI",
			state: context.Authentication,
			msg: &message.IdRsp{MobileId: &ie.MobileId5GS{
				TypeOfId:   ie.IdType_5GS_SUCI,
				PlmnId:     ie.PlmnId{MCC: "208", MNC: "93"},
				MSINLength: 10,
			}},
		},
		{
			name:  "security mode reject",
			state: context.SecurityMode,
			msg:   &message.SecModeRej{Cause5GMM: &ie.Cause5GMM{Value: ie.Cause5GMM_SecModeRejected}},
		},
		{
			name:  "deregistration request",
			state: context.SecurityMode,
			msg: &message.DeregReqUEOrig{
				DeregType: &ie.DeregType{AccessType: ie.AccessType_3gpp},
				Ngksi:     &ie.NASKeySetId{Ksi: ie.NASKeyNA},
				MobileId5GS: &ie.MobileId5GS{
					TypeOfId: ie.IdType_5GS_TMSI,
					TMSI5G:   [4]byte{0, 0, 0, 1},
				},
			},
		},
	}
	for _, tc := range testCases {
		payload, err := message.Marshal(tc.msg, nil, message.SecHdrTypePlainNas)
		require.NoError(t, err, tc.name)
		for _, state := range []fsm.StateType{tc.state, context.Registered} {
			ue := newSecurityTestUE()
			ue.SecurityContextAvailable = true
			ue.State = map[models.AccessType]*fsm.State{models.AccessType_3_GPP_ACCESS: fsm.NewState(state)}

			decoded, integrityProtected, decodeErr := Decode(ue, models.AccessType_3_GPP_ACCESS, payload, false)
			require.False(t, integrityProtected, tc.name)
			if state == tc.state {
				require.NoError(t, decodeErr, "a plain %s in the %s state", tc.name, state)
				require.IsType(t, tc.msg, decoded)
			} else {
				require.Error(t, decodeErr, "a plain %s after the secure exchange is established", tc.name)
			}
		}
	}
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
