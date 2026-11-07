package nas_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	amf_nas "github.com/free5gc/amf/internal/nas"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// TS 24.501 4.4.2.5: the AMF checks that the ngKSI of an initial NAS message belongs to a 5G NAS
// security context that it has. A REGISTRATION REQUEST or SERVICE REQUEST under another ngKSI fails
// the integrity check (4.4.4.3), even if its MAC verifies under the current keys.
func TestHandleNASInitialMessageUnderAnotherNgKsi(t *testing.T) {
	amfSelf, tai := setupFuzzAMF()
	var guti ie.MobileId5GS
	require.NoError(t, guti.UnmarshalBinary([]byte{0xf2, 0x02, 0xf8, 0x39, 0xca, 0xfe, 0x00, 0, 0, 0, 1}))
	initial, mobility := ie.RegType_InitialReg, ie.RegType_MobilityRegUpdating
	registration := func(regType uint8, tsc ie.SecCtxType, ksi uint8) message.Message {
		return &message.RegReq{
			RegType5GS:      &ie.RegType5GS{FOR_Pending: true, Value: regType},
			Ngksi:           &ie.NASKeySetId{Tsc: tsc, Ksi: ksi},
			MobileId5GS:     &guti,
			UESecCapability: &ie.UESecCapability{Length: 2, EA05G: true, IA2_128_5G: true},
		}
	}
	serviceRequest := func(ksi uint8) message.Message {
		return &message.SvcReq{
			Ngksi: &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: ksi},
			// This spelling is the name exported by the NAS API.
			SvcType: &ie.SvcType{Value: ie.SvcType_Signalling}, //nolint:misspell
			TMSI5GS: &ie.MobileId5GS{TypeOfId: ie.IdType_5GS_TMSI, TMSI5G: [4]byte{0, 0, 0, 1}},
		}
	}
	testCases := []struct {
		name           string
		msg            message.Message
		initialMessage bool
		macFailed      bool
	}{
		{"initial registration under the current ngKSI", registration(initial, ie.SecCtxTypeNative, 1), true, false},
		{"initial registration under another ngKSI", registration(initial, ie.SecCtxTypeNative, 6), true, true},
		{"initial registration under a mapped context", registration(initial, ie.SecCtxTypeMapped, 1), true, true},
		{"mobility registration under another ngKSI", registration(mobility, ie.SecCtxTypeNative, 6), true, true},
		{"service request under the current ngKSI", serviceRequest(1), true, false},
		{"service request under another ngKSI", serviceRequest(2), true, true},
		{"service request after the secure exchange is established", serviceRequest(2), false, false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conn := &ngaptesting.SctpConnStub{}
			ranUe := newFuzzRanUe(amfSelf, tai)
			ranUe.Ran.Conn = conn
			// The UE has no SUPI, so that the AMF asks for its identity instead of calling an AUSF.
			ue := ranUe.AmfUe
			ue.AttachRanUe(ranUe)
			ue.State[models.AccessType_3_GPP_ACCESS].Set(amf_context.Registered)
			ue.SecurityContextAvailable = true
			ue.NgKsi = models.Amf_Comm_NgKsi{Tsc: models.Amf_Comm_ScType_NATIVE, Ksi: 1}
			ue.CipheringAlg = uint8(message.AlgCiphering128NEA2)
			ue.IntegrityAlg = uint8(message.AlgIntegrity128NIA2)
			ue.KnasEnc = [16]byte{1, 2, 3, 4}
			ue.KnasInt = [16]byte{5, 6, 7, 8}
			ueSecurity := message.NewSecCtx(message.UESide, message.Bearer3GPP,
				ie.AlgCiphering(ue.CipheringAlg), ie.AlgIntegrity(ue.IntegrityAlg), ue.KnasEnc[:], ue.KnasInt[:])

			procedureCode := ngapMessage.ProcedureCodeUplinkNASTransport
			securityHeaderType := message.SecHdrTypeIntegrityProtectedAndCiphered
			if tc.initialMessage {
				procedureCode = ngapMessage.ProcedureCodeInitialUEMessage
				securityHeaderType = message.SecHdrTypeIntegrityProtected
			}
			payload, err := message.Marshal(tc.msg, ueSecurity, securityHeaderType)
			require.NoError(t, err)

			amf_nas.HandleNAS(ranUe, procedureCode, payload, tc.initialMessage)

			require.Equal(t, tc.macFailed, ue.MacFailed)
			switch tc.msg.(type) {
			case *message.RegReq:
				// RINMR in the SECURITY MODE COMMAND that follows the authentication
				require.Equal(t, tc.macFailed, ue.RetransmissionOfInitialNASMsg)
			case *message.SvcReq:
				answer := firstDownlinkNAS(t, conn, ueSecurity)
				if tc.macFailed {
					require.IsType(t, &message.SvcRej{}, answer)
					require.Equal(t, ie.Cause5GMM_UEIdCannotBeDerivedByTheNw,
						answer.(*message.SvcRej).Cause5GMM.Value)
				} else {
					require.IsType(t, &message.SvcAccept{}, answer)
				}
			}
		})
	}
}

// firstDownlinkNAS returns the NAS message of the first DOWNLINK NAS TRANSPORT sent on conn, as the UE reads it.
func firstDownlinkNAS(t *testing.T, conn *ngaptesting.SctpConnStub, ueSecurity *message.SecCtx) message.Message {
	t.Helper()
	for _, b := range conn.MsgList {
		pdu, err := ngapMessage.Parse(b)
		require.NoError(t, err)
		if transport, ok := pdu.(*ngapMessage.DownlinkNASTransport); ok {
			nasMsg, parseErr := message.Parse(transport.NASPDU.Value, ueSecurity)
			require.NoError(t, parseErr)
			return nasMsg
		}
	}
	require.FailNow(t, "no DOWNLINK NAS TRANSPORT sent")
	return nil
}
