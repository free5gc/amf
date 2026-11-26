package ngap

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	gmm_common "github.com/free5gc/amf/internal/gmm/common"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	nas_message "github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// concealedSuci builds an ECIES Profile A SUCI of PLMN 208-93 (routing indicator 0, home network
// public key identifier 1) whose ephemeral public key is 32 octets of fill. A UE computes a fresh
// SUCI each time (TS 33.501 6.12.4): a different fill gives a different SUCI of the same SUPI.
func concealedSuci(fill byte) ie.MobileId5GS {
	b := []byte{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x01, 0x01}
	b = append(b, bytes.Repeat([]byte{fill}, 32)...)       // ECC ephemeral public key
	b = append(b, 0x10, 0x32, 0x54, 0x76, 0x98)            // ciphertext of the MSIN
	b = append(b, bytes.Repeat([]byte{fill ^ 0x5a}, 8)...) // MAC tag
	return mobileIdentity5GSFromBytes(b)
}

// authenticateAnswering is air.authenticate with suci in the IDENTITY RESPONSE. It returns the
// SECURITY MODE COMMAND, or nil when the UE fails authentication.
func authenticateAnswering(a *air, suci ie.MobileId5GS, resStar []byte) *nas_message.SecModeCmd {
	a.t.Helper()
	_, nasMessages := a.sent()
	require.NotEmpty(a.t, nasMessages)
	if nasMessages[0].MsgType() == nas_message.MsgTypeIdReq {
		a.uplink(plainNas(a.t, &nas_message.IdRsp{MobileId: &suci}))
		_, nasMessages = a.sent()
		require.NotEmpty(a.t, nasMessages)
	}
	_, ok := nasMessages[0].(*nas_message.AuthReq)
	require.True(a.t, ok, "expected AUTHENTICATION REQUEST, got %T", nasMessages[0])
	a.uplink(plainNas(a.t, &nas_message.AuthRsp{AuthRspParam: &ie.AuthRspParam{Res: resStar}}))
	if !bytes.Equal(resStar, akaResStar) {
		return nil
	}
	amfUe := a.ranUe.GetAmfUe()
	a.ueSec = nas_message.NewSecCtx(nas_message.UESide, nas_message.Bearer3GPP,
		ie.AlgCiphering(amfUe.CipheringAlg), ie.AlgIntegrity(amfUe.IntegrityAlg), amfUe.KnasEnc[:], amfUe.KnasInt[:])
	_, nasMessages = a.sent()
	require.Len(a.t, nasMessages, 1)
	securityModeCommand, ok := nasMessages[0].(*nas_message.SecModeCmd)
	require.True(a.t, ok, "expected SECURITY MODE COMMAND, got %T", nasMessages[0])
	return securityModeCommand
}

// TS 24.501 5.5.1.2.8 f): the initial registration of a subscriber that the AMF already serves
// continues on the stored UE context once the UE has authenticated, whatever SUCI it sent. With
// Profile A/B the SUCI differs from the one the stored context has, so only the authenticated SUPI
// finds that context.
func TestConcealedSuciReconcilesStoredContext(t *testing.T) {
	previousConfig := factory.AmfConfig
	factory.AmfConfig = &factory.Config{Configuration: &factory.Configuration{}}
	t.Cleanup(func() { factory.AmfConfig = previousConfig })
	_, err := consumer.NewConsumer(nil)
	require.NoError(t, err)
	const access = models.AccessType_3_GPP_ACCESS
	const releaseRequest = "POST /nsmf-pdusession/v1/sm-contexts/smctx-5/release"
	storedSuci := concealedSuci(0xa1)
	freshSuci := concealedSuci(0xb2)
	unknownGuti := mobileIdentity5GSFromBytes([]uint8{0xf2, 0x02, 0xf8, 0x39, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x42})

	for _, scenario := range []struct {
		name string
		// identity is the identity of the REGISTRATION REQUEST; with the unknown 5G-GUTI the AMF
		// asks for the SUCI.
		identity ie.MobileId5GS
		ausfSupi string
		resStar  []byte
		resumes  bool
	}{
		{"identity response with a fresh concealed SUCI", unknownGuti, victimSupi, akaResStar, true},
		{"registration request with a fresh concealed SUCI", freshSuci, victimSupi, akaResStar, true},
		{"authentication failure", unknownGuti, victimSupi, bytes.Repeat([]byte{0xff}, 16), false},
		{"another subscriber", unknownGuti, otherSupi, akaResStar, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			peers := newCorePeers(t, scenario.ausfSupi)
			self := amf_context.GetSelf()
			NewAmfContext(self)
			self.NrfUri = peers.URL
			victim := registeredVictim(t, peers)
			victim.SetSuci(storedSuci.IdStr())
			old := newAir(t, access)
			oldRanUe, createErr := old.ran.NewRanUe(7)
			require.NoError(t, createErr)
			gmm_common.AttachRanUeToAmfUeAndReleaseOldIfAny(victim, oldRanUe)

			a := newAir(t, access)
			request := unverifiedRegistrationRequest(ie.RegType_InitialReg, scenario.identity)
			request.Ngksi = &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: ie.NASKeyNA}
			request.PDUSessStatus = nil
			a.initialUEMessage(plainNas(t, request), "", false)
			provisional := a.ranUe.GetAmfUe()
			require.NotSame(t, victim, provisional)
			require.Nil(t, provisional.AuthenticatingFor, "no stored context found by the SUCI")
			t.Cleanup(provisional.Remove)
			// Provide the same subscription data as the UDM would, isolating reconciliation.
			provisional.ContextValid = true
			provisional.Pei = victim.Pei
			provisional.SubscribedNssai = victim.SubscribedNssai

			unchanged := func() {
				t.Helper()
				require.Same(t, oldRanUe, victim.GetRanUe(access))
				require.Empty(t, old.conn.MsgList, "old connection released")
				require.Equal(t, storedSuci.IdStr(), victim.GetSuci())
				_, exists := victim.SmContextFindByPDUSessionID(5)
				require.True(t, exists)
				require.NotContains(t, peers.beyondAuthentication(), releaseRequest)
				stored, found := self.AmfUeFindBySupi(victimSupi)
				require.True(t, found)
				require.Same(t, victim, stored)
			}

			if authenticateAnswering(a, freshSuci, scenario.resStar) == nil {
				procedures, nasMessages := a.sent()
				require.Equal(t, []string{sentDLNAS, sentRelease}, procedures)
				require.Equal(t, nas_message.MsgTypeAuthRej, nasMessages[0].MsgType())
				unchanged()
				return
			}
			unchanged()
			a.ueSec.UplinkCount.Set(0, 0)
			a.uplink(a.protected(&nas_message.SecModeComplete{
				NASMsgCntr: &ie.NASMsgCntr{Contents: plainNas(t, request)},
			}, nas_message.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx))
			_, nasMessages := a.sent()
			require.Len(t, nasMessages, 1)
			require.Equal(t, nas_message.MsgTypeRegAccept, nasMessages[0].MsgType())

			if !scenario.resumes {
				require.Same(t, provisional, a.ranUe.GetAmfUe())
				unchanged()
				return
			}
			require.Same(t, victim, a.ranUe.GetAmfUe(), "registration must resume on the stored context")
			require.Same(t, a.ranUe, victim.GetRanUe(access))
			require.Equal(t, freshSuci.IdStr(), victim.GetSuci())
			require.Nil(t, oldRanUe.GetAmfUe())
			require.Len(t, old.conn.MsgList, 1)
			released, decodeErr := ngapMessage.Parse(old.conn.MsgList[0])
			require.NoError(t, decodeErr)
			require.IsType(t, &ngapMessage.UEContextReleaseCommand{}, released)

			a.uplink(a.protected(&nas_message.RegComplete{}, nas_message.SecHdrTypeIntegrityProtectedAndCiphered))
			require.Contains(t, peers.beyondAuthentication(), releaseRequest)
			_, exists := victim.SmContextFindByPDUSessionID(5)
			require.False(t, exists)
			stored, found := self.AmfUeFindBySupi(victimSupi)
			require.True(t, found)
			require.Same(t, victim, stored)
		})
	}
}
