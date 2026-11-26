package ngap

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	gmm_common "github.com/free5gc/amf/internal/gmm/common"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	nas_message "github.com/free5gc/nas/message"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// An unknown GUTI can resolve to a stored subscriber only after an Identity
// Response. Exercise authentication and security mode before reusing that context.
func TestIdentityResponseReconcilesStoredContext(t *testing.T) {
	previousConfig := factory.AmfConfig
	factory.AmfConfig = &factory.Config{Configuration: &factory.Configuration{}}
	t.Cleanup(func() { factory.AmfConfig = previousConfig })
	_, consumerErr := consumer.NewConsumer(nil)
	require.NoError(t, consumerErr)
	const access = models.AccessType_3_GPP_ACCESS
	const releaseRequest = "POST /nsmf-pdusession/v1/sm-contexts/smctx-5/release"
	const releaseFailure = "SMF release failure"
	const earlyRelease = "release before registration complete"

	for _, scenario := range []string{
		"release complete", "single access", "local reset", "idle subscriber",
		earlyRelease, releaseFailure,
		"authentication failure", "invalid security mode MAC", "different SUPI",
	} {
		t.Run(scenario, func(t *testing.T) {
			supi := victimSupi
			if scenario == "different SUPI" {
				supi = otherSupi
			}
			peers := newCorePeers(t, supi)
			self := amf_context.GetSelf()
			NewAmfContext(self)
			self.NrfUri = peers.URL
			victim := registeredVictim(t, peers)
			oldSession, exists := victim.SmContextFindByPDUSessionID(5)
			require.True(t, exists)
			var failedReleaseCalls atomic.Int32
			if scenario == releaseFailure {
				smf := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method+" "+r.URL.Path == releaseRequest {
						failedReleaseCalls.Add(1)
					}
					http.Error(w, "SMF unavailable", http.StatusServiceUnavailable)
				}))
				smf.Config.Protocols = new(http.Protocols)
				smf.Config.Protocols.SetHTTP1(true)
				smf.Config.Protocols.SetUnencryptedHTTP2(true)
				smf.Start()
				t.Cleanup(smf.Close)
				oldSession.SetSmfUri(smf.URL)
			}
			releaseCount := func() int {
				count := int(failedReleaseCalls.Load())
				for _, request := range peers.beyondAuthentication() {
					if request == releaseRequest {
						count++
					}
				}
				return count
			}
			policy := &models.Pcf_AMPolCtrl_PolicyAssociation{}
			victim.AmPolicyAssociation = policy
			victim.PolicyAssociationId = "existing-policy"
			victim.PcfUri = peers.URL
			old := newAir(t, access)
			var oldRanUe *amf_context.RanUe
			if scenario != "idle subscriber" {
				ranUe, createErr := old.ran.NewRanUe(7)
				require.NoError(t, createErr)
				oldRanUe = ranUe
				gmm_common.AttachRanUeToAmfUeAndReleaseOldIfAny(victim, oldRanUe)
			}
			var otherRanUe *amf_context.RanUe
			var otherSession *amf_context.SmContext
			if scenario != "single access" {
				other := newAir(t, models.AccessType_NON_3_GPP_ACCESS)
				ranUe, createErr := other.ran.NewRanUe(8)
				require.NoError(t, createErr)
				otherRanUe = ranUe
				victim.AttachRanUe(otherRanUe)
				otherSession = amf_context.NewSmContext(6)
				otherSession.SetAccessType(models.AccessType_NON_3_GPP_ACCESS)
				otherSession.SetSmfUri(peers.URL)
				otherSession.SetSmContextRef("smctx-6")
				victim.StoreSmContext(6, otherSession)
			}
			originalGuti := victim.GetGuti()

			a := newAir(t, access)
			unknownGuti := mobileIdentity5GSFromBytes([]uint8{
				0xf2, 0x02, 0xf8, 0x39, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x42,
			})
			request := unverifiedRegistrationRequest(ie.RegType_InitialReg, unknownGuti)
			request.Ngksi = &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: ie.NASKeyNA}
			request.PDUSessStatus = nil
			a.initialUEMessage(plainNas(t, request), "", false)
			provisional := a.ranUe.GetAmfUe()
			require.NotSame(t, victim, provisional)
			t.Cleanup(provisional.Remove)
			// Provide the same subscription data as UDM would, isolating reconciliation.
			provisional.ContextValid = true
			provisional.Pei = victim.Pei
			provisional.SubscribedNssai = victim.SubscribedNssai

			unchanged := func() {
				t.Helper()
				require.Zero(t, releaseCount(), "SMF session released without proof of ownership")
				require.True(t, oldRanUe == victim.GetRanUe(access))
				require.True(t, otherRanUe == victim.GetRanUe(models.AccessType_NON_3_GPP_ACCESS))
				require.Empty(t, old.conn.MsgList, "old connection released without proof of ownership")
				require.Equal(t, bindingKnasInt, victim.KnasInt)
				require.Equal(t, originalGuti, victim.GetGuti())
				require.Same(t, policy, victim.AmPolicyAssociation)
				_, sessionExists := victim.SmContextFindByPDUSessionID(5)
				require.True(t, sessionExists)
				stored, found := self.AmfUeFindBySupi(victimSupi)
				require.True(t, found)
				require.Same(t, victim, stored)
			}
			unchanged()
			res := akaResStar
			if scenario == "authentication failure" {
				res = bytes.Repeat([]byte{0xff}, 16)
			}
			a.authenticate(res) // Answers Identity Request with the stored subscriber's SUCI.
			unchanged()
			require.Empty(t, peers.beyondAuthentication())
			if scenario == "authentication failure" {
				return
			}
			a.ueSec.UplinkCount.Set(0, 0)
			complete := a.protected(&nas_message.SecModeComplete{
				NASMsgCntr: &ie.NASMsgCntr{Contents: plainNas(t, request)},
			}, nas_message.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx)
			if scenario == "invalid security mode MAC" {
				complete[2] ^= 0xff
			}
			a.uplink(complete)
			if scenario == "invalid security mode MAC" || scenario == "different SUPI" {
				unchanged()
				return
			}

			require.True(t, victim == a.ranUe.GetAmfUe(), "registration must resume on the stored context")
			require.Same(t, a.ranUe, victim.GetRanUe(access))
			require.True(t, otherRanUe == victim.GetRanUe(models.AccessType_NON_3_GPP_ACCESS))
			if oldRanUe != nil {
				require.Nil(t, oldRanUe.GetAmfUe())
				require.Len(t, old.conn.MsgList, 1)
				released, decodeErr := ngapMessage.Parse(old.conn.MsgList[0])
				require.NoError(t, decodeErr)
				require.IsType(t, &ngapMessage.UEContextReleaseCommand{}, released)
			}
			_, messages := a.sent()
			require.Len(t, messages, 1)
			require.IsType(t, &nas_message.RegAccept{}, messages[0])
			completeOldRelease := func() {
				t.Helper()
				dispatchMain(old.ran, &ngapMessage.UEContextReleaseComplete{
					AMFUENGAPID: &ngapType.AMFUENGAPID{Value: oldRanUe.AmfUeNgapId},
					RANUENGAPID: &ngapType.RANUENGAPID{Value: oldRanUe.RanUeNgapId},
				}, nil)
			}
			if scenario == earlyRelease {
				completeOldRelease()
			}
			// The stored session survives N2 release and security mode; existing
			// Initial Registration completion is responsible for releasing it.
			retained, exists := victim.SmContextFindByPDUSessionID(5)
			require.True(t, exists)
			require.Same(t, oldSession, retained)
			require.Zero(t, releaseCount())
			a.uplink(a.protected(&nas_message.RegComplete{}, nas_message.SecHdrTypeIntegrityProtectedAndCiphered))
			require.Equal(t, 1, releaseCount())
			retained, exists = victim.SmContextFindByPDUSessionID(5)
			if scenario == releaseFailure {
				require.True(t, exists, "failed SMF release must retain the session reference")
				require.Same(t, oldSession, retained)
			} else {
				require.False(t, exists)
			}
			retained, exists = victim.SmContextFindByPDUSessionID(6)
			if otherSession != nil {
				require.True(t, exists)
				require.Same(t, otherSession, retained)
			} else {
				require.False(t, exists)
			}
			require.NotContains(t, peers.beyondAuthentication(),
				"POST /nsmf-pdusession/v1/sm-contexts/smctx-6/release")

			if scenario == "local reset" {
				removeRan(old.ran)
			} else if oldRanUe != nil && scenario != earlyRelease {
				completeOldRelease()
			}
			if oldRanUe != nil {
				require.Nil(t, self.RanUeFindByAmfUeNgapID(oldRanUe.AmfUeNgapId))
			}
			stored, exists := self.AmfUeFindBySupi(victimSupi)
			require.True(t, exists)
			require.Same(t, victim, stored, "delayed old release removed the reused context")
			require.Same(t, a.ranUe, victim.GetRanUe(access))
			require.Equal(t, 1, releaseCount(), "old N2 cleanup must not release the session again")
			if scenario == releaseFailure {
				retained, exists = stored.SmContextFindByPDUSessionID(5)
				require.True(t, exists)
				require.Same(t, oldSession, retained)
			}
		})
	}
}
