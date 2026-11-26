package ngap

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	nas_message "github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

const (
	createAMPolicyRequest   = "POST /npcf-am-policy-control/v1/policies"
	deleteStoredPolicy      = "DELETE /npcf-am-policy-control/v1/policies/existing-policy"
	storedPolicyAssociation = "existing-policy"
)

// amPolicyRequests returns the requests made to the PCF's AM policy control service.
func amPolicyRequests(peers *corePeers) []string {
	var requests []string
	for _, request := range peers.allRequests() {
		if strings.Contains(request, " /npcf-am-policy-control/") {
			requests = append(requests, request)
		}
	}
	return requests
}

// TS 24.501 5.5.1.2.8 f): an initial registration that continues on the stored UE context replaces the
// 5GMM context of its access. The AM policy association of the replaced registration is deleted
// (TS 29.507 4.2.5) before a new one is established (TS 23.502 4.16.1.2), instead of being overwritten
// and left at the PCF. While the UE stays registered over the other access, its association is kept.
func TestInitialRegistrationReplacesAMPolicyAssociation(t *testing.T) {
	previousConfig := factory.AmfConfig
	factory.AmfConfig = &factory.Config{Configuration: &factory.Configuration{}}
	t.Cleanup(func() { factory.AmfConfig = previousConfig })
	_, err := consumer.NewConsumer(nil)
	require.NoError(t, err)

	setUp := func(t *testing.T, withAssociation bool) (*corePeers, *amf_context.AmfUe) {
		peers := newCorePeers(t, victimSupi)
		NewAmfContext(amf_context.GetSelf())
		amf_context.GetSelf().NrfUri = peers.URL
		victim := registeredVictim(t, peers)
		if withAssociation {
			victim.PcfId = "PCF-1"
			victim.PcfUri = peers.URL
			victim.AmPolicyUri = peers.URL + "/npcf-am-policy-control/v1/policies/" + storedPolicyAssociation
			victim.PolicyAssociationId = storedPolicyAssociation
			victim.AmPolicyAssociation = &models.Pcf_AMPolCtrl_PolicyAssociation{SuppFeat: "0"}
		}
		return peers, victim
	}
	// register runs an initial registration with the stored context's SUCI over anType up to the
	// SECURITY MODE COMPLETE, checks that it continued on the stored context, and returns the UE side.
	register := func(t *testing.T, anType models.AccessType, victim *amf_context.AmfUe) *air {
		t.Helper()
		a := newAir(t, anType)
		request := unverifiedRegistrationRequest(ie.RegType_InitialReg, bindingSuci)
		request.Ngksi = &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: ie.NASKeyNA}
		request.PDUSessStatus = nil
		a.initialUEMessage(plainNas(t, request), "", false)
		newUe := a.ranUe.GetAmfUe()
		require.NotSame(t, victim, newUe)
		require.Same(t, victim, newUe.AuthenticatingFor)
		t.Cleanup(newUe.Remove)
		a.authenticate(akaResStar)
		a.ueSec.UplinkCount.Set(0, 0)
		a.uplink(a.protected(&nas_message.SecModeComplete{
			NASMsgCntr: &ie.NASMsgCntr{Contents: plainNas(t, request)},
		}, nas_message.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx))
		require.Same(t, victim, a.ranUe.GetAmfUe(), "registration did not continue on the stored context")
		return a
	}

	t.Run("an initial registration on the stored context replaces its association", func(t *testing.T) {
		peers, victim := setUp(t, true)
		a := register(t, models.AccessType_3_GPP_ACCESS, victim)
		_, nasMessages := a.sent()
		require.Len(t, nasMessages, 1)
		require.Equal(t, nas_message.MsgTypeRegAccept, nasMessages[0].MsgType())
		a.uplink(a.protected(&nas_message.RegComplete{}, nas_message.SecHdrTypeIntegrityProtectedAndCiphered))

		require.Equal(t, []string{deleteStoredPolicy, createAMPolicyRequest}, amPolicyRequests(peers))
		require.Equal(t, "polassoc-new", victim.PolicyAssociationId)
		// The 5GMM context of the access is replaced as well (TS 24.501 5.5.1.2.8 f)).
		require.Contains(t, peers.beyondAuthentication(), "POST /nsmf-pdusession/v1/sm-contexts/smctx-5/release")
	})

	t.Run("an association the PCF no longer has is replaced", func(t *testing.T) {
		peers, victim := setUp(t, true)
		// The PCF that created the association lost it (e.g. it restarted): DELETE gets 404.
		var mu sync.Mutex
		var lost []string
		lostPCF := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			lost = append(lost, r.Method+" "+r.URL.Path)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusNotFound)
			if _, writeErr := w.Write([]byte(`{"status":404,"cause":"CONTEXT_NOT_FOUND"}`)); writeErr != nil {
				t.Error(writeErr)
			}
		}))
		lostPCF.Config.Protocols = new(http.Protocols)
		lostPCF.Config.Protocols.SetHTTP1(true)
		lostPCF.Config.Protocols.SetUnencryptedHTTP2(true)
		lostPCF.Start()
		t.Cleanup(lostPCF.Close)
		victim.PcfUri = lostPCF.URL
		register(t, models.AccessType_3_GPP_ACCESS, victim)

		mu.Lock()
		require.Equal(t, []string{deleteStoredPolicy}, lost)
		mu.Unlock()
		require.Equal(t, []string{createAMPolicyRequest}, amPolicyRequests(peers))
		require.Equal(t, "polassoc-new", victim.PolicyAssociationId)
		require.Equal(t, peers.URL, victim.PcfUri)
	})

	t.Run("an initial registration over non-3GPP access keeps the association while 3GPP access is registered",
		func(t *testing.T) {
			peers, victim := setUp(t, true)
			a := register(t, models.AccessType_NON_3_GPP_ACCESS, victim)
			procedures, _ := a.sent()
			// The REGISTRATION ACCEPT is sent once the N3IWF has set up the context.
			require.Equal(t, []string{sentICS}, procedures)
			require.True(t, victim.State[models.AccessType_3_GPP_ACCESS].Is(amf_context.Registered))

			// The PCF looks AM policies up by access type: the 3GPP access still needs its association.
			require.Equal(t, []string{createAMPolicyRequest}, amPolicyRequests(peers))
		})

	t.Run("a stored context without an association creates one", func(t *testing.T) {
		peers, victim := setUp(t, false)
		a := register(t, models.AccessType_3_GPP_ACCESS, victim)
		_, nasMessages := a.sent()
		require.Len(t, nasMessages, 1)
		require.Equal(t, nas_message.MsgTypeRegAccept, nasMessages[0].MsgType())

		require.Equal(t, []string{createAMPolicyRequest}, amPolicyRequests(peers))
		require.Equal(t, "polassoc-new", victim.PolicyAssociationId)
	})

	t.Run("an initial registration of a subscriber without a stored context creates one", func(t *testing.T) {
		peers, victim := setUp(t, true)
		a := newAir(t, models.AccessType_3_GPP_ACCESS)
		request := unverifiedRegistrationRequest(ie.RegType_InitialReg, bindingGuti)
		request.PDUSessStatus = nil
		a.initialUEMessage(staleProtected(t, request), "", false)
		newUe := a.ranUe.GetAmfUe()
		require.NotSame(t, victim, newUe)
		t.Cleanup(newUe.Remove)
		a.authenticate(akaResStar)
		victim.Remove() // e.g. deregistered meanwhile
		// The subscription data the UDM would provide, so that the registration completes here.
		newUe.ContextValid = true
		newUe.Pei = victim.Pei
		newUe.SubscribedNssai = victim.SubscribedNssai
		a.ueSec.UplinkCount.Set(0, 0)
		a.uplink(a.protected(&nas_message.SecModeComplete{
			NASMsgCntr: &ie.NASMsgCntr{Contents: plainNas(t, request)},
		}, nas_message.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx))

		require.Same(t, newUe, a.ranUe.GetAmfUe())
		_, nasMessages := a.sent()
		require.Len(t, nasMessages, 1)
		require.Equal(t, nas_message.MsgTypeRegAccept, nasMessages[0].MsgType())
		require.Equal(t, []string{createAMPolicyRequest}, amPolicyRequests(peers))
		require.Equal(t, "polassoc-new", newUe.PolicyAssociationId)
	})
}
