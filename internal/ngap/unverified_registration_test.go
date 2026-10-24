package ngap

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	business_metrics "github.com/free5gc/amf/internal/metrics/business"
	amf_nas "github.com/free5gc/amf/internal/nas"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	nas_message "github.com/free5gc/nas/message"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
	metrics_utils "github.com/free5gc/util/metrics/utils"
)

const (
	victimSupi = "imsi-208930000000001"
	otherSupi  = "imsi-208930000000002"
)

var (
	akaRand    = bytes.Repeat([]byte{0x11}, 16)
	akaAutn    = bytes.Repeat([]byte{0x44}, 16)
	akaResStar = bytes.Repeat([]byte{0x22}, 16)
)

// corePeers stands in for the NRF, AUSF, PCF, SMF and UDM over HTTP/2 cleartext and records each request.
// Its AUSF runs 5G AKA with one fixed vector: a UE that answers with akaResStar authenticates as supi.
type corePeers struct {
	*httptest.Server
	supi     string
	mu       sync.Mutex
	requests []string
}

func newCorePeers(t *testing.T, supi string) *corePeers {
	t.Helper()
	peers := &corePeers{supi: supi}
	hxresStar := sha256.Sum256(append(append([]byte(nil), akaRand...), akaResStar...))
	peers.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peers.mu.Lock()
		peers.requests = append(peers.requests, r.Method+" "+r.URL.Path)
		peers.mu.Unlock()
		status, body := http.StatusOK, ""
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/nnrf-disc/"):
			nfType := r.URL.Query().Get("target-nf-type")
			services := map[string][]string{
				"AUSF": {"nausf-auth"},
				"PCF":  {"npcf-am-policy-control"},
				// Its requests get 204 No Content, so a registration that reaches the UDM fails.
				"UDM": {"nudm-uecm", "nudm-sdm"},
			}[nfType]
			nfServices := make([]string, 0, len(services))
			for i, service := range services {
				nfServices = append(nfServices, `{"serviceInstanceId":"`+strconv.Itoa(i)+`","serviceName":"`+service+
					`","versions":[{"apiVersionInUri":"v1","apiFullVersion":"1.0.0"}],"scheme":"http",`+
					`"nfServiceStatus":"REGISTERED","apiPrefix":"`+peers.URL+`"}`)
			}
			body = `{"validityPeriod":100,"nfInstances":[{"nfInstanceId":"` + nfType + `-1","nfType":"` + nfType +
				`","nfStatus":"REGISTERED","nfServices":[` + strings.Join(nfServices, ",") + `]}]}`
		case r.Method == http.MethodPost && r.URL.Path == "/nausf-auth/v1/ue-authentications":
			status = http.StatusCreated
			w.Header().Set("Location", peers.URL+"/nausf-auth/v1/ue-authentications/ctx-1")
			body = `{"authType":"5G_AKA","5gAuthData":{"rand":"` + hex.EncodeToString(akaRand) +
				`","hxresStar":"` + hex.EncodeToString(hxresStar[16:]) + `","autn":"` + hex.EncodeToString(akaAutn) +
				`"},"_links":{"5g-aka":[{"href":"` + peers.URL +
				`/nausf-auth/v1/ue-authentications/ctx-1/5g-aka-confirmation"}]}}`
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/5g-aka-confirmation"):
			body = `{"authResult":"AUTHENTICATION_SUCCESS","supi":"` + peers.supi + `","kseaf":"` +
				strings.Repeat("33", 32) + `"}`
		case r.Method == http.MethodPost && r.URL.Path == "/npcf-am-policy-control/v1/policies":
			status = http.StatusCreated
			w.Header().Set("Location", peers.URL+"/npcf-am-policy-control/v1/policies/polassoc-new")
			body = `{"suppFeat":"0"}`
		default:
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if _, err := w.Write([]byte(body)); err != nil {
			t.Error(err)
		}
	}))
	peers.Config.Protocols = new(http.Protocols)
	peers.Config.Protocols.SetHTTP1(true)
	peers.Config.Protocols.SetUnencryptedHTTP2(true)
	peers.Start()
	t.Cleanup(peers.Close)
	return peers
}

// allRequests returns the requests made so far.
func (p *corePeers) allRequests() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.requests...)
}

// beyondAuthentication returns the requests made to other NFs than the NRF and the AUSF.
func (p *corePeers) beyondAuthentication() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var requests []string
	for _, request := range p.requests {
		if !strings.Contains(request, " /nnrf-disc/") && !strings.Contains(request, " /nausf-auth/") {
			requests = append(requests, request)
		}
	}
	return requests
}

// registeredVictim is bindingVictim with the state a mobility registration needs: a PEI, a default
// subscribed S-NSSAI, valid subscription data and PDU session 5 over 3GPP access.
func registeredVictim(t *testing.T, peers *corePeers) *amf_context.AmfUe {
	t.Helper()
	victim := bindingVictim(t, true)
	victim.Pei = "imeisv-4370816125816151"
	snssai := models.Snssai{Sst: 1, Sd: "010203"}
	victim.SubscribedNssai = []models.Nssf_NSSel_SubscribedSnssai{{SubscribedSnssai: &snssai, DefaultIndication: true}}
	victim.UESecurityCapability = ie.UESecCapability{Length: 2, EA05G: true, IA2_128_5G: true}
	victim.ContextValid = true
	smContext := amf_context.NewSmContext(5)
	smContext.SetAccessType(models.AccessType_3_GPP_ACCESS)
	smContext.SetSmfUri(peers.URL)
	smContext.SetSmContextRef("smctx-5")
	victim.StoreSmContext(5, smContext)
	t.Cleanup(victim.Remove)
	return victim
}

func unverifiedRegistrationRequest(registrationType uint8, identity ie.MobileId5GS) *nas_message.RegReq {
	return &nas_message.RegReq{
		RegType5GS:      &ie.RegType5GS{Value: registrationType},
		Ngksi:           &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 1},
		MobileId5GS:     &identity,
		Capability5GMM:  &ie.Capability5GMM{Length: 1},
		UESecCapability: &ie.UESecCapability{Length: 2, EA05G: true, IA2_128_5G: true},
		PDUSessStatus:   &ie.PDUSessStatus{Psi: ie.Psi{PSI: [16]bool{5: true}}},
	}
}

// staleProtected encodes msg integrity protected with a 5G NAS security context the AMF no longer has,
// as a UE does in the cases of TS 24.501 4.4.4.3 NOTE 3.
func staleProtected(t *testing.T, msg nas_message.Message) []byte {
	t.Helper()
	stale := nas_message.NewSecCtx(nas_message.UESide, nas_message.Bearer3GPP,
		nas_message.AlgCiphering128NEA2, nas_message.AlgIntegrity128NIA2, bindingKnasEnc[:], []byte{9, 9, 9, 9})
	stale.UplinkCount.Set(0, 5)
	b, err := nas_message.Marshal(msg, stale, nas_message.SecHdrTypeIntegrityProtected)
	require.NoError(t, err)
	return b
}

func plainNas(t *testing.T, msg nas_message.Message) []byte {
	t.Helper()
	b, err := msg.MarshalBinary()
	require.NoError(t, err)
	return b
}

// air is the radio side of one UE: the RAN it uses, the NGAP messages sent to it and, once the AMF
// has sent a SECURITY MODE COMMAND, the new 5G NAS security context.
type air struct {
	t     *testing.T
	conn  *ngaptesting.SctpConnStub
	ran   *amf_context.AmfRan
	ranUe *amf_context.RanUe
	seen  int
	ueSec *nas_message.SecCtx
	// downlinkSQN holds the NAS sequence number of each security protected downlink NAS message,
	// securityKey the security key of the last INITIAL CONTEXT SETUP REQUEST.
	downlinkSQN []uint8
	securityKey []byte
}

func newAir(t *testing.T, anType models.AccessType) *air {
	conn := new(ngaptesting.SctpConnStub)
	ran := NewAmfRan(conn)
	ran.AnType = anType
	return &air{t: t, conn: conn, ran: ran}
}

func (a *air) initialUEMessage(nasPdu []byte, fiveGSTmsi string, ueContextRequest bool) {
	message := BuildInitialUEMessage(a.t, 1, nasPdu, fiveGSTmsi)
	if ueContextRequest {
		message.UEContextRequest = &ngapType.UEContextRequest{Value: ngapType.UEContextRequestPresentRequested}
	}
	encoded, err := message.MarshalBinary()
	require.NoError(a.t, err)
	handleInitialUEMessageMain(a.ran, encoded, message.RANUENGAPID, message.NASPDU,
		message.UserLocationInformation, message.RRCEstablishmentCause, message.FiveGSTMSI, message.UEContextRequest)
	a.ranUe = a.ran.RanUeFindByRanUeNgapID(1)
	require.NotNil(a.t, a.ranUe)
}

func (a *air) uplink(nasPdu []byte) {
	amf_nas.HandleNAS(a.ranUe, ngapMessage.ProcedureCodeUplinkNASTransport, nasPdu, false)
}

// protected encodes msg as the UE does with the new 5G NAS security context.
func (a *air) protected(msg nas_message.Message, headerType nas_message.SecHdrType) []byte {
	b, err := nas_message.Marshal(msg, a.ueSec, headerType)
	require.NoError(a.t, err)
	return b
}

// sent returns the NGAP procedures and the NAS messages that the AMF has sent since the last call.
func (a *air) sent() ([]string, []nas_message.Message) {
	var procedures []string
	var nasMessages []nas_message.Message
	for ; a.seen < len(a.conn.MsgList); a.seen++ {
		decoded, err := ngapMessage.Parse(a.conn.MsgList[a.seen])
		require.NoError(a.t, err)
		var nasPdu []byte
		switch m := decoded.(type) {
		case *ngapMessage.DownlinkNASTransport:
			procedures = append(procedures, sentDLNAS)
			nasPdu = m.NASPDU.Value
		case *ngapMessage.InitialContextSetupRequest:
			procedures = append(procedures, sentICS)
			a.securityKey = m.SecurityKey.Value.Bytes
			if m.NASPDU != nil {
				nasPdu = m.NASPDU.Value
			}
		case *ngapMessage.UEContextReleaseCommand:
			procedures = append(procedures, sentRelease)
		default:
			procedures = append(procedures, "other")
		}
		if nasPdu == nil {
			continue
		}
		var security *nas_message.SecCtx
		if nas_message.GetSecHdrType(nasPdu) != nas_message.SecHdrTypePlainNas {
			require.NotNil(a.t, a.ueSec, "protected downlink NAS before the security mode command")
			a.downlinkSQN = append(a.downlinkSQN, nasPdu[nas_message.SecHdrLen-1])
			security = nas_message.NewSecCtx(nas_message.UESide, a.ueSec.Bearer,
				a.ueSec.CipheringAlg, a.ueSec.IntegrityAlg, a.ueSec.KnasEnc[:], a.ueSec.KnasInt[:])
		}
		nasMessage, err := nas_message.Parse(nasPdu, security)
		require.NoError(a.t, err)
		nasMessages = append(nasMessages, nasMessage)
	}
	return procedures, nasMessages
}

// authenticate answers the AMF's IDENTITY REQUEST (if any) and AUTHENTICATION REQUEST as the UE does and
// returns the SECURITY MODE COMMAND. resStar is the UE's answer to the challenge.
func (a *air) authenticate(resStar []byte) *nas_message.SecModeCmd {
	_, nasMessages := a.sent()
	require.NotEmpty(a.t, nasMessages)
	if nasMessages[0].MsgType() == nas_message.MsgTypeIdReq {
		a.uplink(plainNas(a.t, &nas_message.IdRsp{MobileId: &bindingSuci}))
		_, nasMessages = a.sent()
		require.NotEmpty(a.t, nasMessages)
	}
	authenticationRequest, ok := nasMessages[0].(*nas_message.AuthReq)
	require.True(a.t, ok, "expected AUTHENTICATION REQUEST, got %T", nasMessages[0])
	require.Equal(a.t, akaRand, authenticationRequest.AuthParamRAND5GAuthChlg.Rand)
	a.uplink(plainNas(a.t, &nas_message.AuthRsp{AuthRspParam: &ie.AuthRspParam{Res: resStar}}))
	if !bytes.Equal(resStar, akaResStar) {
		return nil
	}
	// The UE derives the same keys from KAMF; the test takes them from the AMF.
	amfUe := a.ranUe.AmfUe
	a.ueSec = nas_message.NewSecCtx(nas_message.UESide, nas_message.Bearer3GPP,
		ie.AlgCiphering(amfUe.CipheringAlg), ie.AlgIntegrity(amfUe.IntegrityAlg), amfUe.KnasEnc[:], amfUe.KnasInt[:])
	if a.ran.AnType == models.AccessType_NON_3_GPP_ACCESS {
		a.ueSec.Bearer = nas_message.BearerNon3GPP
	}
	_, nasMessages = a.sent()
	require.Len(a.t, nasMessages, 1)
	securityModeCommand, ok := nasMessages[0].(*nas_message.SecModeCmd)
	require.True(a.t, ok, "expected SECURITY MODE COMMAND, got %T", nasMessages[0])
	// With HDP set the UE would derive K'AMF from this KAMF (TS 24.501 5.4.2.3) and no longer share the
	// AMF's NAS keys: the AMF never derives K'AMF.
	require.False(a.t, securityModeCommand.Additional5GSecInfo.HDP, "KAMF derivation requested after authentication")
	return securityModeCommand
}

// contextSetupGauge enables the GMM state metrics and returns a reader of the number of UE contexts
// that the GMM state gauge counts in ContextSetup over anType.
func contextSetupGauge(t *testing.T, anType models.AccessType) func() float64 {
	t.Helper()
	metrics_utils.EnableBusinessMetrics()
	business_metrics.EnableGmmStateMetrics()
	registry := prometheus.NewRegistry()
	registry.MustRegister(business_metrics.GetGMMStatesHandlerMetrics("test")...)
	return func() float64 {
		families, err := registry.Gather()
		require.NoError(t, err)
		for _, family := range families {
			if !strings.HasSuffix(family.GetName(), business_metrics.GMM_STATE_GAUGE_NAME) {
				continue
			}
			for _, metric := range family.GetMetric() {
				labels := make(map[string]string)
				for _, label := range metric.GetLabel() {
					labels[label.GetName()] = label.GetValue()
				}
				if labels[business_metrics.GMM_STATE_ACCESS_TYPE_LABEL] == string(anType) &&
					labels[business_metrics.GMM_STATE_LABEL] == string(amf_context.ContextSetup) {
					return metric.GetGauge().GetValue()
				}
			}
		}
		return 0
	}
}

// TS 24.501 4.4.4.3: a REGISTRATION REQUEST that fails the integrity check against the UE context it
// names is authenticated, and the security mode control procedure takes a new 5G NAS security context
// into use, on a new UE context. Only a UE that authenticates as the subscriber of the named context
// continues its registration there; nothing else changes that context.
func TestUnverifiedRegistrationAuthenticatesBeforeTheFoundContext(t *testing.T) {
	previousConfig := factory.AmfConfig
	factory.AmfConfig = &factory.Config{Configuration: &factory.Configuration{}}
	t.Cleanup(func() { factory.AmfConfig = previousConfig })
	_, err := consumer.NewConsumer(nil)
	require.NoError(t, err)

	setUp := func(t *testing.T, ausfSupi string) (*corePeers, *amf_context.AmfUe) {
		peers := newCorePeers(t, ausfSupi)
		NewAmfContext(amf_context.GetSelf())
		amf_context.GetSelf().NrfUri = peers.URL
		return peers, registeredVictim(t, peers)
	}
	// newContext returns the UE context that the initial message was handled on, and stops its timers
	// when the test ends.
	newContext := func(t *testing.T, a *air, victim *amf_context.AmfUe) *amf_context.AmfUe {
		t.Helper()
		amfUe := a.ranUe.AmfUe
		require.NotNil(t, amfUe)
		require.NotSame(t, victim, amfUe, "attached to the found context before authentication")
		require.Same(t, victim, amfUe.AuthenticatingFor)
		t.Cleanup(amfUe.Remove)
		return amfUe
	}
	// requireUnchanged checks that the found context is as registeredVictim made it.
	requireUnchanged := func(t *testing.T, peers *corePeers, victim *amf_context.AmfUe) {
		t.Helper()
		stored, ok := amf_context.GetSelf().AmfUeFindBySupi(victimSupi)
		require.True(t, ok)
		require.Same(t, victim, stored)
		require.True(t, victim.State[models.AccessType_3_GPP_ACCESS].Is(amf_context.Registered))
		require.True(t, victim.SecurityContextAvailable)
		require.Equal(t, bindingKnasInt, victim.KnasInt)
		require.Equal(t, uint32(4), victim.ULCount.Get())
		require.Equal(t, "20893cafe0000000001", victim.Guti)
		require.Empty(t, victim.RanUe)
		require.NotNil(t, victim.T3513, "paging stopped")
		_, ok = victim.SmContextFindByPDUSessionID(5)
		require.True(t, ok)
		require.Empty(t, peers.beyondAuthentication())
	}

	for _, registration := range []struct {
		name string
		typ  uint8
	}{{"mobility", ie.RegType_MobilityRegUpdating}, {"periodic", ie.RegType_PeriodicRegUpdating}} {
		registrationType := registration.typ
		name := "the subscriber's " + registration.name + " registration continues on its context with its PDU sessions"
		t.Run(name, func(t *testing.T) {
			peers, victim := setUp(t, victimSupi)
			victimKn3iwf := bytes.Repeat([]byte{0x55}, 32)
			victim.Kn3iwf = victimKn3iwf
			contextSetup := contextSetupGauge(t, models.AccessType_3_GPP_ACCESS)
			inContextSetup := contextSetup()
			a := newAir(t, models.AccessType_3_GPP_ACCESS)
			request := unverifiedRegistrationRequest(registrationType, bindingGuti)
			if registrationType == ie.RegType_PeriodicRegUpdating {
				request.UESecCapability = nil // TS 24.501 8.2.6.4
			}
			a.initialUEMessage(staleProtected(t, request), bindingFiveGSTmsi, true)
			newUe := newContext(t, a, victim)
			securityModeCommand := a.authenticate(akaResStar)
			require.True(t, securityModeCommand.Additional5GSecInfo.RINMR)
			requireUnchanged(t, peers, victim)

			a.ueSec.UplinkCount.Set(0, 0)
			a.uplink(a.protected(&nas_message.SecModeComplete{
				NASMsgCntr: &ie.NASMsgCntr{Contents: plainNas(t, request)},
			}, nas_message.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx))

			require.Same(t, victim, a.ranUe.AmfUe)
			require.Same(t, a.ranUe, victim.RanUe[models.AccessType_3_GPP_ACCESS])
			// The stored context runs the registration as one that passed the integrity check.
			require.Equal(t, amf_context.OnGoingProcedureRegistration,
				victim.OnGoing(models.AccessType_3_GPP_ACCESS).Procedure)
			stored, ok := amf_context.GetSelf().AmfUeFindBySupi(victimSupi)
			require.True(t, ok)
			require.Same(t, victim, stored)
			require.Equal(t, newUe.KnasInt, victim.KnasInt)
			require.Equal(t, victimKn3iwf, victim.Kn3iwf, "AN key of the other access replaced")
			require.NotEqual(t, "20893cafe0000000001", victim.Guti, "no new 5G-GUTI")
			require.Nil(t, victim.T3513)
			procedures, nasMessages := a.sent()
			require.Equal(t, []string{sentICS}, procedures)
			registrationAccept, ok := nasMessages[0].(*nas_message.RegAccept)
			require.True(t, ok, "expected REGISTRATION ACCEPT, got %T", nasMessages[0])
			// The new 5G NAS security context continues: SECURITY MODE COMMAND at downlink NAS COUNT 0,
			// REGISTRATION ACCEPT at 1, and the KgNB derived from the new KAMF.
			require.Equal(t, []uint8{0, 1}, a.downlinkSQN)
			require.Equal(t, newUe.Kgnb, a.securityKey)
			require.True(t, registrationAccept.PDUSessStatus.PSI[5], "PDU session 5 not kept")
			require.Equal(t, victim.Guti, registrationAccept.GUTI5G.GUTIStr())
			require.Empty(t, peers.beyondAuthentication(), "PDU session or policy released")

			a.uplink(a.protected(&nas_message.RegComplete{}, nas_message.SecHdrTypeIntegrityProtectedAndCiphered))
			require.True(t, victim.State[models.AccessType_3_GPP_ACCESS].Is(amf_context.Registered))
			require.Nil(t, victim.T3550)
			_, ok = victim.SmContextFindByPDUSessionID(5)
			require.True(t, ok)
			// The new context left ContextSetup when the registration moved: no UE context is
			// counted there any more.
			require.True(t, newUe.State[models.AccessType_3_GPP_ACCESS].Is(amf_context.Deregistered))
			require.Equal(t, inContextSetup, contextSetup(), "GMM state gauge of ContextSetup")
		})
	}

	t.Run("a sender that fails authentication leaves the found context unchanged", func(t *testing.T) {
		peers, victim := setUp(t, victimSupi)
		a := newAir(t, models.AccessType_3_GPP_ACCESS)
		a.initialUEMessage(bindingNas(t, unverifiedRegistrationRequest(ie.RegType_MobilityRegUpdating, bindingGuti),
			"forged"), bindingFiveGSTmsi, false)
		newContext(t, a, victim)
		require.Nil(t, a.authenticate(bytes.Repeat([]byte{0x99}, 16)))

		procedures, nasMessages := a.sent()
		require.Equal(t, []string{sentDLNAS, sentRelease}, procedures)
		require.Equal(t, nas_message.MsgTypeAuthRej, nasMessages[0].MsgType())
		requireUnchanged(t, peers, victim)
	})

	t.Run("a periodic registration authenticated as another subscriber is rejected", func(t *testing.T) {
		peers, victim := setUp(t, otherSupi)
		other := amf_context.GetSelf().NewAmfUe(otherSupi)
		other.State[models.AccessType_3_GPP_ACCESS].Set(amf_context.Registered)
		other.SecurityContextAvailable = true
		t.Cleanup(other.Remove)
		otherGuti := other.Guti
		contextSetup := contextSetupGauge(t, models.AccessType_3_GPP_ACCESS)
		inContextSetup := contextSetup()
		a := newAir(t, models.AccessType_3_GPP_ACCESS)
		request := unverifiedRegistrationRequest(ie.RegType_PeriodicRegUpdating, bindingGuti)
		request.UESecCapability = nil
		a.initialUEMessage(plainNas(t, request), bindingFiveGSTmsi, false)
		newUe := newContext(t, a, victim)
		a.authenticate(akaResStar)
		a.ueSec.UplinkCount.Set(0, 0)
		a.uplink(a.protected(&nas_message.SecModeComplete{},
			nas_message.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx))

		procedures, nasMessages := a.sent()
		require.Equal(t, []string{sentDLNAS, sentRelease}, procedures)
		registrationReject, ok := nasMessages[0].(*nas_message.RegRej)
		require.True(t, ok, "expected REGISTRATION REJECT, got %T", nasMessages[0])
		require.Equal(t, ie.Cause5GMM_ImplicitlyDeregistered, registrationReject.Cause5GMM.Value)
		requireUnchanged(t, peers, victim)
		require.Empty(t, other.RanUe)
		require.Equal(t, otherGuti, other.Guti)
		require.True(t, newUe.State[models.AccessType_3_GPP_ACCESS].Is(amf_context.Deregistered))
		require.Equal(t, inContextSetup, contextSetup(), "GMM state gauge of ContextSetup")
	})

	for _, busy := range []struct {
		name        string
		set, revert func(victim *amf_context.AmfUe)
	}{
		{
			name: "in another GMM state",
			set: func(victim *amf_context.AmfUe) {
				victim.State[models.AccessType_3_GPP_ACCESS].Set(amf_context.DeregistrationInitiated)
			},
			revert: func(victim *amf_context.AmfUe) {
				victim.State[models.AccessType_3_GPP_ACCESS].Set(amf_context.Registered)
			},
		},
		{
			name: "in an N2 handover",
			set: func(victim *amf_context.AmfUe) {
				victim.SetOnGoing(models.AccessType_3_GPP_ACCESS,
					&amf_context.OnGoing{Procedure: amf_context.OnGoingProcedureN2Handover})
			},
			revert: func(victim *amf_context.AmfUe) {
				victim.SetOnGoing(models.AccessType_3_GPP_ACCESS,
					&amf_context.OnGoing{Procedure: amf_context.OnGoingProcedureNothing})
			},
		},
	} {
		t.Run("a mobility registration for a found context "+busy.name+" is rejected", func(t *testing.T) {
			peers, victim := setUp(t, victimSupi)
			contextSetup := contextSetupGauge(t, models.AccessType_3_GPP_ACCESS)
			inContextSetup := contextSetup()
			a := newAir(t, models.AccessType_3_GPP_ACCESS)
			request := unverifiedRegistrationRequest(ie.RegType_MobilityRegUpdating, bindingGuti)
			a.initialUEMessage(staleProtected(t, request), bindingFiveGSTmsi, false)
			newUe := newContext(t, a, victim)
			a.authenticate(akaResStar)
			busy.set(victim)
			a.ueSec.UplinkCount.Set(0, 0)
			a.uplink(a.protected(&nas_message.SecModeComplete{},
				nas_message.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx))

			procedures, nasMessages := a.sent()
			require.Equal(t, []string{sentDLNAS, sentRelease}, procedures)
			registrationReject, ok := nasMessages[0].(*nas_message.RegRej)
			require.True(t, ok, "expected REGISTRATION REJECT, got %T", nasMessages[0])
			require.Equal(t, ie.Cause5GMM_Congestion, registrationReject.Cause5GMM.Value)
			busy.revert(victim)
			requireUnchanged(t, peers, victim)
			require.True(t, newUe.State[models.AccessType_3_GPP_ACCESS].Is(amf_context.Deregistered))
			require.Equal(t, inContextSetup, contextSetup(), "GMM state gauge of ContextSetup")
		})
	}

	t.Run("the subscriber's initial registration replaces the 5GMM context of its access (PR 259)", func(t *testing.T) {
		peers, victim := setUp(t, victimSupi)
		a := newAir(t, models.AccessType_3_GPP_ACCESS)
		request := unverifiedRegistrationRequest(ie.RegType_InitialReg, bindingSuci)
		request.Ngksi = &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: ie.NASKeyNA}
		request.PDUSessStatus = nil
		a.initialUEMessage(plainNas(t, request), "", false)
		newContext(t, a, victim)
		a.authenticate(akaResStar)
		requireUnchanged(t, peers, victim)
		a.ueSec.UplinkCount.Set(0, 0)
		a.uplink(a.protected(&nas_message.SecModeComplete{
			NASMsgCntr: &ie.NASMsgCntr{Contents: plainNas(t, request)},
		}, nas_message.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx))

		require.Same(t, victim, a.ranUe.AmfUe)
		procedures, nasMessages := a.sent()
		require.Equal(t, []string{sentDLNAS}, procedures)
		require.Equal(t, nas_message.MsgTypeRegAccept, nasMessages[0].MsgType())
		a.uplink(a.protected(&nas_message.RegComplete{}, nas_message.SecHdrTypeIntegrityProtectedAndCiphered))
		// TS 24.501 5.5.1.2.8 f): the 5GMM context of the genuine UE is replaced, so its PDU
		// sessions over this access are released.
		require.Contains(t, peers.beyondAuthentication(), "POST /nsmf-pdusession/v1/sm-contexts/smctx-5/release")
		stored, ok := amf_context.GetSelf().AmfUeFindBySupi(victimSupi)
		require.True(t, ok)
		require.Same(t, victim, stored)
	})

	t.Run("an initial registration of a subscriber without a stored context continues on the new context",
		func(t *testing.T) {
			_, victim := setUp(t, victimSupi)
			a := newAir(t, models.AccessType_3_GPP_ACCESS)
			request := unverifiedRegistrationRequest(ie.RegType_InitialReg, bindingGuti)
			request.PDUSessStatus = nil
			a.initialUEMessage(staleProtected(t, request), "", false)
			newUe := newContext(t, a, victim)
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

			require.Same(t, newUe, a.ranUe.AmfUe)
			_, nasMessages := a.sent()
			require.Len(t, nasMessages, 1)
			require.Equal(t, nas_message.MsgTypeRegAccept, nasMessages[0].MsgType())
			stored, ok := amf_context.GetSelf().AmfUeFindBySupi(victimSupi)
			require.True(t, ok)
			require.Same(t, newUe, stored)
		})

	t.Run("the subscriber's initial registration over non-3GPP access keeps its 3GPP access (PR 274)",
		func(t *testing.T) {
			peers, victim := setUp(t, victimSupi)
			victimKgnb := bytes.Repeat([]byte{0x66}, 32)
			victim.Kgnb = victimKgnb
			a := newAir(t, models.AccessType_NON_3_GPP_ACCESS)
			request := unverifiedRegistrationRequest(ie.RegType_InitialReg, bindingSuci)
			request.PDUSessStatus = nil
			a.initialUEMessage(plainNas(t, request), "", false)
			newUe := newContext(t, a, victim)
			a.authenticate(akaResStar)
			a.ueSec.UplinkCount.Set(0, 0)
			a.uplink(a.protected(&nas_message.SecModeComplete{
				NASMsgCntr: &ie.NASMsgCntr{Contents: plainNas(t, request)},
			}, nas_message.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx))

			require.Same(t, victim, a.ranUe.AmfUe)
			require.Same(t, a.ranUe, victim.RanUe[models.AccessType_NON_3_GPP_ACCESS])
			procedures, _ := a.sent()
			// The REGISTRATION ACCEPT is sent once the N3IWF has set up the context.
			require.Equal(t, []string{sentICS}, procedures)
			require.NotNil(t, victim.RegistrationAcceptForNon3GPPAccess)
			require.Len(t, newUe.Kn3iwf, 32)
			require.Equal(t, newUe.Kn3iwf, victim.Kn3iwf)
			require.Equal(t, newUe.Kn3iwf, a.securityKey)
			require.Equal(t, victimKgnb, victim.Kgnb, "AN key of the 3GPP access replaced")
			require.True(t, victim.State[models.AccessType_3_GPP_ACCESS].Is(amf_context.Registered))
			_, ok := victim.SmContextFindByPDUSessionID(5)
			require.True(t, ok)
			for _, request := range peers.beyondAuthentication() {
				require.False(t, strings.HasPrefix(request, "DELETE") || strings.HasSuffix(request, "/release"),
					"3GPP access state released: %s", request)
			}
		})

	t.Run("the subscriber's mobility registration over non-3GPP access keeps the AN key of its 3GPP access",
		func(t *testing.T) {
			peers, victim := setUp(t, victimSupi)
			victimKgnb := bytes.Repeat([]byte{0x66}, 32)
			victim.Kgnb = victimKgnb
			victim.State[models.AccessType_NON_3_GPP_ACCESS].Set(amf_context.Registered)
			a := newAir(t, models.AccessType_NON_3_GPP_ACCESS)
			request := unverifiedRegistrationRequest(ie.RegType_MobilityRegUpdating, bindingGuti)
			request.PDUSessStatus = nil
			a.initialUEMessage(staleProtected(t, request), bindingFiveGSTmsi, true)
			newUe := newContext(t, a, victim)
			a.authenticate(akaResStar)
			a.ueSec.UplinkCount.Set(0, 0)
			a.uplink(a.protected(&nas_message.SecModeComplete{
				NASMsgCntr: &ie.NASMsgCntr{Contents: plainNas(t, request)},
			}, nas_message.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx))

			require.Same(t, victim, a.ranUe.AmfUe)
			require.Same(t, a.ranUe, victim.RanUe[models.AccessType_NON_3_GPP_ACCESS])
			procedures, _ := a.sent()
			// The REGISTRATION ACCEPT is sent once the N3IWF has set up the context.
			require.Equal(t, []string{sentICS}, procedures)
			require.NotNil(t, victim.RegistrationAcceptForNon3GPPAccess)
			require.Len(t, newUe.Kn3iwf, 32)
			require.Equal(t, newUe.Kn3iwf, a.securityKey)
			require.Equal(t, newUe.Kn3iwf, victim.Kn3iwf)
			require.Equal(t, victimKgnb, victim.Kgnb, "AN key of the 3GPP access replaced")
			require.True(t, victim.State[models.AccessType_3_GPP_ACCESS].Is(amf_context.Registered))
			_, ok := victim.SmContextFindByPDUSessionID(5)
			require.True(t, ok)
			require.Empty(t, peers.beyondAuthentication(), "PDU session or policy released")
		})
}
