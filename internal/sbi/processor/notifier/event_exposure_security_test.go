package callback

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/openapi/models"
)

func TestIsDisallowedNotifyHost(t *testing.T) {
	cases := []struct {
		name       string
		host       string
		disallowed bool
	}{
		{"loopback literal", "127.0.0.1", true},
		{"loopback hostname", "localhost", true},
		{"rfc1918", "10.0.0.5", true},
		{"link-local / cloud metadata", "169.254.169.254", true},
		{"unspecified", "0.0.0.0", true},
		{"public literal", "8.8.8.8", false},
		{"empty host", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isDisallowedNotifyHost(c.host); got != c.disallowed {
				t.Errorf("isDisallowedNotifyHost(%q) = %v, want %v", c.host, got, c.disallowed)
			}
		})
	}
}

type fakeApp struct {
	ctx *amf_context.AMFContext
	cfg *factory.Config
}

func (f *fakeApp) SetLogEnable(bool)                {}
func (f *fakeApp) SetLogLevel(string)               {}
func (f *fakeApp) SetReportCaller(bool)             {}
func (f *fakeApp) Start()                           {}
func (f *fakeApp) Terminate()                       {}
func (f *fakeApp) Context() *amf_context.AMFContext { return f.ctx }
func (f *fakeApp) Config() *factory.Config          { return f.cfg }

// newTestConsumer makes consumer.GetConsumer() return a live Consumer, so
// verifyNotifyHostAgainstNrf's SendSearchNFInstances call has something to
// run on. amfSelf is shared, global, process-wide state (context.GetSelf()
// always returns the same *AMFContext); callers must not run in parallel
// with anything else that reads or writes it.
func newTestConsumer(t *testing.T, amfSelf *amf_context.AMFContext) {
	t.Helper()
	_, err := consumer.NewConsumer(&fakeApp{
		ctx: amfSelf,
		cfg: &factory.Config{Configuration: &factory.Configuration{}},
	})
	if err != nil {
		t.Fatalf("NewConsumer: %v", err)
	}
}

const testNfId = "22221155-70de-4c1f-a7c4-8d7b7e297876"

// fakeNrfServer speaks h2c (HTTP/2 over cleartext): the generated NRF
// discovery client sends an HTTP/2 preface unconditionally, which a plain
// httptest.NewServer (HTTP/1.1) can't parse ("frame too large").
func fakeNrfServer(t *testing.T, profile *models.Nrf_NFDisc_NFProfile) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(models.Nrf_NFDisc_SearchResult{
			NfInstances: []models.Nrf_NFDisc_NFProfile{*profile},
		}); err != nil {
			t.Errorf("encoding fake NRF response: %v", err)
		}
	})
	server := httptest.NewServer(h2c.NewHandler(handler, &http2.Server{}))
	t.Cleanup(server.Close)
	return server
}

func TestVerifyNotifyHostAgainstNrf(t *testing.T) {
	amfSelf := amf_context.GetSelf()
	profile := models.Nrf_NFDisc_NFProfile{
		NfInstanceId:  testNfId,
		NfType:        models.Nrf_NFMgmt_NFType_PCF,
		Ipv4Addresses: []string{"203.0.113.10"},
	}
	server := fakeNrfServer(t, &profile)
	amfSelf.NrfUri = server.URL
	newTestConsumer(t, amfSelf)

	t.Run("matching ipv4 address is allowed", func(t *testing.T) {
		if !verifyNotifyHostAgainstNrf(testNfId, models.Nrf_NFMgmt_NFType_PCF, "203.0.113.10") {
			t.Error("expected matching host to be verified against the NRF profile")
		}
	})

	t.Run("host not on the profile is rejected", func(t *testing.T) {
		if verifyNotifyHostAgainstNrf(testNfId, models.Nrf_NFMgmt_NFType_PCF, "evil.attacker.example") {
			t.Error("expected a host absent from the NRF profile to be rejected")
		}
	})

	t.Run("mismatched nfId is rejected even if the host would otherwise match", func(t *testing.T) {
		if verifyNotifyHostAgainstNrf("some-other-nf-id", models.Nrf_NFMgmt_NFType_PCF, "203.0.113.10") {
			t.Error("expected a profile for a different nfId to never match")
		}
	})

	t.Run("missing nfId or nfType short-circuits to rejected", func(t *testing.T) {
		if verifyNotifyHostAgainstNrf("", models.Nrf_NFMgmt_NFType_PCF, "203.0.113.10") {
			t.Error("expected empty nfId to be rejected without calling the NRF")
		}
	})
}

// TestSendAmfEventNotify_RejectsLoopbackEvenWithARealListener proves the
// rejection happens before any network call, not just when the host is
// unreachable: a real server is listening on the loopback address, and it
// must still never see a request.
func TestSendAmfEventNotify_RejectsLoopbackEvenWithARealListener(t *testing.T) {
	var hit bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
	}))
	defer server.Close()

	savedClient := eventNotifyClient
	eventNotifyClient = server.Client()
	t.Cleanup(func() { eventNotifyClient = savedClient })

	// server.URL is https://127.0.0.1:<port> - a real, reachable, https
	// listener on a loopback address. isNotifyDestinationSafe is left at
	// its production default deliberately: this is the case it exists to
	// stop.
	SendAmfEventNotify(&models.Amf_Comm_ExtAmfEventSubscription{
		EventNotifyUri: server.URL,
		NfId:           testNfId,
		SourceNfType:   models.Nrf_NFMgmt_NFType_PCF,
	}, []models.Amf_EvtExpos_AmfEventReport{{Supi: "imsi-001010000000001"}})

	if hit {
		t.Error("SendAmfEventNotify must not deliver to a loopback host, even when something is listening there")
	}
}

func TestSendAmfEventNotify_RejectsNonHttps(t *testing.T) {
	var hit bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
	}))
	defer server.Close()

	SendAmfEventNotify(&models.Amf_Comm_ExtAmfEventSubscription{
		EventNotifyUri: server.URL, // plain http://
		NfId:           testNfId,
		SourceNfType:   models.Nrf_NFMgmt_NFType_PCF,
	}, []models.Amf_EvtExpos_AmfEventReport{{Supi: "imsi-001010000000001"}})

	if hit {
		t.Error("SendAmfEventNotify must reject a non-https notifyUri before making any request")
	}
}
