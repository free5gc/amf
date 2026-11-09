package callback

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/openapi/models"
)

const testScheduleSupi = "imsi-001010000000099"

// notifyRecorder counts delivered notifications under a mutex; scheduling
// runs a background goroutine (the PERIODIC ticker), so the test and that
// goroutine both touch this concurrently.
type notifyRecorder struct {
	mu    sync.Mutex
	count int
}

func (r *notifyRecorder) hit() {
	r.mu.Lock()
	r.count++
	r.mu.Unlock()
}

func (r *notifyRecorder) get() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

// stubNotifyPipeline bypasses the NRF host check (always-allow) and points
// eventNotifyClient at server's own trusted client, so delivery exercises
// the real HTTP POST without needing a live NRF or a non-loopback host.
// Restored via t.Cleanup.
func stubNotifyPipeline(t *testing.T, server *httptest.Server) {
	t.Helper()
	savedSafe := isNotifyDestinationSafe
	savedClient := eventNotifyClient
	isNotifyDestinationSafe = func(*models.Amf_Comm_ExtAmfEventSubscription, string) bool { return true }
	eventNotifyClient = server.Client()
	t.Cleanup(func() {
		isNotifyDestinationSafe = savedSafe
		eventNotifyClient = savedClient
	})
}

func newScheduleTestUe(t *testing.T) *amf_context.AmfUe {
	t.Helper()
	amfSelf := amf_context.GetSelf()
	amfSelf.ServedGuamiList = []models.Guami{{
		PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"},
		AmfId:  "cafe00",
	}}
	ue := amfSelf.NewAmfUe(testScheduleSupi)
	t.Cleanup(func() { amfSelf.UePool.Delete(testScheduleSupi) })
	return ue
}

// TestStartPeriodicReporting_FiresRepeatedlyThenStopsAtExpiry proves a
// PERIODIC subscription (TS 29.518 AmfEventMode.repPeriod) ticks more than
// once - the original gap in issue #78, where report-building existed but
// nothing ever called it more than once at subscription creation - and
// that it stops ticking once Expiry passes.
func TestStartPeriodicReporting_FiresRepeatedlyThenStopsAtExpiry(t *testing.T) {
	recorder := &notifyRecorder{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder.hit()
	}))
	defer server.Close()
	stubNotifyPipeline(t, server)

	savedUnit := periodicReportTickUnit
	periodicReportTickUnit = 10 * time.Millisecond
	t.Cleanup(func() { periodicReportTickUnit = savedUnit })

	ue := newScheduleTestUe(t)
	const subscriptionId = "sub-periodic-1"
	const repPeriodTicks = 1 // RepPeriod * periodicReportTickUnit per fire

	ue.Lock.Lock()
	sub := &amf_context.AmfUeEventSubscription{
		Timestamp: time.Now(),
		EventSubscription: &models.Amf_Comm_ExtAmfEventSubscription{
			EventNotifyUri: server.URL,
			NfId:           testNfId,
			SourceNfType:   models.Nrf_NFMgmt_NFType_PCF,
			EventList:      []models.Amf_EvtExpos_AmfEvent{{Type: models.Amf_EvtExpos_AmfEventType_REACHABILITY_REPORT}},
			Options: &models.Amf_EvtExpos_AmfEventMode{
				Trigger:   models.Amf_EvtExpos_AmfEventTrigger_PERIODIC,
				RepPeriod: repPeriodTicks,
				// Expires after ~6 ticks: enough fires to prove repetition,
				// short enough to keep the test fast.
				Expiry: ptrTime(time.Now().Add(6 * time.Duration(repPeriodTicks) * periodicReportTickUnit)),
			},
		},
	}
	ue.EventSubscriptionsInfo[subscriptionId] = sub
	StartPeriodicReporting(ue, subscriptionId, sub)
	ue.Lock.Unlock()

	deadline := time.Now().Add(2 * time.Second)
	for recorder.get() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := recorder.get(); got < 3 {
		t.Fatalf("expected at least 3 periodic notifications, got %d", got)
	}

	// Let it run past Expiry, then confirm it actually stopped: the
	// subscription entry is gone and the count stops climbing.
	time.Sleep(300 * time.Millisecond)
	ue.Lock.Lock()
	_, stillPresent := ue.EventSubscriptionsInfo[subscriptionId]
	ue.Lock.Unlock()
	if stillPresent {
		t.Error("expected the subscription to be removed once Expiry passed")
	}
	countAtExpiry := recorder.get()
	time.Sleep(200 * time.Millisecond)
	if recorder.get() != countAtExpiry {
		t.Error("expected no further notifications after the subscription expired")
	}
}

// TestFireContinuousEventReport_FiresOnEachCallAndStopsAtMaxReports proves
// a CONTINUOUS subscription delivers once per matching state-change event
// (the GMM hook calls this directly) and stops once RemainReports is
// exhausted, per TS 29.518 AmfEventMode.maxReports.
func TestFireContinuousEventReport_FiresOnEachCallAndStopsAtMaxReports(t *testing.T) {
	recorder := &notifyRecorder{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder.hit()
	}))
	defer server.Close()
	stubNotifyPipeline(t, server)

	ue := newScheduleTestUe(t)
	const subscriptionId = "sub-continuous-1"
	remain := int32(2)

	ue.Lock.Lock()
	ue.EventSubscriptionsInfo[subscriptionId] = &amf_context.AmfUeEventSubscription{
		Timestamp:     time.Now(),
		RemainReports: &remain,
		EventSubscription: &models.Amf_Comm_ExtAmfEventSubscription{
			EventNotifyUri: server.URL,
			NfId:           testNfId,
			SourceNfType:   models.Nrf_NFMgmt_NFType_PCF,
			EventList:      []models.Amf_EvtExpos_AmfEvent{{Type: models.Amf_EvtExpos_AmfEventType_REGISTRATION_STATE_REPORT}},
			Options: &models.Amf_EvtExpos_AmfEventMode{
				Trigger:    models.Amf_EvtExpos_AmfEventTrigger_CONTINUOUS,
				MaxReports: 2,
			},
		},
	}
	ue.Lock.Unlock()

	FireContinuousEventReport(ue, models.Amf_EvtExpos_AmfEventType_REGISTRATION_STATE_REPORT)
	waitForCount(t, recorder, 1)
	ue.Lock.Lock()
	_, stillPresent := ue.EventSubscriptionsInfo[subscriptionId]
	ue.Lock.Unlock()
	if !stillPresent {
		t.Fatal("expected the subscription to still be active after 1 of 2 reports")
	}

	FireContinuousEventReport(ue, models.Amf_EvtExpos_AmfEventType_REGISTRATION_STATE_REPORT)
	waitForCount(t, recorder, 2)
	ue.Lock.Lock()
	_, stillPresent = ue.EventSubscriptionsInfo[subscriptionId]
	ue.Lock.Unlock()
	if stillPresent {
		t.Error("expected the subscription to be removed once RemainReports hit 0")
	}

	// A third firing must be a no-op: no subscription left to match.
	FireContinuousEventReport(ue, models.Amf_EvtExpos_AmfEventType_REGISTRATION_STATE_REPORT)
	time.Sleep(100 * time.Millisecond)
	if got := recorder.get(); got != 2 {
		t.Errorf("expected exactly 2 deliveries total, got %d", got)
	}
}

// TestFireContinuousEventReport_IgnoresUnrelatedEventType proves a
// subscription only fires for event types actually in its EventList.
func TestFireContinuousEventReport_IgnoresUnrelatedEventType(t *testing.T) {
	recorder := &notifyRecorder{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder.hit()
	}))
	defer server.Close()
	stubNotifyPipeline(t, server)

	ue := newScheduleTestUe(t)
	remain := int32(5)
	ue.Lock.Lock()
	ue.EventSubscriptionsInfo["sub-continuous-2"] = &amf_context.AmfUeEventSubscription{
		Timestamp:     time.Now(),
		RemainReports: &remain,
		EventSubscription: &models.Amf_Comm_ExtAmfEventSubscription{
			EventNotifyUri: server.URL,
			NfId:           testNfId,
			SourceNfType:   models.Nrf_NFMgmt_NFType_PCF,
			EventList:      []models.Amf_EvtExpos_AmfEvent{{Type: models.Amf_EvtExpos_AmfEventType_ACCESS_TYPE_REPORT}},
			Options:        &models.Amf_EvtExpos_AmfEventMode{Trigger: models.Amf_EvtExpos_AmfEventTrigger_CONTINUOUS, MaxReports: 5},
		},
	}
	ue.Lock.Unlock()

	FireContinuousEventReport(ue, models.Amf_EvtExpos_AmfEventType_REGISTRATION_STATE_REPORT)
	time.Sleep(100 * time.Millisecond)
	if got := recorder.get(); got != 0 {
		t.Errorf("expected no delivery for an event type absent from EventList, got %d", got)
	}
}

func waitForCount(t *testing.T, r *notifyRecorder, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if r.get() >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d notifications, got %d", want, r.get())
}

func ptrTime(t time.Time) *time.Time { return &t }
