package processor

import (
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/openapi/models"
)

// TestCreateAMFEventSubscriptionProcedureConcurrentDeregistration is a regression test for
// free5gc/amf#71 ("Amf Event Exposure Subscription causes panic").
//
// CreateAMFEventSubscriptionProcedure used to look up the target UE by SUPI twice for the
// single-SUPI (non-AnyUE, non-GroupId) subscription path:
//   - once near the top of the function, correctly guarded with an "ok" check, returning
//     a UE_NOT_SERVED_BY_AMF problem detail if the UE isn't found;
//   - a second time, further down in the "for immediate use" block, via
//     `ue, _ := amfSelf.AmfUeFindBySupi(subscription.Supi)`, discarding the "ok" flag.
//
// If the UE was deregistered and removed from amfSelf.UePool (e.g. by a concurrent
// deregistration procedure) between those two lookups, the second lookup returned
// (nil, false), and the following `ue.Lock.Lock()` paniced on a nil pointer, crashing the
// whole AMF process. This was reachable by any NF (e.g. NEF) triggering
// AmfCreateEventSubscription, making it a real DoS vector.
//
// The fix reuses the UE reference obtained from the first, validated lookup for the rest of
// the procedure instead of performing a second, unguarded lookup, which removes the race
// window entirely rather than just narrowing it. This test races a concurrent deregistration
// against subscription creation over many iterations to catch any regression back to an
// unguarded second lookup.
func TestCreateAMFEventSubscriptionProcedureConcurrentDeregistration(t *testing.T) {
	previousLevel := logger.Log.GetLevel()
	logger.Log.SetLevel(logrus.ErrorLevel)
	t.Cleanup(func() { logger.Log.SetLevel(previousLevel) })

	amfSelf := context.GetSelf()
	amfSelf.ServedGuamiList = []models.Guami{{
		PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"},
		AmfId:  "cafe00",
	}}
	p := &Processor{}

	const iterations = 5000
	for i := 0; i < iterations; i++ {
		supi := fmt.Sprintf("imsi-208930000%05d", i)
		amfSelf.NewAmfUe(supi)

		req := models.Amf_EvtExpos_AmfCreateEventSubscription{
			Subscription: &models.Amf_EvtExpos_AmfEventSubscription{
				Supi: supi,
				EventList: []models.Amf_EvtExpos_AmfEvent{
					{Type: models.Amf_EvtExpos_AmfEventType_LOCATION_REPORT},
				},
			},
		}

		// Simulate a concurrent deregistration racing against
		// CreateAMFEventSubscriptionProcedure's use of the UE below. The
		// deleter spins for the whole duration of the call (instead of firing
		// once) so that, on the pre-fix code, at least one delete reliably
		// lands inside the narrow window between the first (validated) UE
		// lookup and the second (previously unguarded) one.
		stop := make(chan struct{})
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				select {
				case <-stop:
					return
				default:
					amfSelf.UePool.Delete(supi)
				}
			}
		}()

		require.NotPanics(t, func() {
			_, _ = p.CreateAMFEventSubscriptionProcedure(req)
		}, "CreateAMFEventSubscriptionProcedure must not panic when the UE is "+
			"deregistered concurrently with subscription creation (iteration %d)", i)

		close(stop)
		<-done
		amfSelf.UePool.Delete(supi) // ensure clean pool state regardless of race outcome
	}
}

// TestCreateAMFEventSubscriptionProcedureUnknownSupi confirms the baseline, non-racy behavior:
// a SUPI with no corresponding UE in the pool is rejected with UE_NOT_SERVED_BY_AMF instead of
// panicking.
func TestCreateAMFEventSubscriptionProcedureUnknownSupi(t *testing.T) {
	p := &Processor{}

	req := models.Amf_EvtExpos_AmfCreateEventSubscription{
		Subscription: &models.Amf_EvtExpos_AmfEventSubscription{
			Supi: "imsi-208930000099999",
			EventList: []models.Amf_EvtExpos_AmfEvent{
				{Type: models.Amf_EvtExpos_AmfEventType_LOCATION_REPORT},
			},
		},
	}

	var rsp *models.Amf_EvtExpos_AmfCreatedEventSubscription
	var problemDetails *models.ProblemDetails
	require.NotPanics(t, func() {
		rsp, problemDetails = p.CreateAMFEventSubscriptionProcedure(req)
	})

	require.Nil(t, rsp)
	require.NotNil(t, problemDetails)
	require.Equal(t, "UE_NOT_SERVED_BY_AMF", problemDetails.Cause)
}
