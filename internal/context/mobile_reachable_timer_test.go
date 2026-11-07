package context

import (
	"testing"
	"time"

	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/fsm"
)

// newConnectedTestUe returns a UE in the given 3GPP state with a RanUe attached, T3512 of one
// second and the mobile reachable timer margin shortened so that each timer runs 200 ms.
func newConnectedTestUe(t *testing.T, state fsm.StateType) (*AmfUe, *RanUe, chan *AmfUe) {
	t.Helper()
	margin := mobileReachableTimerMargin
	procedure := implicitDeregistration
	mobileReachableTimerMargin = -800 * time.Millisecond
	deregistered := make(chan *AmfUe, 1)
	SetImplicitDeregistration(func(ue *AmfUe) { deregistered <- ue })
	t.Cleanup(func() {
		mobileReachableTimerMargin = margin
		implicitDeregistration = procedure
	})

	ue := &AmfUe{
		RanUe:       make(map[models.AccessType]*RanUe),
		AnTypeFlags: make(map[models.AccessType]bool),
		State: map[models.AccessType]*fsm.State{
			models.AccessType_3_GPP_ACCESS:     fsm.NewState(state),
			models.AccessType_NON_3_GPP_ACCESS: fsm.NewState(Deregistered),
		},
		T3512Value:  1,
		NASLog:      logger.GmmLog,
		GmmLog:      logger.GmmLog,
		ProducerLog: logger.ProducerLog,
	}
	ranUe := &RanUe{
		Ran:         &AmfRan{AnType: models.AccessType_3_GPP_ACCESS, Log: logger.NgapLog},
		RanUeNgapId: 1,
		AmfUeNgapId: 1,
		Log:         logger.NgapLog,
	}
	ue.AttachRanUe(ranUe)
	return ue, ranUe, deregistered
}

// TS 24.501 5.3.7: the mobile reachable timer starts when the NAS signaling connection of a
// registered UE is released, the implicit de-registration timer when it expires, and the UE is
// de-registered when that one expires in turn.
func TestImplicitDeregistrationAfterBothTimers(t *testing.T) {
	ue, ranUe, deregistered := newConnectedTestUe(t, Registered)

	ue.DetachRanUe(models.AccessType_3_GPP_ACCESS, ranUe)
	ue.RanUeMu.RLock()
	started := ue.MobileReachableTimer != nil
	ue.RanUeMu.RUnlock()
	if !started {
		t.Fatal("the mobile reachable timer did not start when the UE's connection was released")
	}

	select {
	case got := <-deregistered:
		if got != ue {
			t.Fatalf("implicitly de-registered UE = %p, want %p", got, ue)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the UE was not implicitly de-registered after both timers")
	}
	ue.RanUeMu.RLock()
	defer ue.RanUeMu.RUnlock()
	if ue.MobileReachableTimer != nil || ue.ImplicitDeregistrationTimer != nil {
		t.Fatal("a timer is still set after the implicit de-registration")
	}
}

// TS 24.501 5.3.7: both timers stop when a NAS signaling connection is established.
func TestMobileReachableTimerStopsOnNewConnection(t *testing.T) {
	ue, ranUe, deregistered := newConnectedTestUe(t, Registered)

	ue.DetachRanUe(models.AccessType_3_GPP_ACCESS, ranUe)
	implicitStarted := func() bool {
		ue.RanUeMu.RLock()
		defer ue.RanUeMu.RUnlock()
		return ue.ImplicitDeregistrationTimer != nil
	}
	for deadline := time.Now().Add(2 * time.Second); !implicitStarted(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the implicit de-registration timer did not start when the mobile reachable timer expired")
		}
	}

	ue.AttachRanUe(ranUe)
	ue.RanUeMu.RLock()
	stopped := ue.MobileReachableTimer == nil && ue.ImplicitDeregistrationTimer == nil
	ue.RanUeMu.RUnlock()
	if !stopped {
		t.Fatal("a timer is still set after a new connection")
	}
	select {
	case <-deregistered:
		t.Fatal("a UE with a new connection was implicitly de-registered")
	case <-time.After(500 * time.Millisecond):
	}
}

// A UE that is de-registered has no mobile reachable timer.
func TestNoMobileReachableTimerForDeregisteredUe(t *testing.T) {
	ue, ranUe, _ := newConnectedTestUe(t, Deregistered)

	ue.DetachRanUe(models.AccessType_3_GPP_ACCESS, ranUe)
	ue.RanUeMu.RLock()
	defer ue.RanUeMu.RUnlock()
	if ue.MobileReachableTimer != nil {
		t.Fatal("the mobile reachable timer started for a de-registered UE")
	}
}
