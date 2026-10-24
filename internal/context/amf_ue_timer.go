package context

import (
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/openapi/models"
)

// The 5GMM timer fields of AmfUe are started by one procedure, stopped by
// another procedure or by a release, and cleared by the timer's own goroutine,
// each on its own goroutine.  Every access goes through ue.timerMu.  Only the
// caller that removes a Timer from its field stops it, after the lock is
// released, so a Timer is stopped at most once (a second Timer.Stop panics).
// A Timer's callbacks act only while it is still in its field.  A timer is
// started before the message it guards is sent, because the answer can be
// handled on another goroutine, and the timer stopped, before the send returns.

// takeTimer removes and returns the timer held in field.
func (ue *AmfUe) takeTimer(field **Timer) *Timer {
	ue.timerMu.Lock()
	defer ue.timerMu.Unlock()
	timer := *field
	*field = nil
	return timer
}

// clearTimer clears field if it still holds timer and reports whether it did.
func (ue *AmfUe) clearTimer(field **Timer, timer *Timer) bool {
	ue.timerMu.Lock()
	defer ue.timerMu.Unlock()
	if *field != timer {
		return false
	}
	*field = nil
	return true
}

func (ue *AmfUe) holdsTimer(field **Timer, timer *Timer) bool {
	ue.timerMu.Lock()
	defer ue.timerMu.Unlock()
	return *field == timer
}

func (ue *AmfUe) hasTimer(field **Timer) bool {
	ue.timerMu.Lock()
	defer ue.timerMu.Unlock()
	return *field != nil
}

// startTimer publishes a new timer in field and then starts it.  A timer that
// is still running in field is stopped: otherwise it would keep
// retransmitting and later run its abort callback against the procedure that
// replaced it.  The callbacks run only while field still holds this timer, so
// an expiry that was already pending when the timer was stopped or replaced
// does nothing.  When the timer runs out, field is cleared before cancel runs.
// expired gets an abort function that ends the timer from its own callback: it
// clears field and stops the timer if field still holds it, and reports
// whether it did.
func (ue *AmfUe) startTimer(field **Timer, cfg factory.TimerValue,
	expired func(expireTimes int32, abort func() bool), cancel func(),
) {
	timer := newTimer(cfg.ExpireTime, cfg.MaxRetryTimes)
	abort := func() bool {
		if !ue.clearTimer(field, timer) {
			return false
		}
		timer.Stop()
		return true
	}

	ue.timerMu.Lock()
	replaced := *field
	*field = timer
	ue.timerMu.Unlock()
	if replaced != nil {
		replaced.Stop()
	}

	timer.start(func(expireTimes int32) {
		if ue.holdsTimer(field, timer) {
			expired(expireTimes, abort)
		}
	}, func() {
		if ue.clearTimer(field, timer) {
			cancel()
		}
	})
}

func (ue *AmfUe) startSimpleTimer(field **Timer, cfg factory.TimerValue,
	expired func(expireTimes int32), cancel func(),
) {
	ue.startTimer(field, cfg, func(expireTimes int32, _ func() bool) {
		expired(expireTimes)
	}, cancel)
}

// StartT3513 starts the paging timer T3513, replacing (and stopping) any
// running T3513.  expired runs on every expiry; cancel runs once after the
// last one, when T3513 has already been cleared.
func (ue *AmfUe) StartT3513(cfg factory.TimerValue, expired func(expireTimes int32), cancel func()) {
	ue.startSimpleTimer(&ue.T3513, cfg, expired, cancel)
}

// StartT3522 starts T3522 (deregistration request); see StartT3513.
func (ue *AmfUe) StartT3522(cfg factory.TimerValue, expired func(expireTimes int32), cancel func()) {
	ue.startSimpleTimer(&ue.T3522, cfg, expired, cancel)
}

// StartT3550 starts T3550 (registration accept); see StartT3513.  expired
// also gets an abort function that stops this T3550 if it is still the running
// one, for a lower layer failure before Registration Complete.
func (ue *AmfUe) StartT3550(cfg factory.TimerValue, expired func(expireTimes int32, abort func() bool),
	cancel func(),
) {
	ue.startTimer(&ue.T3550, cfg, expired, cancel)
}

// StartT3555 starts T3555 (configuration update command); see StartT3513.
func (ue *AmfUe) StartT3555(cfg factory.TimerValue, expired func(expireTimes int32), cancel func()) {
	ue.startSimpleTimer(&ue.T3555, cfg, expired, cancel)
}

// StartT3560 starts T3560 (authentication request, security mode command);
// see StartT3513.
func (ue *AmfUe) StartT3560(cfg factory.TimerValue, expired func(expireTimes int32), cancel func()) {
	ue.startSimpleTimer(&ue.T3560, cfg, expired, cancel)
}

// StartT3565 starts T3565 (notification); see StartT3513.
func (ue *AmfUe) StartT3565(cfg factory.TimerValue, expired func(expireTimes int32), cancel func()) {
	ue.startSimpleTimer(&ue.T3565, cfg, expired, cancel)
}

// StartT3570 starts T3570 (identity request); see StartT3513.
func (ue *AmfUe) StartT3570(cfg factory.TimerValue, expired func(expireTimes int32), cancel func()) {
	ue.startSimpleTimer(&ue.T3570, cfg, expired, cancel)
}

// HasT3550 reports whether T3550 is running, i.e. a Registration Accept is
// waiting for Registration Complete.
func (ue *AmfUe) HasT3550() bool {
	return ue.hasTimer(&ue.T3550)
}

// StopAll5GSMMTimers stops every 5GMM timer of the UE and, if paging was in
// progress, ends the paging procedure.
func (ue *AmfUe) StopAll5GSMMTimers() {
	if timer := ue.takeTimer(&ue.T3513); timer != nil {
		timer.Stop()
		if ue.OnGoing(models.AccessType_3_GPP_ACCESS).Procedure == OnGoingProcedurePaging {
			ue.SetOnGoing(models.AccessType_3_GPP_ACCESS, &OnGoing{
				Procedure: OnGoingProcedureNothing,
			})
		}
	}
	for _, field := range []**Timer{&ue.T3522, &ue.T3550, &ue.T3560, &ue.T3565, &ue.T3570, &ue.T3555} {
		if timer := ue.takeTimer(field); timer != nil {
			timer.Stop()
		}
	}
}
