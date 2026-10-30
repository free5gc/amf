package context

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/amf/pkg/factory"
)

// TestReplacedTimerCallbackKeepsItsReplacement covers a T3550 callback that is
// already running when a new Registration Accept restarts T3550.  Stopping the
// replaced timer cannot interrupt that callback, so when it then aborts T3550
// (the "UE context released" branch of SendRegistrationAccept) it must leave
// the new timer running and must not stop the replaced timer a second time.
func TestReplacedTimerCallbackKeepsItsReplacement(t *testing.T) {
	ue := &AmfUe{GmmLog: logger.GmmLog}

	inCallback := make(chan struct{})
	release := make(chan struct{})
	aborted := make(chan bool, 1)
	var once sync.Once
	ue.StartT3550(factory.TimerValue{Enable: true, ExpireTime: time.Millisecond, MaxRetryTimes: 1000},
		func(_ int32, abort func() bool) {
			once.Do(func() {
				close(inCallback)
				<-release
				aborted <- abort()
			})
		}, func() {})

	select {
	case <-inCallback:
	case <-time.After(5 * time.Second):
		t.Fatal("T3550 did not expire")
	}
	ue.StartT3550(factory.TimerValue{Enable: true, ExpireTime: time.Minute, MaxRetryTimes: 4},
		func(int32, func() bool) {}, func() {})
	close(release)

	require.False(t, <-aborted, "the replaced T3550 aborted the running one")
	require.True(t, ue.HasT3550(), "the replaced T3550 cleared its replacement")
	ue.StopT3550()
	require.False(t, ue.HasT3550())
}

// TestEndedTimerIsStopped checks that a timer which is replaced by a restart,
// or which aborts itself from its callback, is stopped, so its goroutine and
// ticker end with it.  (Its callbacks are already skipped once it has left its
// field; see TestStoppedTimerSkipsPendingExpiry.)
func TestEndedTimerIsStopped(t *testing.T) {
	stopped := func(timer *Timer) bool {
		select {
		case <-timer.done: // Stop sends on and closes done
			return true
		default:
			return false
		}
	}

	t.Run("replaced by a restart", func(t *testing.T) {
		ue := &AmfUe{GmmLog: logger.GmmLog}
		cfg := factory.TimerValue{Enable: true, ExpireTime: time.Minute, MaxRetryTimes: 4}
		ue.StartT3560(cfg, func(int32) {}, func() {})
		ue.timerMu.Lock()
		replaced := ue.T3560
		ue.timerMu.Unlock()

		ue.StartT3560(cfg, func(int32) {}, func() {})
		require.True(t, stopped(replaced), "the replaced T3560 was not stopped")
		ue.StopT3560()
	})

	t.Run("aborted by its callback", func(t *testing.T) {
		ue := &AmfUe{GmmLog: logger.GmmLog}
		release := make(chan struct{})
		aborted := make(chan bool, 1)
		var once sync.Once
		ue.StartT3550(factory.TimerValue{Enable: true, ExpireTime: time.Millisecond, MaxRetryTimes: 1000},
			func(_ int32, abort func() bool) {
				once.Do(func() {
					<-release
					aborted <- abort()
				})
			}, func() {})
		ue.timerMu.Lock()
		timer := ue.T3550
		ue.timerMu.Unlock()

		close(release)
		require.True(t, <-aborted)
		require.False(t, ue.HasT3550())
		require.True(t, stopped(timer), "the aborted T3550 was not stopped")
	})
}

// TestStoppedTimerSkipsPendingExpiry stops T3560 while one of its
// retransmission callbacks is still running, as HandleAuthenticationResponse
// does on another goroutine, and lets the next expiry become due before the
// callback returns.  Timer.Stop cannot withdraw that pending expiry, so it must
// not retransmit again or, after the last retransmission, run the abort
// callback (RemoveAmfUe for T3560) of a procedure that has completed.
func TestStoppedTimerSkipsPendingExpiry(t *testing.T) {
	testCases := []struct {
		name          string
		maxRetryTimes int
	}{
		{name: "retransmission pending", maxRetryTimes: 1000},
		{name: "abort pending", maxRetryTimes: 1},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Without the check, each timer has a one-in-two chance to run the
			// pending expiry, so 20 timers catch it with near certainty.
			for i := 0; i < 20; i++ {
				ue := &AmfUe{GmmLog: logger.GmmLog}
				var expiries, cancels atomic.Int32
				stopped := make(chan struct{})
				ue.StartT3560(factory.TimerValue{Enable: true, ExpireTime: time.Millisecond, MaxRetryTimes: tc.maxRetryTimes},
					func(int32) {
						if expiries.Add(1) == 1 {
							ue.StopT3560()
							time.Sleep(5 * time.Millisecond) // the next expiry is now due
							close(stopped)
						}
					}, func() { cancels.Add(1) })

				select {
				case <-stopped:
				case <-time.After(5 * time.Second):
					t.Fatal("T3560 did not expire")
				}
				time.Sleep(20 * time.Millisecond)
				require.EqualValues(t, 1, expiries.Load(), "a stopped T3560 retransmitted again")
				require.EqualValues(t, 0, cancels.Load(), "a stopped T3560 ran its abort callback")
			}
		})
	}
}

// TestTimerCancelClearsOnlyItsOwnField checks that a timer that runs out clears
// its field before the abort callback runs, so the callback (and anything it
// calls, such as RemoveAmfUe -> StopT3560) sees the timer as gone.
func TestTimerCancelClearsOnlyItsOwnField(t *testing.T) {
	ue := &AmfUe{GmmLog: logger.GmmLog}

	canceled := make(chan bool, 1)
	ue.StartT3560(factory.TimerValue{Enable: true, ExpireTime: time.Millisecond, MaxRetryTimes: 0},
		func(int32) {}, func() {
			canceled <- ue.takeTimer(&ue.T3560) == nil
		})

	select {
	case cleared := <-canceled:
		require.True(t, cleared, "T3560 was still set when its abort callback ran")
	case <-time.After(5 * time.Second):
		t.Fatal("T3560 did not run out")
	}
}

// TestStopT3550RacesItsLastExpiry stops T3550 around the time it runs out, as
// HandleRegistrationComplete does when Registration Complete arrives at T3550's
// last expiry.  The abort callback of that expiry clears the registration
// request data that HandleRegistrationComplete reads after the stop, so the two
// must exclude each other: StopT3550 reports true exactly when the abort
// callback does not run.
func TestStopT3550RacesItsLastExpiry(t *testing.T) {
	var stopped, ranOut int
	for i := 0; i < 100; i++ {
		ue := &AmfUe{GmmLog: logger.GmmLog}
		canceled := make(chan struct{})
		ue.StartT3550(factory.TimerValue{Enable: true, ExpireTime: time.Millisecond, MaxRetryTimes: 0},
			func(int32, func() bool) {}, func() { close(canceled) })
		// Stop before, around and after the expiry.
		time.Sleep(time.Duration(i%5) * 250 * time.Microsecond)

		if ue.StopT3550() {
			stopped++
			select {
			case <-canceled:
				t.Fatal("StopT3550 reported that it stopped T3550, but the abort callback ran")
			case <-time.After(5 * time.Millisecond):
			}
		} else {
			ranOut++
			select {
			case <-canceled:
			case <-time.After(5 * time.Second):
				t.Fatal("StopT3550 found no T3550, but the abort callback did not run")
			}
		}
	}
	t.Logf("StopT3550 won %d times, the last expiry %d times", stopped, ranOut)
}
