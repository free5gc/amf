package consumer

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/h2non/gock"
)

// TestHeartbeatWiring drives the runner through the real consumer transport:
// the registration seeds the timer, the loop sends the PATCH and adopts the
// interval it returns, and shutdown waits for the heartbeat goroutine. The
// runner's own behavior is covered in the util nfheartbeat package.
func TestHeartbeatWiring(t *testing.T) {
	// The NRF assigns registerTimer at registration time and answers the first
	// heartbeat with adoptedTimer.
	const (
		registerTimer = 1
		adoptedTimer  = 2
	)

	synctest.Test(t, func(t *testing.T) {
		c := newNrfTestConsumer(t)

		gock.New(testNrfUri).
			Put(testNfIdPath).
			Reply(http.StatusCreated).
			JSON(nfProfileJSON(registerTimer, nil))
		gock.New(testNrfUri).
			Patch(testNfIdPath).
			Reply(http.StatusOK).
			JSON(nfProfileJSON(adoptedTimer, nil))

		ctx, cancel := context.WithCancel(synctestCtx(t))
		if err := c.SendRegisterNFInstance(ctx, true); err != nil {
			t.Fatalf("SendRegisterNFInstance: %v", err)
		}

		var wg sync.WaitGroup
		c.StartHeartbeat(ctx, &wg)

		// Fake clock: Sleep jumps to the tick, then synctest.Wait returns once the loop has served it.
		time.Sleep(registerTimer * time.Second)
		synctest.Wait()

		if !gock.IsDone() {
			t.Fatal("the heartbeat loop sent no PATCH")
		}

		gock.New(testNrfUri).
			Patch(testNfIdPath).
			Reply(http.StatusNoContent)

		// One registration interval later nothing may fire: the adopted
		// interval is longer. The next PATCH lands only on the adopted one.
		time.Sleep(registerTimer * time.Second)
		synctest.Wait()
		if gock.IsDone() {
			t.Fatal("the loop kept the registration interval after the PATCH assigned a new one")
		}

		time.Sleep((adoptedTimer - registerTimer) * time.Second)
		synctest.Wait()
		if !gock.IsDone() {
			t.Fatal("the next PATCH did not fire on the adopted interval")
		}

		cancel()
		waitHeartbeatStopped(t, c)
		wg.Wait()
	})
}

// TestHeartbeatReregistersOnNotFound drives the 404 handshake through the real
// transport: the PATCH answers 404, the adapter re-registers with a PUT, and
// the next heartbeat fires on the interval the re-registration returned.
func TestHeartbeatReregistersOnNotFound(t *testing.T) {
	const (
		initialTimer    = 1
		reregisterTimer = 2
	)

	synctest.Test(t, func(t *testing.T) {
		c := newNrfTestConsumer(t)
		c.heartbeatTimer = initialTimer

		gock.New(testNrfUri).
			Patch(testNfIdPath).
			Reply(http.StatusNotFound).
			JSON(problemJSON(http.StatusNotFound, causeNotFound))
		gock.New(testNrfUri).
			Put(testNfIdPath).
			Reply(http.StatusOK).
			JSON(nfProfileJSON(reregisterTimer, nil))
		gock.New(testNrfUri).
			Patch(testNfIdPath).
			Reply(http.StatusNoContent)

		var wg sync.WaitGroup
		ctx, cancel := context.WithCancel(t.Context())
		c.StartHeartbeat(ctx, &wg)

		// t=1s: 404 PATCH, then a PUT answered with reregisterTimer. t=2s: no PATCH. t=3s: follow-up PATCH.
		time.Sleep(initialTimer * time.Second)
		synctest.Wait()

		time.Sleep(initialTimer * time.Second)
		synctest.Wait()
		if gock.IsDone() {
			t.Fatal("the loop kept the old interval after re-registration")
		}

		time.Sleep((reregisterTimer - initialTimer) * time.Second)
		synctest.Wait()
		if !gock.IsDone() {
			t.Fatal("expected 404 PATCH, re-registration PUT and follow-up PATCH")
		}

		cancel()
		waitHeartbeatStopped(t, c)
		wg.Wait()
	})
}

// TestHeartbeatFallbackInterval proves the wiring of the config fallback: the
// NRF assigns no timer, so the loop must tick at the configured interval.
func TestHeartbeatFallbackInterval(t *testing.T) {
	const configTimer = 45

	synctest.Test(t, func(t *testing.T) {
		c := newNrfTestConsumer(t)
		c.Config().Configuration.NfHeartBeatTimer = configTimer

		gock.New(testNrfUri).
			Put(testNfIdPath).
			Reply(http.StatusOK).
			JSON(nfProfileJSON(0, nil))
		gock.New(testNrfUri).
			Patch(testNfIdPath).
			Reply(http.StatusNoContent)

		ctx, cancel := context.WithCancel(synctestCtx(t))
		if err := c.SendRegisterNFInstance(ctx, true); err != nil {
			t.Fatalf("SendRegisterNFInstance: %v", err)
		}

		var wg sync.WaitGroup
		c.StartHeartbeat(ctx, &wg)

		// One second short of the configured interval nothing may fire; a
		// loop running on the default interval would already have PATCHed.
		time.Sleep((configTimer - 1) * time.Second)
		synctest.Wait()
		if gock.IsDone() {
			t.Fatal("the heartbeat fired before the configured fallback interval")
		}

		time.Sleep(1 * time.Second)
		synctest.Wait()
		if !gock.IsDone() {
			t.Fatal("the heartbeat loop did not tick at the configured fallback interval")
		}

		cancel()
		waitHeartbeatStopped(t, c)
		wg.Wait()
	})
}

// waitHeartbeatStopped fails the test if WaitHeartbeatStopped is still blocked once every goroutine in the
// synctest bubble is idle, which means the heartbeat goroutine did not exit.
func waitHeartbeatStopped(t *testing.T, c *Consumer) {
	t.Helper()

	stopped := make(chan struct{})
	go func() {
		c.WaitHeartbeatStopped()
		close(stopped)
	}()

	synctest.Wait()
	select {
	case <-stopped:
	default:
		t.Fatal("WaitHeartbeatStopped did not return")
	}
}
