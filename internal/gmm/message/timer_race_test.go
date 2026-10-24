package message

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	gmm_common "github.com/free5gc/amf/internal/gmm/common"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/openapi/models"
)

// countingConn is an SCTP connection stub that is safe for concurrent writers.
type countingConn struct {
	mu sync.Mutex
	n  int
}

func (c *countingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return len(b), nil
}

func (c *countingConn) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func (c *countingConn) Read([]byte) (int, error) {
	return 0, nil
}

func (c *countingConn) Close() error {
	return nil
}

func (c *countingConn) LocalAddr() net.Addr {
	return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (c *countingConn) RemoteAddr() net.Addr {
	return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (c *countingConn) SetDeadline(time.Time) error {
	return nil
}

func (c *countingConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *countingConn) SetWriteDeadline(time.Time) error {
	return nil
}

// newAuthenticatingUe returns a pooled AmfUe in the authentication procedure,
// attached to a RanUe on a gNB whose writes are counted.
func newAuthenticatingUe(t *testing.T, supi string, t3560 factory.TimerValue) (*context.AmfUe, *context.RanUe,
	*countingConn,
) {
	t.Helper()
	amfSelf := context.GetSelf()
	amfSelf.ServedGuamiList = []models.Guami{{
		PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"},
		AmfId:  "cafe00",
	}}
	prevT3560 := amfSelf.T3560Cfg
	amfSelf.T3560Cfg = t3560
	t.Cleanup(func() { amfSelf.T3560Cfg = prevT3560 })

	conn := &countingConn{}
	ran := &context.AmfRan{AnType: models.AccessType_3_GPP_ACCESS, Conn: conn, Log: logger.NgapLog}
	ranUe := &context.RanUe{Ran: ran, RanUeNgapId: 1, AmfUeNgapId: 1, Log: logger.NgapLog}

	amfUe := amfSelf.NewAmfUe(supi)
	t.Cleanup(func() { amfSelf.UePool.Delete(supi) })
	amfUe.NgKsi = models.Amf_Comm_NgKsi{Tsc: models.Amf_Comm_ScType_NATIVE, Ksi: 1}
	amfUe.ABBA = []uint8{0x00, 0x00}
	amfUe.AuthenticationCtx = &models.Ausf_UEAU_UEAuthenticationCtx{
		AuthType: models.Ausf_UEAU_AuthType_5_G_AKA,
		Var5gAuthData: models.Ausf_UEAU_Av5gAka{
			Rand: "000102030405060708090a0b0c0d0e0f",
			Autn: "101112131415161718191a1b1c1d1e1f",
		},
	}
	gmm_common.AttachRanUeToAmfUeAndReleaseOldIfAny(amfUe, ranUe)
	return amfUe, ranUe, conn
}

// TestAuthenticationRequestRacesT3560Stop drives the T3560 start and stop paths
// from two goroutines, as an NGAP worker running the authentication procedure
// (SendAuthenticationRequest restarts T3560) and another worker or the GMM
// handler stopping it (HandleAuthenticationResponse, removeRanUeByInvalidId).
// Without serialization the T3560 field races and a stale Timer can be stopped
// twice, which panics in Timer.Stop.
func TestAuthenticationRequestRacesT3560Stop(t *testing.T) {
	amfUe, ranUe, _ := newAuthenticatingUe(t, "imsi-208930000000101",
		factory.TimerValue{Enable: true, ExpireTime: time.Minute, MaxRetryTimes: 4})

	const iterations = 200
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			SendAuthenticationRequest(ranUe)
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			if i%2 == 0 {
				amfUe.StopT3560()
			} else {
				gmm_common.StopAll5GSMMTimers(amfUe)
			}
		}
	}()
	close(start)
	wg.Wait()

	amfUe.StopT3560()
	require.True(t, amfUe.T3560 == nil)
}

// TestRestartedT3560DoesNotOutliveItsProcedure restarts T3560 (a second
// Authentication Request) and then stops it as HandleAuthenticationResponse
// does.  The T3560 that was replaced must not keep retransmitting, and its
// abort callback must not remove the UE context afterwards.
func TestRestartedT3560DoesNotOutliveItsProcedure(t *testing.T) {
	const supi = "imsi-208930000000102"
	amfUe, ranUe, conn := newAuthenticatingUe(t, supi,
		factory.TimerValue{Enable: true, ExpireTime: 10 * time.Millisecond, MaxRetryTimes: 2})

	SendAuthenticationRequest(ranUe)
	SendAuthenticationRequest(ranUe)
	amfUe.StopT3560()
	sent := conn.count()

	time.Sleep(200 * time.Millisecond)

	require.Equal(t, sent, conn.count(), "a replaced T3560 kept retransmitting after T3560 was stopped")
	_, ok := context.GetSelf().AmfUeFindBySupi(supi)
	require.True(t, ok, "a replaced T3560 aborted and removed the UE context")
}

// TestLowerLayerFailureAbortsT3550 sends a Registration Accept and then loses
// the UE's N2 connection without stopping the UE's timers, as NG Reset or the
// loss of the gNB's SCTP association does (RanUe.Remove), before Registration
// Complete arrives.  TS 24.501 5.5.1.2.8 a): the AMF locally aborts the
// registration procedure, enters 5GMM-REGISTERED and does not resend the
// Registration Accept.  When the UE then comes back through another gNB and
// starts a new procedure, the old T3550 must neither send the stale
// Registration Accept to the new gNB nor reset the state of the new procedure.
func TestLowerLayerFailureAbortsT3550(t *testing.T) {
	const supi = "imsi-208930000000104"
	const anType = models.AccessType_3_GPP_ACCESS

	amfSelf := context.GetSelf()
	amfSelf.ServedGuamiList = []models.Guami{{
		PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"},
		AmfId:  "cafe00",
	}}
	prevCfg := factory.AmfConfig
	factory.AmfConfig = &factory.Config{Configuration: &factory.Configuration{}}
	t.Cleanup(func() { factory.AmfConfig = prevCfg })
	const period = 50 * time.Millisecond
	prevT3550 := amfSelf.T3550Cfg
	amfSelf.T3550Cfg = factory.TimerValue{Enable: true, ExpireTime: period, MaxRetryTimes: 4}
	t.Cleanup(func() { amfSelf.T3550Cfg = prevT3550 })

	conn1 := &countingConn{}
	ran1 := &context.AmfRan{AnType: anType, Conn: conn1, Log: logger.NgapLog}
	ranUe1 := &context.RanUe{Ran: ran1, RanUeNgapId: 1, AmfUeNgapId: 1, Log: logger.NgapLog}
	amfUe := amfSelf.NewAmfUe(supi)
	t.Cleanup(func() { amfSelf.UePool.Delete(supi) })
	amfUe.SecurityContextAvailable = true
	amfUe.IntegrityAlg = 2 // 128-5G-IA2
	amfUe.KnasInt = [16]byte{5, 6, 7, 8}
	gmm_common.AttachRanUeToAmfUeAndReleaseOldIfAny(amfUe, ranUe1)
	amfUe.State[anType].Set(context.ContextSetup)

	SendRegistrationAccept(amfUe, anType, nil, nil, nil, nil, nil)
	require.True(t, amfUe.HasT3550())
	require.Equal(t, 1, conn1.count())

	// The gNB is lost: the RanUe is detached as RanUe.Remove does, and the
	// UE's timers keep running.
	amfUe.DetachRanUe(anType, ranUe1)
	ranUe1.DetachAmfUe()

	// The first expiry finds no N2 connection.  Allow three periods: an
	// orphaned T3550 would only reach 5GMM-REGISTERED at its fifth expiry.
	assert.Eventually(t, func() bool { return amfUe.State[anType].Is(context.Registered) }, 3*period,
		time.Millisecond, "the AMF did not enter 5GMM-REGISTERED after the lower layer failure")
	require.False(t, amfUe.HasT3550())

	// The UE comes back through another gNB and starts a new procedure.
	conn2 := &countingConn{}
	ran2 := &context.AmfRan{AnType: anType, Conn: conn2, Log: logger.NgapLog}
	ranUe2 := &context.RanUe{Ran: ran2, RanUeNgapId: 2, AmfUeNgapId: 2, Log: logger.NgapLog}
	gmm_common.AttachRanUeToAmfUeAndReleaseOldIfAny(amfUe, ranUe2)
	amfUe.State[anType].Set(context.Authentication)

	time.Sleep(5 * period) // longer than the remaining T3550 retransmissions
	assert.Zero(t, conn2.count(), "the old T3550 sent the stale Registration Accept to the new gNB")
	assert.Equal(t, 1, conn1.count())
	assert.True(t, amfUe.State[anType].Is(context.Authentication),
		"the old T3550 moved the new procedure to %s", amfUe.State[anType].Current())
}
