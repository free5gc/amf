package common

import (
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// gnbConn is an SCTP connection stub that is safe for concurrent writers.  If
// stall is set, every Write blocks until stall is closed, like a gNB that has
// stopped reading its socket.
type gnbConn struct {
	mu      sync.Mutex
	msgs    [][]byte
	writing chan struct{}
	stall   chan struct{}
}

func (c *gnbConn) Write(b []byte) (int, error) {
	if c.writing != nil {
		select {
		case c.writing <- struct{}{}:
		default:
		}
	}
	if c.stall != nil {
		<-c.stall
	}
	c.mu.Lock()
	c.msgs = append(c.msgs, append([]byte(nil), b...))
	c.mu.Unlock()
	return len(b), nil
}

func (c *gnbConn) messages() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.msgs...)
}

func (c *gnbConn) Read([]byte) (int, error) {
	return 0, nil
}

func (c *gnbConn) Close() error {
	return nil
}

func (c *gnbConn) LocalAddr() net.Addr {
	return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (c *gnbConn) RemoteAddr() net.Addr {
	return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (c *gnbConn) SetDeadline(time.Time) error {
	return nil
}

func (c *gnbConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *gnbConn) SetWriteDeadline(time.Time) error {
	return nil
}

func newTestRan(conn net.Conn) *context.AmfRan {
	return &context.AmfRan{
		AnType: models.AccessType_3_GPP_ACCESS,
		Conn:   conn,
		Log:    logger.NgapLog,
	}
}

func newTestRanUe(ran *context.AmfRan, id int64) *context.RanUe {
	return &context.RanUe{
		Ran:         ran,
		RanUeNgapId: id,
		AmfUeNgapId: id,
		Log:         logger.NgapLog,
	}
}

// newPooledAmfUe returns an AmfUe with no RanUe attached, as for a registered
// UE in CM-IDLE whose context is still in the UE pool.
func newPooledAmfUe(t *testing.T) *context.AmfUe {
	t.Helper()
	amfSelf := context.GetSelf()
	if len(amfSelf.ServedGuamiList) == 0 {
		amfSelf.ServedGuamiList = []models.Guami{{
			PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"},
			AmfId:  "cafe00",
		}}
	}
	return amfSelf.NewAmfUe("")
}

func releasedRanUeNgapIDs(t *testing.T, conn *gnbConn) []int64 {
	t.Helper()
	var ids []int64
	for _, msg := range conn.messages() {
		decoded, err := ngapMessage.Parse(msg)
		require.NoError(t, err)
		release, ok := decoded.(*ngapMessage.UEContextReleaseCommand)
		require.True(t, ok, "unexpected NGAP message %T", decoded)
		pair, ok := release.UENGAPIDs.Choice.(*ngapType.UENGAPIDPair)
		require.True(t, ok)
		ids = append(ids, pair.RANUENGAPID.Value)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// TestConcurrentAttachToPooledAmfUeReleasesEveryOldRanUe drives the race from
// the pre-authentication SUCI attack: several NGAP workers each run
// AttachRanUeToAmfUeAndReleaseOldIfAny for a new RanUe on one pooled AmfUe,
// while a GMM/SBI goroutine reads the same AmfUe.  Without serialization the
// RanUe map is written concurrently ("fatal error: concurrent map writes"), two
// workers can release the same old RanUe, and a replaced RanUe can stay linked
// without ever being released.
func TestConcurrentAttachToPooledAmfUeReleasesEveryOldRanUe(t *testing.T) {
	const anType = models.AccessType_3_GPP_ACCESS
	const workers = 16
	const rounds = 50

	amfUe := newPooledAmfUe(t)
	conn := &gnbConn{}
	ran := newTestRan(conn)

	var all []*context.RanUe
	for round := 0; round < rounds; round++ {
		ranUes := make([]*context.RanUe, workers)
		for i := range ranUes {
			ranUes[i] = newTestRanUe(ran, int64(round*workers+i+1))
		}
		all = append(all, ranUes...)

		var wg sync.WaitGroup
		start := make(chan struct{})
		for _, ranUe := range ranUes {
			wg.Add(1)
			go func(ranUe *context.RanUe) {
				defer wg.Done()
				<-start
				AttachRanUeToAmfUeAndReleaseOldIfAny(amfUe, ranUe)
			}(ranUe)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < workers; i++ {
				_ = amfUe.CmConnect(anType)
				_ = amfUe.GetAnType()
			}
		}()
		close(start)
		wg.Wait()
	}

	winner := amfUe.RanUe[anType]
	require.NotNil(t, winner)
	require.True(t, amfUe.AnTypeFlags[anType])

	var want []int64
	for _, ranUe := range all {
		if ranUe == winner {
			require.True(t, ranUe.GetAmfUe() == amfUe, "attached RanUe %d is not linked to the AmfUe", ranUe.RanUeNgapId)
			continue
		}
		require.True(t, ranUe.GetAmfUe() == nil, "replaced RanUe %d is still linked to the AmfUe", ranUe.RanUeNgapId)
		want = append(want, ranUe.RanUeNgapId)
	}
	// Every replaced RanUe gets exactly one UE CONTEXT RELEASE COMMAND.
	require.Equal(t, want, releasedRanUeNgapIDs(t, conn))
}

// TestConcurrentAttachesStopRunningTimerOnce drives the same attack while an
// earlier attacker's authentication procedure has T3560 running on the pooled
// AmfUe.  Every attach that replaces a RanUe stops the 5GMM timers.  If two of
// them see the same running T3560, both call Timer.Stop, and the second call
// panics ("send on closed channel" or "close of closed channel"), which ends
// the NGAP worker that runs it.
func TestConcurrentAttachesStopRunningTimerOnce(t *testing.T) {
	const workers = 16
	const rounds = 1000

	conn := &gnbConn{}
	ran := newTestRan(conn)
	for round := 0; round < rounds; round++ {
		amfUe := newPooledAmfUe(t)
		AttachRanUeToAmfUeAndReleaseOldIfAny(amfUe, newTestRanUe(ran, int64(round*(workers+1)+1)))
		amfUe.T3560 = context.NewTimer(time.Minute, 4, func(int32) {}, func() {})

		var wg sync.WaitGroup
		start := make(chan struct{})
		panics := make(chan interface{}, workers)
		for i := 0; i < workers; i++ {
			ranUe := newTestRanUe(ran, int64(round*(workers+1)+i+2))
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() {
					if p := recover(); p != nil {
						panics <- p
					}
				}()
				<-start
				AttachRanUeToAmfUeAndReleaseOldIfAny(amfUe, ranUe)
			}()
		}
		close(start)
		wg.Wait()
		close(panics)
		for p := range panics {
			t.Fatalf("round %d: an attach panicked: %v", round, p)
		}
		require.True(t, amfUe.T3560 == nil, "round %d: T3560 was not stopped", round)
	}
}

// TestAttachPanicDoesNotLeaveRanUeMuLocked covers an attach that panics while
// it stops the old connection's 5GMM timers under RanUeMu.  That happens when
// another path has just stopped the same timer without RanUeMu (for example
// removeRanUeByInvalidId for a forged UE CONTEXT RELEASE REQUEST), because a
// second Timer.Stop panics.  The NGAP worker recovers from the panic and ends;
// RanUeMu must not stay locked, or every later GetRanUe, CmConnect and attach
// on the AmfUe blocks for good, on every NGAP worker and timer goroutine.  The
// test leaves an already stopped T3560 in the field, which is the state that
// race leaves behind.
func TestAttachPanicDoesNotLeaveRanUeMuLocked(t *testing.T) {
	const anType = models.AccessType_3_GPP_ACCESS

	testCases := []struct {
		name   string
		attach func(amfUe *context.AmfUe, oldRanUe, newRanUe *context.RanUe)
	}{
		{
			name: "implicit deregistration",
			attach: func(amfUe *context.AmfUe, _, newRanUe *context.RanUe) {
				AttachRanUeToAmfUeAndReleaseOldIfAny(amfUe, newRanUe)
			},
		},
		{
			name: "handover",
			attach: func(amfUe *context.AmfUe, oldRanUe, newRanUe *context.RanUe) {
				AttachRanUeToAmfUeAndReleaseOldHandover(amfUe, oldRanUe, newRanUe)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			amfUe := newPooledAmfUe(t)
			oldRanUe := newTestRanUe(newTestRan(&gnbConn{}), 1)
			AttachRanUeToAmfUeAndReleaseOldIfAny(amfUe, oldRanUe)
			stopped := context.NewTimer(time.Minute, 4, func(int32) {}, func() {})
			stopped.Stop()
			amfUe.T3560 = stopped
			newRanUe := newTestRanUe(newTestRan(&gnbConn{}), 2)

			var panicked interface{}
			func() {
				defer func() { panicked = recover() }()
				tc.attach(amfUe, oldRanUe, newRanUe)
			}()
			require.NotNil(t, panicked, "test precondition: stopping the stopped T3560 again panics")

			require.True(t, amfUe.RanUeMu.TryLock(), "RanUeMu is still locked after the attach panicked")
			amfUe.RanUeMu.Unlock()
			require.True(t, amfUe.GetRanUe(anType) == newRanUe, "new RanUe is not attached")
		})
	}
}

// TestAttachDoesNotBlockAmfUeReadersDuringRelease checks that the release of
// the replaced RanUe is sent without holding the AmfUe's RanUe lock: if the old
// gNB stops reading, the SCTP write blocks, and readers of the AmfUe (GMM
// sends, N1N2MessageTransfer, timer callbacks, other NGAP workers) must not
// block with it.
func TestAttachDoesNotBlockAmfUeReadersDuringRelease(t *testing.T) {
	const anType = models.AccessType_3_GPP_ACCESS

	testCases := []struct {
		name   string
		attach func(amfUe *context.AmfUe, oldRanUe, newRanUe *context.RanUe)
	}{
		{
			name: "implicit deregistration",
			attach: func(amfUe *context.AmfUe, _, newRanUe *context.RanUe) {
				AttachRanUeToAmfUeAndReleaseOldIfAny(amfUe, newRanUe)
			},
		},
		{
			name: "handover",
			attach: func(amfUe *context.AmfUe, oldRanUe, newRanUe *context.RanUe) {
				AttachRanUeToAmfUeAndReleaseOldHandover(amfUe, oldRanUe, newRanUe)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			amfUe := newPooledAmfUe(t)
			oldConn := &gnbConn{writing: make(chan struct{}, 1), stall: make(chan struct{})}
			oldRanUe := newTestRanUe(newTestRan(oldConn), 1)
			AttachRanUeToAmfUeAndReleaseOldIfAny(amfUe, oldRanUe)
			newRanUe := newTestRanUe(newTestRan(&gnbConn{}), 2)

			done := make(chan struct{})
			go func() {
				defer close(done)
				tc.attach(amfUe, oldRanUe, newRanUe)
			}()

			select {
			case <-oldConn.writing:
			case <-time.After(5 * time.Second):
				close(oldConn.stall)
				t.Fatal("UE CONTEXT RELEASE COMMAND was not sent to the old gNB")
			}

			// The release write to the old gNB is now blocked.
			read := make(chan bool, 1)
			go func() { read <- amfUe.CmConnect(anType) }()
			select {
			case connected := <-read:
				require.True(t, connected)
			case <-time.After(2 * time.Second):
				close(oldConn.stall)
				<-done
				t.Fatal("AmfUe readers blocked while the release to the old gNB was blocked")
			}

			close(oldConn.stall)
			<-done
			require.True(t, amfUe.RanUe[anType] == newRanUe, "new RanUe is not attached")
			require.True(t, oldRanUe.GetAmfUe() == nil, "old RanUe is still linked to the AmfUe")
			require.Len(t, oldConn.messages(), 1)
		})
	}
}
