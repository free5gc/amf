package nas_test

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	gmm_common "github.com/free5gc/amf/internal/gmm/common"
	"github.com/free5gc/amf/internal/logger"
	amf_nas "github.com/free5gc/amf/internal/nas"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// These tests deliberately run sequentially: the AMF context, log entries and
// ID allocators are shared globals.
func TestHandleNASInvalidSUCICleansNewAmfUe(t *testing.T) {
	for scheme := uint8(3); scheme <= 15; scheme++ {
		t.Run(fmt.Sprintf("scheme-%d", scheme), func(t *testing.T) {
			fixture := newCleanupFixture(t)
			ranUe := fixture.newRanUe(t)
			require.Nil(t, ranUe.AmfUe)

			fixture.handleInvalidSUCI(t, ranUe, scheme)

			// The error hook sees the real UE after NewAmfUe/Attach and before
			// cleanup. This rules out a test passing solely on early rejection.
			created := fixture.observer.decodingUE
			require.NotNil(t, created)
			require.Positive(t, fixture.observer.decodingTmsi)
			require.Empty(t, created.Supi)
			require.Nil(t, ranUe.AmfUe)
			require.Empty(t, created.RanUe)
			require.Equal(t, 1, fixture.observer.removedUEs, "must also run AmfUe.Remove, not just detach")
			require.True(t, created.State[fixture.ran.AnType].Is(amf_context.Deregistered))
			require.Empty(t, created.Suci)
			require.Nil(t, created.T3560)
		})
	}
}

func TestHandleNASDecodeFailurePreservesExistingAmfUe(t *testing.T) {
	fixture := newCleanupFixture(t)
	ranUe := fixture.newRanUe(t)
	existing := fixture.newAmfUe("imsi-208930000000001")
	gmm_common.AttachRanUeToAmfUeAndReleaseOldIfAny(existing, ranUe)
	tmsi, guti := existing.Tmsi, existing.Guti
	nasPdu := []byte{0x01, 0x02}
	existing.NasPduValue = nasPdu
	existing.MacFailed = true

	fixture.handleInvalidSUCI(t, ranUe, 5)

	require.Same(t, existing, fixture.observer.decodingUE)
	require.Zero(t, fixture.observer.removedUEs)
	require.Same(t, existing, ranUe.AmfUe)
	require.Same(t, ranUe, existing.RanUe[fixture.ran.AnType])
	require.Equal(t, tmsi, existing.Tmsi)
	require.Equal(t, guti, existing.Guti)
	require.Equal(t, nasPdu, existing.NasPduValue)
	require.True(t, existing.MacFailed)
	pooled, ok := fixture.amf.AmfUeFindBySupi(existing.Supi)
	require.True(t, ok)
	require.Same(t, existing, pooled)
	fixture.requireRanUePreserved(t, ranUe, ranUe.AmfUeNgapId)
}

func TestHandleNASDecodeFailurePreservesRanUeResources(t *testing.T) {
	fixture := newCleanupFixture(t)
	ranUe := fixture.newRanUe(t)
	amfID, ranID := ranUe.AmfUeNgapId, ranUe.RanUeNgapId
	fixture.requireRanUePreserved(t, ranUe, amfID)

	fixture.handleInvalidSUCI(t, ranUe, 15)

	require.NotNil(t, fixture.observer.decodingUE)
	require.Nil(t, ranUe.AmfUe)
	require.Empty(t, fixture.observer.decodingUE.RanUe)
	require.Equal(t, 1, fixture.observer.removedUEs)
	require.Equal(t, ranID, ranUe.RanUeNgapId)
	// RanUe.Remove deletes both entries and frees its NGAP ID. Retaining
	// the same object under both IDs detects accidental cascading removal.
	fixture.requireRanUePreserved(t, ranUe, amfID)
}

func TestHandleNASDecodeFailurePreservesHoldingAmfUe(t *testing.T) {
	t.Run("CM-CONNECTED", func(t *testing.T) {
		fixture := newCleanupFixture(t)
		oldRanUe := fixture.newRanUe(t)
		existing := fixture.newAmfUe("imsi-208930000000002")
		gmm_common.AttachRanUeToAmfUeAndReleaseOldIfAny(existing, oldRanUe)
		tmsi := existing.Tmsi
		incoming := fixture.newRanUe(t)
		incoming.HoldingAmfUe = existing

		fixture.handleInvalidSUCI(t, incoming, 5)

		require.NotNil(t, fixture.observer.decodingUE)
		require.NotSame(t, existing, fixture.observer.decodingUE)
		require.Empty(t, fixture.observer.decodingUE.RanUe)
		require.Equal(t, 1, fixture.observer.removedUEs)
		require.Nil(t, incoming.AmfUe)
		require.Same(t, existing, incoming.HoldingAmfUe)
		require.Same(t, existing, oldRanUe.AmfUe)
		require.Same(t, oldRanUe, existing.RanUe[fixture.ran.AnType])
		require.Equal(t, tmsi, existing.Tmsi)
		pooled, ok := fixture.amf.AmfUeFindBySupi(existing.Supi)
		require.True(t, ok)
		require.Same(t, existing, pooled)
		fixture.requireRanUePreserved(t, oldRanUe, oldRanUe.AmfUeNgapId)
		fixture.requireRanUePreserved(t, incoming, incoming.AmfUeNgapId)
	})

	t.Run("CM-IDLE", func(t *testing.T) {
		fixture := newCleanupFixture(t)
		existing := fixture.newAmfUe("imsi-208930000000003")
		tmsi := existing.Tmsi
		incoming := fixture.newRanUe(t)
		incoming.HoldingAmfUe = existing
		require.False(t, existing.CmConnect(fixture.ran.AnType))

		fixture.handleInvalidSUCI(t, incoming, 5)

		// Current behavior attaches the idle context before Decode. No new
		// context is created, so the decode-error cleanup must leave it alone.
		require.Same(t, existing, fixture.observer.decodingUE)
		require.Zero(t, fixture.observer.removedUEs)
		require.Same(t, existing, incoming.AmfUe)
		require.Nil(t, incoming.HoldingAmfUe)
		require.Same(t, incoming, existing.RanUe[fixture.ran.AnType])
		require.True(t, existing.CmConnect(fixture.ran.AnType))
		require.Equal(t, tmsi, existing.Tmsi)
		pooled, ok := fixture.amf.AmfUeFindBySupi(existing.Supi)
		require.True(t, ok)
		require.Same(t, existing, pooled)
		fixture.requireRanUePreserved(t, incoming, incoming.AmfUeNgapId)
	})
}

type cleanupFixture struct {
	amf      *amf_context.AMFContext
	ran      *amf_context.AmfRan
	conn     *ngaptesting.SctpConnStub
	ues      map[*amf_context.AmfUe]bool
	observer *cleanupLogObserver
}

func newCleanupFixture(t *testing.T) *cleanupFixture {
	t.Helper()
	amf := amf_context.GetSelf()
	guamis, tais, gmmLog := amf.ServedGuamiList, amf.SupportTaiLists, logger.GmmLog
	ctxLog := logger.CtxLog
	setupFuzzAMF()
	observer := new(cleanupLogObserver)
	testLog := logrus.New()
	testLog.SetOutput(io.Discard)
	testLog.AddHook(observer)
	logger.GmmLog = logrus.NewEntry(testLog)
	logger.CtxLog = logrus.NewEntry(testLog)
	conn := new(ngaptesting.SctpConnStub)
	ran := amf.NewAmfRan(conn)
	ran.AnType = models.AccessType_3_GPP_ACCESS
	fixture := &cleanupFixture{
		amf: amf, ran: ran, conn: conn, observer: observer,
		ues: make(map[*amf_context.AmfUe]bool),
	}
	t.Cleanup(func() {
		// Include any UE left attached when an assertion fails, so the tests
		// also clean up correctly against the pre-fix implementation.
		ran.RanUeList.Range(func(_, value interface{}) bool {
			if ue := value.(*amf_context.RanUe).AmfUe; ue != nil {
				fixture.ues[ue] = true
			}
			return true
		})
		for ue := range fixture.ues {
			ue.Remove()
		}
		ran.Remove()
		amf.ServedGuamiList, amf.SupportTaiLists, logger.GmmLog = guamis, tais, gmmLog
		logger.CtxLog = ctxLog
	})
	return fixture
}

func (f *cleanupFixture) newRanUe(t *testing.T) *amf_context.RanUe {
	t.Helper()
	var count int64
	f.ran.RanUeList.Range(func(_, _ interface{}) bool { count++; return true })
	ranUe, err := f.ran.NewRanUe(count + 1)
	require.NoError(t, err)
	return ranUe
}

func (f *cleanupFixture) newAmfUe(supi string) *amf_context.AmfUe {
	ue := f.amf.NewAmfUe(supi)
	f.ues[ue] = true
	return ue
}

func (f *cleanupFixture) handleInvalidSUCI(t *testing.T, ranUe *amf_context.RanUe, scheme uint8) {
	t.Helper()
	pdu := registrationRequest(t)
	_, err := message.Parse(pdu, nil)
	require.NoError(t, err)
	// Plain GMM header (3), registration type/ngKSI (1), identity length
	// (2), then byte 6 of the IMSI-format SUCI contains the scheme nibble.
	const schemeOffset = 3 + 1 + 2 + 6
	require.Greater(t, len(pdu), schemeOffset)
	pdu[schemeOffset] = (pdu[schemeOffset] & 0xf0) | scheme
	_, err = message.Parse(pdu, nil)
	wantError := fmt.Sprintf("unsupported protection scheme ID %d", scheme)
	require.ErrorContains(t, err, wantError)

	f.observer.ranUe = ranUe
	amf_nas.HandleNAS(ranUe, ngapMessage.ProcedureCodeInitialUEMessage, pdu, true)

	// Observe the error from HandleNAS itself, not just the parser precheck.
	require.Contains(t, f.observer.decodeError, wantError)
	require.Zero(t, f.observer.authenticationCalls, "must not enter AuthenticationProcedure")
	require.Empty(t, f.conn.MsgList, "must not send authentication, identity or NGAP release messages")
}

func (f *cleanupFixture) requireRanUePreserved(t *testing.T, ranUe *amf_context.RanUe, amfID int64) {
	t.Helper()
	require.Equal(t, amfID, ranUe.AmfUeNgapId)
	require.Same(t, f.ran, ranUe.Ran)
	pooled, ok := f.amf.RanUePool.Load(amfID)
	require.True(t, ok)
	require.Same(t, ranUe, pooled)
	listed, ok := f.ran.RanUeList.Load(ranUe.RanUeNgapId)
	require.True(t, ok)
	require.Same(t, ranUe, listed)
}

// This hook only observes real log events; it does not replace Decode, Attach,
// Remove or any authentication handler.
type cleanupLogObserver struct {
	ranUe               *amf_context.RanUe
	decodingUE          *amf_context.AmfUe
	decodingTmsi        int32 // read when the error is logged: Remove frees the 5G-TMSI
	decodeError         string
	authenticationCalls int
	removedUEs          int
}

func (h *cleanupLogObserver) Levels() []logrus.Level { return logrus.AllLevels }

func (h *cleanupLogObserver) Fire(entry *logrus.Entry) error {
	if strings.Contains(entry.Message, "unsupported protection scheme ID") && h.ranUe != nil {
		h.decodingUE = h.ranUe.AmfUe
		if h.decodingUE != nil {
			h.decodingTmsi = h.decodingUE.GetTmsi()
		}
		h.decodeError = entry.Message
	}
	if entry.Message == "Authentication procedure" {
		h.authenticationCalls++
	}
	if strings.HasPrefix(entry.Message, "AmfUe[") && strings.HasSuffix(entry.Message, "] is removed") {
		h.removedUEs++
	}
	return nil
}
