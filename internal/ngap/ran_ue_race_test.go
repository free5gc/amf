package ngap

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/openapi/models"
)

// TestRanUePointersRaceWithRemove drives the RanUe/AmfUe cross pointers, and the
// reverse pointer map, from the goroutine that owns them while a reader on
// another goroutine takes the same snapshots, and removes the RanUe (UE CONTEXT
// RELEASE COMPLETE, NG Reset or the loss of the SCTP association) while the
// reader is still running.  The accessors must keep all of it race-free: the
// AmfUe link, the re-registration link (GetHoldingAmfUe) and the reverse
// pointer (AmfUe.GetRanUe).
func TestRanUePointersRaceWithRemove(t *testing.T) {
	const anType = models.AccessType_3_GPP_ACCESS
	const iterations = 200

	amfSelf := amf_context.GetSelf()
	NewAmfContext(amfSelf)
	ran, _ := newHoTestRan("000003")
	ue := amfSelf.NewAmfUe("imsi-208930000000998")
	t.Cleanup(ue.Remove)
	ranUe, err := ran.NewRanUe(1)
	require.NoError(t, err)

	var (
		wg        sync.WaitGroup
		removeErr error
	)
	start := make(chan struct{})
	done := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			ranUe.SetHoldingAmfUe(ue)
			ranUe.SetAmfUe(ue)
			ue.AttachRanUe(ranUe)
			ue.DetachRanUe(anType, ranUe)
			ranUe.ClearHoldingAmfUe()
			ranUe.DetachAmfUe()
		}
		// Leave both links in place so Remove detaches a non-nil AmfUe, and
		// remove the RanUe while the reader below is still taking snapshots.
		ue.AttachRanUe(ranUe)
		ranUe.SetAmfUe(ue)
		removeErr = ranUe.Remove()
		close(done)
	}()
	go func() {
		defer wg.Done()
		<-start
		for {
			select {
			case <-done:
				return
			default:
			}
			_ = ranUe.GetAmfUe()
			_ = ranUe.GetHoldingAmfUe()
			_ = ue.GetRanUe(anType)
		}
	}()
	close(start)
	wg.Wait()

	require.NoError(t, removeErr)
	require.Nil(t, amfSelf.RanUeFindByAmfUeNgapID(ranUe.AmfUeNgapId))
	require.Nil(t, ue.GetRanUe(anType))
}
