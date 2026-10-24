package gmm

import (
	"sync"
	"testing"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/openapi/models"
)

// newGutiRaceTestUe returns a UE whose 5G-GUTI and 5G-TMSI can be allocated, with
// the served GUAMI it needs, and restores the served GUAMI list afterwards.
func newGutiRaceTestUe(t *testing.T, supi string) *context.AmfUe {
	t.Helper()
	amfSelf := context.GetSelf()
	previous := amfSelf.ServedGuamiList
	amfSelf.ServedGuamiList = []models.Guami{{
		PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"},
		AmfId:  "cafe00",
	}}
	t.Cleanup(func() { amfSelf.ServedGuamiList = previous })
	return amfSelf.NewAmfUe(supi)
}

// TestGutiReallocationRacesGutiLookup drives the 5G-GUTI state machine from the
// GMM goroutine while an NGAP worker or an SBI handler scans the UE pool by
// 5G-GUTI (AmfUeFindByGuti).  The UE keeps a retained 5G-GUTI valid while the
// new one is unacknowledged, so both the current and the old 5G-GUTI are read
// while another goroutine assigns and releases them.
func TestGutiReallocationRacesGutiLookup(t *testing.T) {
	const iterations = 200

	amfSelf := context.GetSelf()
	ue := newGutiRaceTestUe(t, "imsi-208930000007488")
	t.Cleanup(ue.Remove)
	// The lookup argument is hoisted out of the reader: computing it with GetGuti
	// inside the loop would order the unsynchronised access in MatchesGuti after
	// the writer's accesses on a single-CPU run, hiding the race.
	query := ue.GetGuti()

	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			// Alternate between a request that names the 5G-GUTI the UE had
			// before the loop (the retained one once it has been replaced) and
			// one that names no identity.
			used := ""
			if i%2 == 1 {
				used = query
			}
			amfSelf.ReallocateGuti(ue, used)
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			_, _ = amfSelf.AmfUeFindByGuti(query)
			_ = ue.HasOldGuti()
			amfSelf.ReleaseOldGuti(ue)
		}
	}()
	close(start)
	wg.Wait()
}

// TestGutiAllocationAndRemoveRaceWithLookup drives the two other writers of the
// 5G-GUTI state, AllocateGutiToUe and Remove, while a reader scans the UE pool
// and reads the same identities.
func TestGutiAllocationAndRemoveRaceWithLookup(t *testing.T) {
	const allocations = 50

	amfSelf := context.GetSelf()
	ue := newGutiRaceTestUe(t, "imsi-208930000007489")
	// Hoisted for the same reason as above.
	query := ue.GetGuti()

	var wg sync.WaitGroup
	start := make(chan struct{})
	done := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < allocations; i++ {
			amfSelf.AllocateGutiToUe(ue)
		}
		ue.Remove()
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
			_, _ = amfSelf.AmfUeFindByGuti(query)
			_ = ue.GetGuti()
			_ = ue.GetTmsi()
			_ = ue.HasOldGuti()
			_ = ue.MatchesGuti(query)
		}
	}()
	close(start)
	wg.Wait()
}
