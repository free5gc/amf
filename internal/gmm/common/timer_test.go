package common

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	ngap_message "github.com/free5gc/amf/internal/ngap/message"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/openapi/models"
)

// TestPagingRacesRegistrationCleanupOnOnGoing drives the onGoing procedure from
// two goroutines.  One plays the SBI N1N2MessageTransfer that pages a CM-IDLE
// UE (SetOnGoing(Paging) + SendPaging) followed by the release path that ends
// paging (StopAll5GSMMTimers).  The other plays the GMM side that clears the
// registration data (T3550 abort, registration reject) and the N2-handover
// check of handleInitialUEMessageMain.  Without serialization the onGoing map
// is read and written concurrently ("fatal error: concurrent map read and map
// write").
func TestPagingRacesRegistrationCleanupOnOnGoing(t *testing.T) {
	const anType = models.AccessType_3_GPP_ACCESS
	const iterations = 200

	amfSelf := context.GetSelf()
	prevT3513 := amfSelf.T3513Cfg
	amfSelf.T3513Cfg = factory.TimerValue{Enable: true, ExpireTime: time.Minute, MaxRetryTimes: 4}
	t.Cleanup(func() { amfSelf.T3513Cfg = prevT3513 })

	amfUe := newPooledAmfUe(t)
	// No gNB serves the UE's registration area, so SendPaging only starts T3513.
	paging := []byte{0x00}

	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			amfUe.SetOnGoing(anType, &context.OnGoing{Procedure: context.OnGoingProcedurePaging, Ppi: 1})
			ngap_message.SendPaging(amfUe, paging)
			StopAll5GSMMTimers(amfUe)
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			amfUe.ClearRegistrationRequestData(anType)
			_ = amfUe.OnGoing(anType).Procedure == context.OnGoingProcedureN2Handover
		}
	}()
	close(start)
	wg.Wait()

	require.Equal(t, context.OnGoingProcedureNothing, amfUe.OnGoing(anType).Procedure)
	require.True(t, amfUe.T3513 == nil)
}
