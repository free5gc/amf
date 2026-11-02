package context

import (
	"sync"
	"testing"

	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/openapi/models"
)

// TestAttachRanUeAndCmConnectAreSerialized exercises the two operations that
// raced in the pre-authentication SUCI attach: an NGAP worker attaching a
// RanUe to a pooled AmfUe while another worker (or a GMM/SBI goroutine) reads
// the same AmfUe to decide whether it is CM-connected.  Run with -race; on the
// unpatched tree the map write in AttachRanUe and the map read behind
// CmConnect are concurrent.
func TestAttachRanUeAndCmConnectAreSerialized(t *testing.T) {
	ue := &AmfUe{
		RanUe:       make(map[models.AccessType]*RanUe),
		AnTypeFlags: make(map[models.AccessType]bool),
		NASLog:      logger.GmmLog,
		GmmLog:      logger.GmmLog,
		ProducerLog: logger.ProducerLog,
	}
	ran := &AmfRan{AnType: models.AccessType_3_GPP_ACCESS, Log: logger.NgapLog}
	ranUe := &RanUe{
		Ran:         ran,
		RanUeNgapId: 1,
		AmfUeNgapId: 1,
		Log:         logger.NgapLog,
	}

	const iterations = 2000
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < iterations; j++ {
				_ = ue.CmConnect(models.AccessType_3_GPP_ACCESS)
				_ = ue.GetAnType()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for j := 0; j < iterations; j++ {
			ue.AttachRanUe(ranUe)
		}
	}()

	close(start)
	wg.Wait()

	if got := ue.RanUe[models.AccessType_3_GPP_ACCESS]; got != ranUe {
		t.Fatalf("attached RanUe = %p, want %p", got, ranUe)
	}
}
