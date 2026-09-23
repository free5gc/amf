package context

import (
	"sync"
	"testing"

	"github.com/free5gc/openapi/models"
)

// TestAmfUeRanUeConcurrentAccess protects the regression case where NAS
// handling reads RanUe while SCTP shutdown detaches it.
func TestAmfUeRanUeConcurrentAccess(t *testing.T) {
	ue := &AmfUe{}
	ue.init()
	anType := models.AccessType("3GPP_ACCESS")
	ran := &AmfRan{AnType: anType}
	ranUe := &RanUe{Ran: ran, AmfUe: ue}
	ue.AttachRanUe(ranUe)

	var wg sync.WaitGroup
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = ue.GetRanUe(anType)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		ue.DetachRanUe(anType)
	}()
	wg.Wait()
}
