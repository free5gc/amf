package context

import (
	"sync"
	"testing"

	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/ngap/aper"
	"github.com/free5gc/ngap/ie"
	"github.com/free5gc/openapi/models"
)

// LocationCopy, which the local release of a connection calls on another goroutine, does not race with the
// connection's UpdateLocation and SetLocation (go test -race).
func TestLocationCopyWhileTheLocationIsUpdated(t *testing.T) {
	ranUe := &RanUe{Log: logger.NgapLog}
	plmn := aper.OctetString{0x02, 0xf8, 0x39}
	location := &ie.UserLocationInformation{Choice: &ie.UserLocationInformationNR{
		NRCGI: &ie.NRCGI{
			PLMNIdentity:   &ie.PLMNIdentity{Value: plmn},
			NRCellIdentity: &ie.NRCellIdentity{Value: aper.BitString{Bytes: []byte{0, 0, 0, 0, 0x10}, BitLength: 36}},
		},
		TAI: &ie.TAI{PLMNIdentity: &ie.PLMNIdentity{Value: plmn}, TAC: &ie.TAC{Value: aper.OctetString{0, 0, 1}}},
	}}
	var writers sync.WaitGroup
	writers.Go(func() {
		for range 100 {
			ranUe.UpdateLocation(location)
		}
	})
	writers.Go(func() {
		for range 100 {
			ranUe.SetLocation(models.UserLocation{})
		}
	})
	for range 100 {
		ranUe.LocationCopy()
	}
	writers.Wait()
}
