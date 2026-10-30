package gmm

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

// TestIdentityResponseRacesSuciLookup drives the SUCI write and read from two
// goroutines: the GMM handler records the SUCI from an Identity Response while
// an NGAP worker handling another INITIAL UE MESSAGE scans the UE pool by SUCI
// (AmfUeFindBySuci in handleInitialUEMessageMain).
func TestIdentityResponseRacesSuciLookup(t *testing.T) {
	const supi = "imsi-208930000007487"
	const iterations = 200

	amfSelf := context.GetSelf()
	amfSelf.ServedGuamiList = []models.Guami{{
		PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"},
		AmfId:  "cafe00",
	}}
	ue := amfSelf.NewAmfUe(supi)
	t.Cleanup(func() { amfSelf.UePool.Delete(supi) })
	ue.RequestIdentityType = ie.IdType_5GS_SUCI

	var mobileID ie.MobileId5GS
	require.NoError(t, mobileID.UnmarshalBinary([]byte{
		0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78,
	}))
	suci := mobileID.SUCIStr()
	identityResponse := &nasMessage.IdRsp{MobileId: &mobileID}

	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, iterations)
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			if err := HandleIdentityResponse(ue, identityResponse); err != nil {
				errs <- err
			}
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			_, _ = amfSelf.AmfUeFindBySuci(suci)
		}
	}()
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	found, ok := amfSelf.AmfUeFindBySuci(suci)
	require.True(t, ok)
	require.True(t, found == ue)
}
