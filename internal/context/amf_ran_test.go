package context

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/ngap/aper"
	"github.com/free5gc/ngap/ie"
)

func TestRemoveAndRemoveAllRanUeRaceCondition(t *testing.T) {
	ran := &AmfRan{
		Log: logger.NgapLog.WithField("", ""),
	}

	// create ranUe & store in RanUeList
	for i := 1; i <= 10000; i++ {
		ranUe, err := ran.NewRanUe(int64(i))
		require.NoError(t, err)
		ran.RanUeList.Store(i, ranUe)
	}

	require.NotPanics(t, func() { runRanUeRemove(ran) })
}

func runRanUeRemove(ran *AmfRan) {
	for i := 1; i <= 10000; i++ {
		go ran.RanUeList.Delete(i)
	}
	ran.RemoveAllRanUe(true)
}

// A GlobalGNBID whose gNB-ID uses the choice-Extensions alternative leaves
// RanId.GNbId nil. RanID() is called when the association is removed, and
// used to dereference GNbId there, which exited the AMF.
func TestRanIDWithGNBIDChoiceExtensions(t *testing.T) {
	ran := &AmfRan{Log: logger.NgapLog.WithField("", "")}
	ran.SetRanId(&ie.GlobalRANNodeID{
		Choice: &ie.GlobalGNBID{
			PLMNIdentity: &ie.PLMNIdentity{Value: aper.OctetString{0x02, 0xf8, 0x39}},
			GNBID:        &ie.GNBID{Choice: &ie.ProtocolIESingleContainerGNBIDExtIEs{}},
		},
	})
	require.Equal(t, RanPresentGNbId, ran.RanPresent)
	require.NotNil(t, ran.RanId)
	require.Nil(t, ran.RanId.GNbId)

	require.NotPanics(t, func() {
		require.Equal(t, "<PlmnID: {Mcc:208 Mnc:93}, GNbID: >", ran.RanID())
	})
	require.NotPanics(t, ran.Remove)
}
