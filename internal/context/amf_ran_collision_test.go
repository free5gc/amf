package context

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/openapi/models"
)

func TestNewRanUeRejectsDuplicateRanUeNgapID(t *testing.T) {
	ran := &AmfRan{
		Name:   "test-ran",
		AnType: models.AccessType_3_GPP_ACCESS,
		Log:    logger.NgapLog.WithField("test", t.Name()),
	}
	const ranUeNgapID int64 = 42

	// The first allocation must succeed.
	first, err := ran.NewRanUe(ranUeNgapID)
	require.NoError(t, err)
	require.NotNil(t, first)
	t.Cleanup(func() {
		require.NoError(t, first.Remove())
	})

	// A second allocation with the same ID must be rejected.
	second, err := ran.NewRanUe(ranUeNgapID)
	if second != nil && second != first {
		t.Cleanup(func() {
			require.NoError(t, second.Remove())
		})
	}
	require.Error(t, err)
	require.Nil(t, second)

	// The original per-RAN mapping must survive.
	actual, loaded := ran.RanUeList.Load(ranUeNgapID)
	require.True(t, loaded)
	require.Same(t, first, actual)

	// The original AMF-side mapping and UE fields must also survive.
	require.Same(t, first,
		GetSelf().RanUeFindByAmfUeNgapID(first.AmfUeNgapId))
	require.Same(t, ran, first.Ran)
	require.Equal(t, ranUeNgapID, first.RanUeNgapId)
	require.True(t, first.RanUeNgapIdAssigned)
}
