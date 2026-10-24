package context

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/openapi/models"
)

func ranUeListLen(ran *AmfRan) int {
	n := 0
	ran.RanUeList.Range(func(_, _ interface{}) bool {
		n++
		return true
	})
	return n
}

// The handover-target placeholder has no RAN-UE-NGAP-ID yet. Removing or
// switching it must not touch the per-RAN list entry of a connection whose
// legal RAN-UE-NGAP-ID is 0xffffffff, or NG Reset no longer reaches that UE.
func TestHandoverPlaceholderKeepsRanUeNgapIDMaxConnection(t *testing.T) {
	newRan := func() *AmfRan {
		return &AmfRan{AnType: models.AccessType_3_GPP_ACCESS, Log: logger.NgapLog.WithField("", "")}
	}

	t.Run("placeholder is not stored in the per-RAN list", func(t *testing.T) {
		ran := newRan()
		placeholder, err := ran.NewRanUeUnspecified()
		require.NoError(t, err)
		require.False(t, placeholder.RanUeNgapIdAssigned)
		require.Zero(t, ranUeListLen(ran))
		require.Equal(t, placeholder, GetSelf().RanUeFindByAmfUeNgapID(placeholder.AmfUeNgapId))
		require.NoError(t, placeholder.Remove())
	})

	t.Run("Remove", func(t *testing.T) {
		ran := newRan()
		ue, err := ran.NewRanUe(RanUeNgapIdUnspecified)
		require.NoError(t, err)
		require.True(t, ue.RanUeNgapIdAssigned)
		placeholder, err := ran.NewRanUeUnspecified()
		require.NoError(t, err)

		require.NoError(t, placeholder.Remove())

		require.Equal(t, ue, ran.RanUeFindByRanUeNgapID(RanUeNgapIdUnspecified))
		require.Nil(t, GetSelf().RanUeFindByAmfUeNgapID(placeholder.AmfUeNgapId))
		require.NoError(t, ue.Remove())
		require.Zero(t, ranUeListLen(ran))
	})

	t.Run("SwitchToRan", func(t *testing.T) {
		ran, targetRan := newRan(), newRan()
		ue, err := ran.NewRanUe(RanUeNgapIdUnspecified)
		require.NoError(t, err)
		placeholder, err := ran.NewRanUeUnspecified()
		require.NoError(t, err)

		require.NoError(t, placeholder.SwitchToRan(targetRan, 7))

		require.Equal(t, ue, ran.RanUeFindByRanUeNgapID(RanUeNgapIdUnspecified))
		require.Equal(t, placeholder, targetRan.RanUeFindByRanUeNgapID(7))
		require.True(t, placeholder.RanUeNgapIdAssigned)
		require.NoError(t, ue.Remove())
		require.NoError(t, placeholder.Remove())
	})
}
