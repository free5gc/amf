package context

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAmfUeRemoveKeepsReplacementInUePool(t *testing.T) {
	amfSelf := GetSelf()
	oldAmfUe := &AmfUe{Supi: "imsi-208930000001084"}
	newAmfUe := &AmfUe{Supi: oldAmfUe.Supi}
	amfSelf.UePool.Store(newAmfUe.Supi, newAmfUe)
	t.Cleanup(func() { amfSelf.UePool.CompareAndDelete(newAmfUe.Supi, newAmfUe) })

	oldAmfUe.Remove()

	storedAmfUe, ok := amfSelf.AmfUeFindBySupi(newAmfUe.Supi)
	require.True(t, ok)
	require.Same(t, newAmfUe, storedAmfUe)
}
