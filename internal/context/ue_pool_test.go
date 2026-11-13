package context

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/openapi/models"
)

// A UE context that has authenticated a SUPI without being stored under it, such as one with
// AuthenticatingFor set, does not remove the stored UE context of that SUPI when it is removed.
func TestRemoveKeepsTheStoredContextOfTheSameSupi(t *testing.T) {
	const supi = "imsi-208930000000003"
	self := GetSelf()
	previousServedGuamiList := self.ServedGuamiList
	self.ServedGuamiList = []models.Guami{{PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"}, AmfId: "cafe00"}}
	t.Cleanup(func() { self.ServedGuamiList = previousServedGuamiList })

	stored := self.NewAmfUe(supi)
	t.Cleanup(stored.Remove)
	authenticating := self.NewAmfUe("")
	authenticating.AuthenticatingFor = stored
	authenticating.Supi = supi

	authenticating.Remove()
	found, ok := self.AmfUeFindBySupi(supi)
	require.True(t, ok)
	require.Same(t, stored, found)

	stored.Remove()
	_, ok = self.AmfUeFindBySupi(supi)
	require.False(t, ok)
}
