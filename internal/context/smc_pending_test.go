package context

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/openapi/models"
)

// The AMF needs the pending keys to verify SMC Complete, but must not treat
// those keys as established for a subsequent Service Request.
func TestSMCPendingLifecycle(t *testing.T) {
	ue := &AmfUe{
		SecurityContextAvailable: true,
		NgKsi:                    models.Amf_Comm_NgKsi{Ksi: 1},
	}

	require.True(t, ue.SecurityContextIsValid())
	require.False(t, ue.IsSMCPending())

	ue.BeginSMC()
	require.True(t, ue.IsSMCPending())
	require.True(t, ue.SecurityContextForSMCCompleteIsValid())
	require.False(t, ue.SecurityContextIsValid(), "pending keys must not authorize service")

	ue.CompleteSMC()
	require.False(t, ue.IsSMCPending())
	require.True(t, ue.SecurityContextAvailable)
	require.True(t, ue.SecurityContextIsValid())
}

func TestSMCAbortInvalidatesPendingContext(t *testing.T) {
	ue := &AmfUe{
		SecurityContextAvailable: true,
		NgKsi:                    models.Amf_Comm_NgKsi{Ksi: 1},
	}
	ue.BeginSMC()
	ue.AbortSMC()

	require.False(t, ue.IsSMCPending())
	require.False(t, ue.SecurityContextAvailable)
	require.False(t, ue.SecurityContextIsValid())

	// Repeated failure handling must not change the resulting invalid state.
	ue.AbortSMC()
	require.False(t, ue.SecurityContextAvailable)
}

func TestSMCAbortDoesNotClearContextWhenNoNewSMCIsPending(t *testing.T) {
	ue := &AmfUe{
		SecurityContextAvailable: true,
		NgKsi:                    models.Amf_Comm_NgKsi{Ksi: 1},
	}

	ue.AbortSMC()
	require.True(t, ue.SecurityContextAvailable)
	require.True(t, ue.SecurityContextIsValid())
}
