package context

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A re-authentication of a UE with a valid security context must still lead to a security mode command.
func TestDerivateKamfNeedsSecurityModeControl(t *testing.T) {
	ue := &AmfUe{
		Supi:                     "imsi-208930000000001",
		ABBA:                     []uint8{0x00, 0x00},
		Kseaf:                    "6b2a8b3d0e7c1f4a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2",
		SecurityContextAvailable: true,
	}
	ue.NgKsi.Ksi = 1
	require.True(t, ue.SecurityContextIsValid())

	ue.DerivateKamf()

	require.NotEmpty(t, ue.Kamf)
	require.False(t, ue.SecurityContextIsValid(), "the new KAMF was taken for the valid security context")
}
