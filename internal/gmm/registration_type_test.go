package gmm

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/nas/ie"
	"github.com/free5gc/openapi/models"
)

// TS 24.501 9.11.3.7: a REGISTRATION REQUEST of the unused type 0 is an initial registration, which does not keep
// the UE's security context.
func TestRegistrationType0IsInitialRegistration(t *testing.T) {
	ue := newGutiTestUe(t, true)
	require.True(t, ue.SecurityContextAvailable)
	ue.MacFailed = true // the request failed the integrity check

	// Rejected for the missing UE security capability, after the registration type is taken
	require.Error(t, HandleRegistrationRequest(ue, models.AccessType_3_GPP_ACCESS, 0,
		gutiTestRegistrationRequest(t, 0, ue.Guti)))

	require.Equal(t, ie.RegType_InitialReg, ue.RegistrationType5GS)
	require.False(t, ue.SecurityContextAvailable)
}
