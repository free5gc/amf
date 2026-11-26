package gmm

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/amf/internal/nas/nas_security"
	nasMessage "github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/fsm"
)

// TestSMCCompleteCommitsPendingContext checks the successful counterpart of
// a MAC-verified SHT=4 SecurityModeComplete commits the pending
// NAS security context and updates the access-network key.
//
// This is a component test, not a complete registration test. The test fixture
// intentionally provides a minimal RegistrationRequest without starting the
// subsequent subscriber-data / SBI registration work in ContextSetup.
// It reuses newSMCRejectTestUE and smcRejectTestUplink from
// smc_reject_pending_test.go.
func TestSMCCompleteCommitsPendingContext(t *testing.T) {
	const accessType = models.AccessType_3_GPP_ACCESS
	ue, _ := newSMCRejectTestUE(t)

	// UpdateSecurityContext derives Kgnb and NH from Kamf after SMC Complete.
	// The Reject fixture only needs KnasInt/Enc, so provide Kamf here.
	ue.Kamf = strings.Repeat("01", 32) // 32-byte test KAMF, hex encoded

	// ContextSetup receives this request after SecurityModeSuccessEvent.
	// RegistrationType5GS remains zero so this component test stops at
	// ContextSetup rather than starting a full registration over SBI.
	ue.RegistrationRequest = &nasMessage.RegReq{}

	require.True(t, ue.IsSMCPending())
	require.True(t, ue.SecurityContextAvailable)
	require.False(t, ue.SecurityContextIsValid(),
		"pending keys must not be treated as established before SMC Complete")
	require.True(t, ue.State[accessType].Is(context.SecurityMode))

	// Build a genuine UE-side, integrity-protected and ciphered NAS message
	// using the pending keys and SHT=4 (new 5G NAS security context).
	payload, err := nasMessage.Marshal(
		&nasMessage.SecModeComplete{},
		smcRejectTestUplink(ue),
		nasMessage.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx,
	)
	require.NoError(t, err)
	require.Equal(t,
		nasMessage.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx,
		nasMessage.GetSecHdrType(payload),
	)

	// Exercise the real AMF uplink NAS decoder, including the integrity check.
	decoded, integrityProtected, err := nas_security.Decode(ue, accessType, payload, false)
	require.NoError(t, err)
	require.True(t, integrityProtected, "SMC Complete must pass NAS integrity verification")
	require.IsType(t, &nasMessage.SecModeComplete{}, decoded)
	ue.MacFailed = !integrityProtected

	// Dispatch the decoded message via the GMM FSM. The SecurityMode handler
	// must accept SMC Complete while pending, derive Kgnb, then commit Pending.
	require.NoError(t, GmmFSM.SendEvent(ue.State[accessType], GmmMessageEvent, fsm.ArgsType{
		ArgAmfUe:         ue,
		ArgAccessType:    accessType,
		ArgProcedureCode: int64(0),
		ArgNASMessage:    decoded,
	}, logger.GmmLog))

	require.True(t, ue.State[accessType].Is(context.ContextSetup),
		"valid SMC Complete should advance GMM to ContextSetup")
	require.False(t, ue.IsSMCPending(),
		"successful SMC must commit the pending security context")
	require.True(t, ue.SecurityContextAvailable)
	require.True(t, ue.SecurityContextIsValid(),
		"committed security context must be usable by subsequent NAS procedures")

	// The previously problematic guard in HandleSecurityModeComplete must use
	// SecurityContextForSMCCompleteIsValid(), not SecurityContextIsValid(),
	// because the latter is deliberately false until SMC succeeds.
	require.Len(t, ue.Kgnb, 32,
		"HandleSecurityModeComplete must derive Kgnb even while SMC is pending")
	require.Len(t, ue.NH, 32, "next-hop key must be derived after SMC Complete")
	require.Equal(t, uint8(1), ue.NCC, "SMC Complete must update NCC")
}

// TestSMCCompleteRequiresSHT4 proves that a protected SMC Complete with SHT=2
// cannot be mistaken for the SHT=4 message that completes new-context SMC.
func TestSMCCompleteRequiresSHT4(t *testing.T) {
	const accessType = models.AccessType_3_GPP_ACCESS
	ue, _ := newSMCRejectTestUE(t)

	payload, err := nasMessage.Marshal(
		&nasMessage.SecModeComplete{},
		smcRejectTestUplink(ue),
		nasMessage.SecHdrTypeIntegrityProtectedAndCiphered, // SHT=2, wrong for SMC Complete
	)
	require.NoError(t, err)

	decoded, integrityProtected, err := nas_security.Decode(ue, accessType, payload, false)
	require.Error(t, err, "SMC Complete with SHT=2 must be rejected")
	require.Nil(t, decoded)
	require.False(t, integrityProtected)
	require.True(t, ue.IsSMCPending())
	require.False(t, ue.SecurityContextIsValid())
	require.True(t, ue.State[accessType].Is(context.SecurityMode))
}

// TestSMCCompleteRejectsInvalidMAC checks that a modified MAC cannot advance
// GMM or commit the new NAS security context.
func TestSMCCompleteRejectsInvalidMAC(t *testing.T) {
	const accessType = models.AccessType_3_GPP_ACCESS
	ue, _ := newSMCRejectTestUE(t)

	payload, err := nasMessage.Marshal(
		&nasMessage.SecModeComplete{},
		smcRejectTestUplink(ue),
		nasMessage.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx,
	)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(payload), 7)

	// The four-byte NAS MAC is at payload[2:6].
	payload[2] ^= 0xff
	decoded, integrityProtected, err := nas_security.Decode(ue, accessType, payload, false)
	require.Error(t, err, "SMC Complete with an invalid MAC must be rejected")
	require.Nil(t, decoded)
	require.False(t, integrityProtected)
	require.True(t, ue.IsSMCPending())
	require.False(t, ue.SecurityContextIsValid())
	require.True(t, ue.State[accessType].Is(context.SecurityMode))
}
