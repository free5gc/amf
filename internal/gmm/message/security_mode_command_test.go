package message

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	nas_message "github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

// The AMF sends a SECURITY MODE COMMAND only after a primary authentication and never derives K'AMF
// horizontally (TS 33.501 6.9.3). HDP must therefore never ask the UE to derive one (TS 24.501 5.4.2.3),
// whatever the registration type; RINMR still follows the integrity check of the initial NAS message.
func TestBuildSecurityModeCommandRequestsNoKamfDerivation(t *testing.T) {
	previousConfig := factory.AmfConfig
	factory.AmfConfig = &factory.Config{}
	t.Cleanup(func() { factory.AmfConfig = previousConfig })

	for _, registrationType := range []uint8{
		ie.RegType_InitialReg, ie.RegType_MobilityRegUpdating, ie.RegType_PeriodicRegUpdating, ie.RegType_EmergReg,
	} {
		ue := newGoldenUE()
		ue.RegistrationType5GS = registrationType
		ue.RetransmissionOfInitialNASMsg = true
		payload, err := BuildSecurityModeCommand(ue, models.AccessType_3_GPP_ACCESS, false, "")
		require.NoError(t, err)

		ueSecurity := nas_message.NewSecCtx(nas_message.UESide, nas_message.Bearer3GPP,
			ie.AlgCiphering(ue.CipheringAlg), ie.AlgIntegrity(ue.IntegrityAlg), ue.KnasEnc[:], ue.KnasInt[:])
		decoded, err := nas_message.Parse(payload, ueSecurity)
		require.NoError(t, err)
		securityModeCommand, ok := decoded.(*nas_message.SecModeCmd)
		require.True(t, ok, "expected SECURITY MODE COMMAND, got %T", decoded)
		require.NotNil(t, securityModeCommand.Additional5GSecInfo)
		require.False(t, securityModeCommand.Additional5GSecInfo.HDP, "registration type %d", registrationType)
		require.True(t, securityModeCommand.Additional5GSecInfo.RINMR, "registration type %d", registrationType)
	}
}
