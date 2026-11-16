//nolint:lll // Golden byte fixtures are intentionally kept as contiguous protocol values.
package message

import (
	"encoding/hex"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	nas_message "github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/fsm"
)

// These cases deliberately use no NAS security context.  They lock the AMF
// builder's plain-NAS baseline before the nas module is upgraded.
func TestBuildIdentityRequestSUCIGolden(t *testing.T) {
	got, err := BuildIdentityRequest(
		&context.AmfUe{},
		models.AccessType_3_GPP_ACCESS,
		ie.IdType_5GS_SUCI,
	)
	require.NoError(t, err)
	require.Equal(t, []byte{0x7e, 0x00, 0x5b, 0x01}, got)

	decoded, err := nas_message.Parse(got, nil)
	require.NoError(t, err)
	identityRequest, ok := decoded.(*nas_message.IdReq)
	require.True(t, ok)
	require.Equal(t, ie.IdType_5GS_SUCI, identityRequest.IdType.IdType)
}

func TestBuildAuthenticationRequest5GAKAGolden(t *testing.T) {
	ue := &context.AmfUe{
		NgKsi: models.Amf_Comm_NgKsi{Tsc: models.Amf_Comm_ScType_NATIVE, Ksi: 1},
		ABBA:  []uint8{0x00, 0x00},
		AuthenticationCtx: &models.Ausf_UEAU_UEAuthenticationCtx{
			AuthType: models.Ausf_UEAU_AuthType_5_G_AKA,
			Var5gAuthData: models.Ausf_UEAU_Av5gAka{
				Rand: "000102030405060708090a0b0c0d0e0f",
				Autn: "101112131415161718191a1b1c1d1e1f",
			},
		},
	}

	got, err := BuildAuthenticationRequest(ue, models.AccessType_3_GPP_ACCESS)
	require.NoError(t, err)
	require.Equal(t, []byte{
		0x7e, 0x00, 0x56, 0x01, 0x02, 0x00, 0x00, 0x21, 0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x20, 0x10, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
		0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}, got)

	decoded, err := nas_message.Parse(got, nil)
	require.NoError(t, err)
	authenticationRequest, ok := decoded.(*nas_message.AuthReq)
	require.True(t, ok)
	require.Equal(t, uint8(1), authenticationRequest.Ngksi.Ksi)
}

func TestAMFNASBuilderGoldenBaseline(t *testing.T) {
	previousConfig := factory.AmfConfig
	factory.AmfConfig = &factory.Config{}
	t.Cleanup(func() { factory.AmfConfig = previousConfig })

	builds := []struct {
		name  string
		build func(*context.AmfUe) ([]byte, error)
	}{
		{"dl_nas_transport", func(ue *context.AmfUe) ([]byte, error) {
			cause, timerUnit := uint8(0x07), uint8(0x05)
			return BuildDLNASTransport(ue, models.AccessType_3_GPP_ACCESS, 1, []byte{1, 2, 3}, 1, &cause, &timerUnit, 2)
		}},
		{"notification", func(ue *context.AmfUe) ([]byte, error) {
			return BuildNotification(ue, models.AccessType_3_GPP_ACCESS)
		}},
		{"service_accept", func(ue *context.AmfUe) ([]byte, error) {
			return BuildServiceAccept(ue, models.AccessType_3_GPP_ACCESS, nil, nil, nil, nil)
		}},
		{"authentication_reject", func(ue *context.AmfUe) ([]byte, error) {
			return BuildAuthenticationReject(ue, models.AccessType_3_GPP_ACCESS, "")
		}},
		{"authentication_result", func(ue *context.AmfUe) ([]byte, error) {
			return BuildAuthenticationResult(ue, models.AccessType_3_GPP_ACCESS, true, "AQIDBA==")
		}},
		{"service_reject", func(ue *context.AmfUe) ([]byte, error) {
			return BuildServiceReject(ue, models.AccessType_3_GPP_ACCESS, nil, 0x07)
		}},
		{"registration_reject", func(ue *context.AmfUe) ([]byte, error) {
			return BuildRegistrationReject(ue, models.AccessType_3_GPP_ACCESS, 0x0b, "")
		}},
		{"security_mode_command", func(ue *context.AmfUe) ([]byte, error) {
			return BuildSecurityModeCommand(ue, models.AccessType_3_GPP_ACCESS, true, "AQIDBA==")
		}},
		{"deregistration_request", func(ue *context.AmfUe) ([]byte, error) {
			ranUe := &context.RanUe{}
			ranUe.SetAmfUe(ue)
			return BuildDeregistrationRequest(ranUe, 1, true, 0x07)
		}},
		{"deregistration_accept", func(ue *context.AmfUe) ([]byte, error) {
			return BuildDeregistrationAccept(ue, models.AccessType_3_GPP_ACCESS)
		}},
		{"registration_accept", func(ue *context.AmfUe) ([]byte, error) {
			return BuildRegistrationAccept(ue, models.AccessType_3_GPP_ACCESS, nil, nil, nil, nil)
		}},
		{"status_5gmm", func(ue *context.AmfUe) ([]byte, error) {
			return BuildStatus5GMM(ue, models.AccessType_3_GPP_ACCESS, 0x5f)
		}},
		{"configuration_update_command", func(ue *context.AmfUe) ([]byte, error) {
			payload, err, _ := BuildConfigurationUpdateCommand(ue, models.AccessType_3_GPP_ACCESS,
				&context.ConfigurationUpdateCommandFlags{NeedNetworkSlicingIndication: true})
			return payload, err
		}},
	}

	for _, test := range builds {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.build(newGoldenUE())
			require.NoError(t, err)
			require.Equal(t, amfNASGolden[test.name], hex.EncodeToString(got))
		})
	}
}

var amfNASGolden = map[string]string{
	"dl_nas_transport":             "7e0200000000007e0068010003010203120158073701a2",
	"notification":                 "7e0200000000007e006501",
	"service_accept":               "7e0200000000007e004e",
	"authentication_reject":        "7e0200000000007e0058",
	"authentication_result":        "7e0200000000007e005a0100040102030438020000",
	"service_reject":               "7e0200000000007e004d07",
	"registration_reject":          "7e0200000000007e00440b",
	"security_mode_command":        "7e0300000000007e005d0001020000e13601007800040102030438020000",
	"deregistration_request":       "7e0200000000007e0047055807",
	"deregistration_accept":        "7e0200000000007e0046",
	"registration_accept":          "7e0200000000007e00420101",
	"status_5gmm":                  "7e0200000000007e00645f",
	"configuration_update_command": "7e0200000000007e0054d191",
}

func newGoldenUE() *context.AmfUe {
	return &context.AmfUe{
		SecurityContextAvailable: true,
		CipheringAlg:             0,
		IntegrityAlg:             0,
		NgKsi:                    models.Amf_Comm_NgKsi{Tsc: models.Amf_Comm_ScType_NATIVE, Ksi: 1},
		ABBA:                     []uint8{0, 0},
		KnasEnc:                  [16]uint8{},
		KnasInt:                  [16]uint8{},
		UESecurityCapability:     ie.UESecCapability{Length: 2},
		State: map[models.AccessType]*fsm.State{
			models.AccessType_3_GPP_ACCESS:     fsm.NewState(context.Deregistered),
			models.AccessType_NON_3_GPP_ACCESS: fsm.NewState(context.Deregistered),
		},
		RanUe:            map[models.AccessType]*context.RanUe{},
		RegistrationArea: map[models.AccessType][]models.Tai{},
		AllowedNssai:     map[models.AccessType][]models.Nssf_NSSel_AllowedSnssai{},
		NASLog:           logrus.NewEntry(logrus.New()),
	}
}
