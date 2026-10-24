package ngap

import (
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	nas_message "github.com/free5gc/nas/message"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// TS 24.501 4.4.3.2: a SERVICE REQUEST replayed at an already accepted COUNT fails the
// integrity check and is not accepted; the 5GMM and 5G NAS security contexts are kept
// (TS 24.501 4.4.4.3). The answer to the failed message is left to the MAC-failure handling.
func TestHandleInitialUEMessageServiceRequestCount(t *testing.T) {
	const ranUeNgapID int64 = 1
	const fiveGSTmsi = "fe0000000001"
	const serviceRequestCount = 5
	knasEnc := [16]byte{1, 2, 3, 4}
	knasInt := [16]byte{5, 6, 7, 8}

	previousConfig := factory.AmfConfig
	factory.AmfConfig = &factory.Config{}
	t.Cleanup(func() { factory.AmfConfig = previousConfig })

	testCases := []struct {
		name        string
		storedCount uint8
		replay      bool
	}{
		{name: "replayed COUNT", storedCount: serviceRequestCount, replay: true},
		{name: "fresh COUNT", storedCount: serviceRequestCount - 1},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			amfSelf := amf_context.GetSelf()
			NewAmfContext(amfSelf)
			connStub := new(ngaptesting.SctpConnStub)
			ran := NewAmfRan(connStub)

			amfUe := amfSelf.NewAmfUe("imsi-208930000000001")
			amfUe.Guti = "20893cafe0000000001"
			amfUe.State[models.AccessType_3_GPP_ACCESS].Set(amf_context.Registered)
			amfUe.SecurityContextAvailable = true
			amfUe.NgKsi = models.Amf_Comm_NgKsi{Tsc: models.Amf_Comm_ScType_NATIVE, Ksi: 1}
			amfUe.CipheringAlg = uint8(nas_message.AlgCiphering128NEA2)
			amfUe.IntegrityAlg = uint8(nas_message.AlgIntegrity128NIA2)
			amfUe.KnasEnc = knasEnc
			amfUe.KnasInt = knasInt
			amfUe.AllowedNssai[models.AccessType_3_GPP_ACCESS] = []models.Nssf_NSSel_AllowedSnssai{
				{AllowedSnssai: &models.Snssai{Sst: 1, Sd: "010203"}},
			}
			amfUe.ULCount.Set(0, test.storedCount)
			amfUe.ULCount.MarkAccepted()

			ueSecurity := nas_message.NewSecCtx(nas_message.UESide, nas_message.Bearer3GPP,
				nas_message.AlgCiphering128NEA2, nas_message.AlgIntegrity128NIA2, knasEnc[:], knasInt[:])
			ueSecurity.UplinkCount.Set(0, serviceRequestCount)
			serviceRequest, err := nas_message.Marshal(&nas_message.SvcReq{
				Ngksi: &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 1},
				// This spelling is the name exported by the NAS API.
				SvcType: &ie.SvcType{Value: ie.SvcType_Signalling}, //nolint:misspell
				TMSI5GS: &ie.MobileId5GS{TypeOfId: ie.IdType_5GS_TMSI, TMSI5G: [4]byte{0, 0, 0, 1}},
			}, ueSecurity, nas_message.SecHdrTypeIntegrityProtected)
			require.NoError(t, err)

			initialUEMessage := BuildInitialUEMessage(t, ranUeNgapID, serviceRequest, fiveGSTmsi)
			initialUEMessage.UEContextRequest = &ngapType.UEContextRequest{
				Value: ngapType.UEContextRequestPresentRequested,
			}
			encoded, err := initialUEMessage.MarshalBinary()
			require.NoError(t, err)
			handleInitialUEMessageMain(
				ran, encoded, initialUEMessage.RANUENGAPID, initialUEMessage.NASPDU,
				initialUEMessage.UserLocationInformation, initialUEMessage.RRCEstablishmentCause,
				initialUEMessage.FiveGSTMSI, initialUEMessage.UEContextRequest,
			)

			require.Equal(t, uint32(serviceRequestCount), amfUe.ULCount.Get())
			require.True(t, amfUe.SecurityContextAvailable)
			require.True(t, amfUe.State[models.AccessType_3_GPP_ACCESS].Is(amf_context.Registered))
			accepted := false
			for _, sent := range connStub.MsgList {
				decoded, parseErr := ngapMessage.Parse(sent)
				require.NoError(t, parseErr)
				if _, ok := decoded.(*ngapMessage.InitialContextSetupRequest); ok {
					accepted = true
				}
				if downlink, ok := decoded.(*ngapMessage.DownlinkNASTransport); ok {
					nasPdu, nasErr := nas_message.Parse(downlink.NASPDU.Value, ueSecurity)
					require.NoError(t, nasErr)
					_, isServiceAccept := nasPdu.(*nas_message.SvcAccept)
					accepted = accepted || isServiceAccept
				}
			}
			require.Equal(t, !test.replay, accepted)
		})
	}
}
