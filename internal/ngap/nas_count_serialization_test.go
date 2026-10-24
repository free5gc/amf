package ngap

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/nas/nas_security"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	nas_message "github.com/free5gc/nas/message"
	ngapType "github.com/free5gc/ngap/ie"
	"github.com/free5gc/openapi/models"
)

// An INITIAL UE MESSAGE naming a UE by its 5G-S-TMSI makes the AMF verify the NAS MAC against
// that UE's context before binding, on a copy of the uplink NAS COUNT. The UE's own uplink is
// decoded on another NGAP worker at the same time. The copy is taken under the COUNT lock (no
// data race), the pre-binding check never moves the stored COUNT, and no COUNT is accepted twice.
func TestPreBindingVerifyWithConcurrentDecode(t *testing.T) {
	const fiveGSTmsi = "fe0000000002"
	knasEnc := [16]byte{1, 2, 3, 4}
	knasInt := [16]byte{5, 6, 7, 8}

	previousConfig := factory.AmfConfig
	factory.AmfConfig = &factory.Config{}
	t.Cleanup(func() { factory.AmfConfig = previousConfig })

	amfSelf := amf_context.GetSelf()
	NewAmfContext(amfSelf)
	amfUe := amfSelf.NewAmfUe("imsi-208930000000002")
	amfUe.Guti = "20893cafe0000000002"
	amfUe.State[models.AccessType_3_GPP_ACCESS].Set(amf_context.Registered)
	amfUe.SecurityContextAvailable = true
	amfUe.NgKsi = models.Amf_Comm_NgKsi{Tsc: models.Amf_Comm_ScType_NATIVE, Ksi: 1}
	amfUe.CipheringAlg = uint8(nas_message.AlgCiphering128NEA2)
	amfUe.IntegrityAlg = uint8(nas_message.AlgIntegrity128NIA2)
	amfUe.KnasEnc = knasEnc
	amfUe.KnasInt = knasInt

	ueSecurity := nas_message.NewSecCtx(nas_message.UESide, nas_message.Bearer3GPP,
		nas_message.AlgCiphering128NEA2, nas_message.AlgIntegrity128NIA2, knasEnc[:], knasInt[:])
	// A SERVICE REQUEST with a forged MAC, sent by someone who knows the 5G-S-TMSI only.
	ueSecurity.UplinkCount.Set(0, 200)
	forged, err := nas_message.Marshal(&nas_message.SvcReq{
		Ngksi: &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 1},
		// This spelling is the name exported by the NAS API.
		SvcType: &ie.SvcType{Value: ie.SvcType_Signalling}, //nolint:misspell
		TMSI5GS: &ie.MobileId5GS{TypeOfId: ie.IdType_5GS_TMSI, TMSI5G: [4]byte{0, 0, 0, 2}},
	}, ueSecurity, nas_message.SecHdrTypeIntegrityProtected)
	require.NoError(t, err)
	forged[2] ^= 0xff
	// The UE's own uplink at COUNT 10, 11, ...
	uplink := make([][]byte, 1500)
	for i := range uplink {
		ueSecurity.UplinkCount.Set(uint16((10+i)>>8), uint8(10+i))
		uplink[i], err = nas_message.Marshal(&nas_message.CfgUpdateComplete{}, ueSecurity,
			nas_message.SecHdrTypeIntegrityProtectedAndCiphered)
		require.NoError(t, err)
	}

	for round := 0; round < 40; round++ {
		amfUe.ULCount.Set(0, 9)
		amfUe.ULCount.MarkAccepted()
		ran := NewAmfRan(new(ngaptesting.SctpConnStub))
		initialUEMessage := BuildInitialUEMessage(t, 1, forged, fiveGSTmsi)
		initialUEMessage.UEContextRequest = &ngapType.UEContextRequest{
			Value: ngapType.UEContextRequestPresentRequested,
		}
		encoded, marshalErr := initialUEMessage.MarshalBinary()
		require.NoError(t, marshalErr)

		var attackerDone atomic.Bool
		var wg sync.WaitGroup
		start := make(chan struct{})
		last := -1
		wg.Add(2)
		go func() {
			defer wg.Done()
			defer attackerDone.Store(true)
			<-start
			for i := 0; i < 20; i++ {
				handleInitialUEMessageMain(
					ran, encoded, initialUEMessage.RANUENGAPID, initialUEMessage.NASPDU,
					initialUEMessage.UserLocationInformation, initialUEMessage.RRCEstablishmentCause,
					initialUEMessage.FiveGSTMSI, initialUEMessage.UEContextRequest,
				)
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < len(uplink) && !attackerDone.Load(); i++ {
				_, integrityProtected, decodeErr := nas_security.Decode(
					amfUe, models.AccessType_3_GPP_ACCESS, uplink[i], false)
				if decodeErr == nil && integrityProtected {
					last = i
				}
			}
		}()
		close(start)
		wg.Wait()

		require.GreaterOrEqual(t, last, 0)
		require.Equal(t, uint32(10+last), amfUe.ULCount.Get(),
			"round %d: uplink COUNT rolled back by the pre-binding MAC check", round)
		_, integrityProtected, decodeErr := nas_security.Decode(
			amfUe, models.AccessType_3_GPP_ACCESS, uplink[last], false)
		require.False(t, decodeErr == nil && integrityProtected, "round %d: COUNT %d accepted twice", round, 10+last)
	}
}
