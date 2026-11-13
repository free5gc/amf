package gmm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/fsm"
)

// newAusf starts an NRF that returns one AUSF, and that AUSF, which answers each authentication with a 5G AKA
// challenge.
func newAusf(t *testing.T) string {
	t.Helper()
	var server *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /nnrf-disc/v1/nf-instances", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(models.Nrf_NFDisc_SearchResult{
			NfInstances: []models.Nrf_NFDisc_NFProfile{{
				NfInstanceId: "ausf", NfType: models.Nrf_NFMgmt_NFType_AUSF, NfStatus: models.Nrf_NFMgmt_NFStatus_REGISTERED,
				NfServices: []models.Nrf_NFDisc_NFService{{
					ServiceInstanceId: "1", ServiceName: models.Nrf_NFMgmt_ServiceName_NAUSF_AUTH,
					Scheme: models.UriScheme_HTTP, NfServiceStatus: models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
					ApiPrefix: server.URL,
				}},
			}},
		}); err != nil {
			t.Error(err)
		}
	})
	mux.HandleFunc("POST /nausf-auth/v1/ue-authentications", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/3gppHal+json")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(models.Ausf_UEAU_UEAuthenticationCtx{
			AuthType: models.Ausf_UEAU_AuthType_5_G_AKA,
			Var5gAuthData: models.Ausf_UEAU_Av5gAka{
				Rand:      "00112233445566778899aabbccddeeff",
				HxresStar: "00112233445566778899aabbccddeeff",
				Autn:      "00112233445566778899aabbccddeeff",
			},
		}); err != nil {
			t.Error(err)
		}
	})
	server = httptest.NewUnstartedServer(mux)
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetUnencryptedHTTP2(true) // the SBI client speaks HTTP/2 with prior knowledge
	server.Start()
	t.Cleanup(server.Close)
	return server.URL
}

// TS 24.501 5.4.1.3.2: "If an ngKSI is contained in an initial NAS message during a 5GMM procedure, the
// network shall include a different ngKSI value in the AUTHENTICATION REQUEST message". 5.4.1.3.4: the
// network also includes an ngKSI other than the one of its own 5G NAS security context.
func TestNewChallengeHasAnotherNgKsi(t *testing.T) {
	const periodic, initial, noContext = ie.RegType_PeriodicRegUpdating, ie.RegType_InitialReg, -1
	testCases := []struct {
		name             string
		amfNgKsi         int32 // the ngKSI of the AMF's native security context, noContext if it has none
		registrationType uint8
		requestTsc       ie.SecCtxType
		requestKsi       uint8
		want             uint8
	}{
		{"the ngKSI of the context that the UE and the AMF have", 0, periodic, ie.SecCtxTypeNative, 0, 1},
		{"the last ngKSI wraps", 6, periodic, ie.SecCtxTypeNative, 6, 0},
		{"neither the UE's ngKSI nor the AMF's", 1, periodic, ie.SecCtxTypeNative, 0, 2},
		{"a UE that has no key, the AMF has a context", 0, initial, ie.SecCtxTypeNative, ie.NASKeyNA, 1},
		{"a mapped ngKSI is no native one", 2, periodic, ie.SecCtxTypeMapped, 0, 0},
		{"a UE that has no key, the AMF has no context", noContext, initial, ie.SecCtxTypeNative, ie.NASKeyNA, 0},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			const anType = models.AccessType_3_GPP_ACCESS
			ue, conn := newNssaiTestUe(t)
			context.GetSelf().NrfUri = newAusf(t)
			ue.State[anType].Set(context.Registered)
			ue.CipheringAlg = uint8(nasMessage.AlgCiphering128NEA2)
			ue.IntegrityAlg = uint8(nasMessage.AlgIntegrity128NIA2)
			ue.KnasEnc = [16]byte{1, 2, 3, 4}
			ue.KnasInt = [16]byte{5, 6, 7, 8}
			if tc.amfNgKsi != noContext {
				ue.SecurityContextAvailable = true
				ue.NgKsi = models.Amf_Comm_NgKsi{Tsc: models.Amf_Comm_ScType_NATIVE, Ksi: tc.amfNgKsi}
			}
			ue.MacFailed = true // the request is plain or fails the integrity check
			var guti ie.MobileId5GS
			require.NoError(t, guti.UnmarshalBinary([]byte{0xf2, 0x02, 0xf8, 0x39, 0xca, 0xfe, 0x00, 0, 0, 0, 1}))
			request := &nasMessage.RegReq{
				RegType5GS:      &ie.RegType5GS{Value: tc.registrationType},
				Ngksi:           &ie.NASKeySetId{Tsc: tc.requestTsc, Ksi: tc.requestKsi},
				MobileId5GS:     &guti,
				UESecCapability: &ie.UESecCapability{Length: 2, EA05G: true, IA2_128_5G: true},
			}
			ueSecurity := nasMessage.NewSecCtx(nasMessage.UESide, nasMessage.Bearer3GPP,
				ie.AlgCiphering(ue.CipheringAlg), ie.AlgIntegrity(ue.IntegrityAlg), ue.KnasEnc[:], ue.KnasInt[:])

			require.NoError(t, GmmFSM.SendEvent(ue.State[anType], GmmMessageEvent, fsm.ArgsType{
				ArgAmfUe:         ue,
				ArgAccessType:    anType,
				ArgNASMessage:    request,
				ArgProcedureCode: ngapMessage.ProcedureCodeInitialUEMessage,
			}, logger.GmmLog))

			require.Len(t, conn.MsgList, 1)
			decoded, err := ngapMessage.Parse(conn.MsgList[0])
			require.NoError(t, err)
			downlink, ok := decoded.(*ngapMessage.DownlinkNASTransport)
			require.True(t, ok, "NGAP message is %T", decoded)
			nasMsg, err := nasMessage.Parse(downlink.NASPDU.Value, ueSecurity)
			require.NoError(t, err)
			challenge, ok := nasMsg.(*nasMessage.AuthReq)
			require.True(t, ok, "NAS message is %T", nasMsg)
			require.Equal(t, ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: tc.want}, *challenge.Ngksi)
		})
	}
}
