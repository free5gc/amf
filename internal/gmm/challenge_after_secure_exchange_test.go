package gmm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/fsm"
)

var (
	secureExchangeRand    = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	secureExchangeResStar = []byte{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
)

// newSecureExchangeAusf starts an NRF that returns one AUSF, and that AUSF, which answers each authentication
// with a 5G AKA challenge whose RES* is secureExchangeResStar and confirms that RES*.
func newSecureExchangeAusf(t *testing.T) string {
	t.Helper()
	var server *httptest.Server
	writeJSON := func(w http.ResponseWriter, contentType string, status int, body any) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(body); err != nil {
			t.Error(err)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /nnrf-disc/v1/nf-instances", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, "application/json", http.StatusOK, models.Nrf_NFDisc_SearchResult{
			NfInstances: []models.Nrf_NFDisc_NFProfile{{
				NfInstanceId: "ausf", NfType: models.Nrf_NFMgmt_NFType_AUSF, NfStatus: models.Nrf_NFMgmt_NFStatus_REGISTERED,
				NfServices: []models.Nrf_NFDisc_NFService{{
					ServiceInstanceId: "1", ServiceName: models.Nrf_NFMgmt_ServiceName_NAUSF_AUTH,
					Scheme: models.UriScheme_HTTP, NfServiceStatus: models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
					ApiPrefix: server.URL,
				}},
			}},
		})
	})
	mux.HandleFunc("POST /nausf-auth/v1/ue-authentications", func(w http.ResponseWriter, _ *http.Request) {
		hxresStar := sha256.Sum256(append(append([]byte{}, secureExchangeRand...), secureExchangeResStar...))
		writeJSON(w, "application/3gppHal+json", http.StatusCreated, models.Ausf_UEAU_UEAuthenticationCtx{
			AuthType: models.Ausf_UEAU_AuthType_5_G_AKA,
			Var5gAuthData: models.Ausf_UEAU_Av5gAka{
				Rand:      hex.EncodeToString(secureExchangeRand),
				HxresStar: hex.EncodeToString(hxresStar[16:]),
				Autn:      "00112233445566778899aabbccddeeff",
			},
			Links: map[string][]models.Link{"5g-aka": {{
				Href: server.URL + "/nausf-auth/v1/ue-authentications/1/5g-aka-confirmation",
			}}},
		})
	})
	mux.HandleFunc("PUT /nausf-auth/v1/ue-authentications/1/5g-aka-confirmation",
		func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, "application/json", http.StatusOK, models.Ausf_UEAU_ConfirmationDataResponse{
				AuthResult: models.Ausf_UEAU_AuthResult_SUCCESS,
				Supi:       "imsi-208930000007487",
				Kseaf:      "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
			})
		})
	server = httptest.NewUnstartedServer(mux)
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetUnencryptedHTTP2(true) // the SBI client speaks HTTP/2 with prior knowledge
	server.Start()
	t.Cleanup(server.Close)
	return server.URL
}

// nextNasPdu returns the NAS PDU of the DOWNLINK NAS TRANSPORT that the AMF sent as its n-th NGAP message.
func nextNasPdu(t *testing.T, conn *ngaptesting.SctpConnStub, n int) []byte {
	t.Helper()
	require.Greater(t, len(conn.MsgList), n, "NGAP messages sent")
	decoded, err := ngapMessage.Parse(conn.MsgList[n])
	require.NoError(t, err)
	downlink, ok := decoded.(*ngapMessage.DownlinkNASTransport)
	require.True(t, ok, "NGAP message is %T", decoded)
	return downlink.NASPDU.Value
}

// TS 24.501 4.4.4.1: for the network, integrity protection is mandatory for the 5GMM NAS messages once a
// secure exchange of 5GS NAS messages has been established for the NAS signaling connection, and the UE
// discards a message that is not integrity protected (4.4.4.2). A UE that sends a new initial REGISTRATION
// REQUEST that passes the integrity check gets a protected AUTHENTICATION REQUEST, and the security mode
// control of the new authentication follows its answer.
func TestChallengeAfterSecureExchangeIsProtected(t *testing.T) {
	for _, tc := range []struct {
		name      string
		macFailed bool
	}{
		{"a request that passed the integrity check", false},
		{"a request that is plain or failed the integrity check", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const anType = models.AccessType_3_GPP_ACCESS
			ue, conn := newNssaiTestUe(t)
			amfSelf := context.GetSelf()
			amfSelf.NrfUri = newSecureExchangeAusf(t)
			saved := amfSelf.SecurityAlgorithm
			amfSelf.SecurityAlgorithm = context.SecurityAlgorithm{
				IntegrityOrder: []uint8{uint8(nasMessage.AlgIntegrity128NIA2)},
				CipheringOrder: []uint8{uint8(nasMessage.AlgCiphering128NEA0)},
			}
			t.Cleanup(func() { amfSelf.SecurityAlgorithm = saved })
			ue.State[anType].Set(context.Registered)
			ue.SecurityContextAvailable = true
			ue.NgKsi = models.Amf_Comm_NgKsi{Tsc: models.Amf_Comm_ScType_NATIVE, Ksi: 1}
			ue.CipheringAlg = uint8(nasMessage.AlgCiphering128NEA2)
			ue.IntegrityAlg = uint8(nasMessage.AlgIntegrity128NIA2)
			ue.KnasEnc = [16]byte{1, 2, 3, 4}
			ue.KnasInt = [16]byte{5, 6, 7, 8}
			ue.DLCount.Set(0, 3)
			ue.MacFailed = tc.macFailed
			ueSecurity := nasMessage.NewSecCtx(nasMessage.UESide, nasMessage.Bearer3GPP,
				ie.AlgCiphering(ue.CipheringAlg), ie.AlgIntegrity(ue.IntegrityAlg), ue.KnasEnc[:], ue.KnasInt[:])
			ueSecurity.DownlinkCount.Set(0, 2)

			var guti ie.MobileId5GS
			require.NoError(t, guti.UnmarshalBinary([]byte{0xf2, 0x02, 0xf8, 0x39, 0xca, 0xfe, 0x00, 0, 0, 0, 1}))
			require.NoError(t, GmmFSM.SendEvent(ue.State[anType], GmmMessageEvent, fsm.ArgsType{
				ArgAmfUe:      ue,
				ArgAccessType: anType,
				ArgNASMessage: &nasMessage.RegReq{
					RegType5GS:      &ie.RegType5GS{Value: ie.RegType_InitialReg},
					Ngksi:           &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 1},
					MobileId5GS:     &guti,
					UESecCapability: &ie.UESecCapability{Length: 2, EA05G: true, IA2_128_5G: true},
				},
				ArgProcedureCode: ngapMessage.ProcedureCodeUplinkNASTransport,
			}, logger.GmmLog))
			ue.StopT3560()

			challenge := nextNasPdu(t, conn, 0)
			if tc.macFailed {
				require.Equal(t, nasMessage.SecHdrTypePlainNas, nasMessage.GetSecHdrType(challenge))
				return
			}
			require.Equal(t, nasMessage.SecHdrTypeIntegrityProtectedAndCiphered, nasMessage.GetSecHdrType(challenge))
			msg, err := nasMessage.Parse(challenge, ueSecurity)
			require.NoError(t, err, "the UE takes the challenge under its security context")
			require.IsType(t, &nasMessage.AuthReq{}, msg)

			// The UE answers under its security context; the AMF takes the answer and runs the security mode
			// control of the new authentication.
			require.NoError(t, GmmFSM.SendEvent(ue.State[anType], GmmMessageEvent, fsm.ArgsType{
				ArgAmfUe:      ue,
				ArgAccessType: anType,
				ArgNASMessage: &nasMessage.AuthRsp{AuthRspParam: &ie.AuthRspParam{Res: secureExchangeResStar}},
			}, logger.GmmLog))
			ue.StopT3560()
			require.True(t, ue.State[anType].Is(context.SecurityMode), "GMM state is %s", ue.State[anType].Current())
			command := nextNasPdu(t, conn, 1)
			require.Equal(t, nasMessage.SecHdrTypeIntegrityProtectedWithNew5gNasSecCtx, nasMessage.GetSecHdrType(command))
		})
	}
}
