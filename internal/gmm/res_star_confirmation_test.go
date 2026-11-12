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
	"github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/fsm"
)

// TS 33.501 6.1.3.2.2 (TS 33.512 4.2.2.1.2, test cases A and B): when HRES* and HXRES* differ, the SEAF
// still sends the RES* that the UE sent to the AUSF, then rejects the authentication of a UE that registered
// with its SUCI, or asks a UE that registered with its 5G-GUTI for its SUCI. It does the same when the AUSF
// does not confirm the authentication.
func TestResStarIsSentToTheAusf(t *testing.T) {
	rand := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	xresStar := []byte{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
	wrongResStar := []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	hxresStar := sha256.Sum256(append(append([]byte{}, rand...), xresStar...))

	for _, tc := range []struct {
		name       string
		identity   uint8
		resStar    []byte
		ausfStatus int // the AUSF's answer: 200 with the result of its own check, or an error
		want       nasMessage.MsgType
	}{
		{
			"a wrong RES* of a UE that registered with its SUCI", ie.IdType_5GS_SUCI, wrongResStar,
			http.StatusOK, nasMessage.MsgTypeAuthRej,
		},
		{
			"a wrong RES* of a UE that registered with its 5G-GUTI", ie.IdType_5GS_GUTI, wrongResStar,
			http.StatusOK, nasMessage.MsgTypeIdReq,
		},
		{
			"no confirmation of the AUSF", ie.IdType_5GS_SUCI, xresStar,
			http.StatusInternalServerError, nasMessage.MsgTypeAuthRej,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const anType = models.AccessType_3_GPP_ACCESS
			ue, conn := newNssaiTestUe(t)

			var received []string
			mux := http.NewServeMux()
			mux.HandleFunc("PUT /nausf-auth/v1/ue-authentications/1/5g-aka-confirmation",
				func(w http.ResponseWriter, r *http.Request) {
					var confirmation models.Ausf_UEAU_ConfirmationData
					if err := json.NewDecoder(r.Body).Decode(&confirmation); err != nil {
						t.Error(err)
					}
					if confirmation.ResStar != nil {
						received = append(received, *confirmation.ResStar)
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(tc.ausfStatus)
					var body any = models.Ausf_UEAU_ConfirmationDataResponse{AuthResult: models.Ausf_UEAU_AuthResult_FAILURE}
					if tc.ausfStatus != http.StatusOK {
						body = models.ProblemDetails{Status: int32(tc.ausfStatus), Cause: "UPSTREAM_SERVER_ERROR"}
					}
					if err := json.NewEncoder(w).Encode(body); err != nil {
						t.Error(err)
					}
				})
			ausf := httptest.NewUnstartedServer(mux)
			ausf.Config.Protocols = new(http.Protocols)
			ausf.Config.Protocols.SetUnencryptedHTTP2(true) // the SBI client speaks HTTP/2 with prior knowledge
			ausf.Start()
			t.Cleanup(ausf.Close)

			ue.State[anType].Set(context.Authentication)
			ue.AusfUri = ausf.URL
			ue.IdentityTypeUsedForRegistration = tc.identity
			ue.AuthenticationCtx = &models.Ausf_UEAU_UEAuthenticationCtx{
				AuthType: models.Ausf_UEAU_AuthType_5_G_AKA,
				Var5gAuthData: models.Ausf_UEAU_Av5gAka{
					Rand:      hex.EncodeToString(rand),
					HxresStar: hex.EncodeToString(hxresStar[16:]),
					Autn:      "00112233445566778899aabbccddeeff",
				},
				Links: map[string][]models.Link{"5g-aka": {{
					Href: ausf.URL + "/nausf-auth/v1/ue-authentications/1/5g-aka-confirmation",
				}}},
			}

			require.NoError(t, GmmFSM.SendEvent(ue.State[anType], GmmMessageEvent, fsm.ArgsType{
				ArgAmfUe:      ue,
				ArgAccessType: anType,
				ArgNASMessage: &nasMessage.AuthRsp{AuthRspParam: &ie.AuthRspParam{Res: tc.resStar}},
			}, logger.GmmLog))
			ue.StopT3570()

			require.Equal(t, []string{hex.EncodeToString(tc.resStar)}, received, "RES* sent to the AUSF")
			require.NotEmpty(t, conn.MsgList) // a reject is followed by the release of the connection
			decoded, err := ngapMessage.Parse(conn.MsgList[0])
			require.NoError(t, err)
			downlink, ok := decoded.(*ngapMessage.DownlinkNASTransport)
			require.True(t, ok, "NGAP message is %T", decoded)
			msg, err := nasMessage.Parse(downlink.NASPDU.Value, nil)
			require.NoError(t, err)
			require.Equal(t, tc.want, msg.MsgType())
		})
	}
}

// TS 33.501 6.1.3.2.2: when the AUSF does not answer the confirmation of an EAP-AKA' authentication, or answers
// it with an error, the AMF rejects the authentication of a UE that registered with its SUCI, or asks a UE that
// registered with its 5G-GUTI for its SUCI.
func TestEapConfirmationErrorEndsTheAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name     string
		identity uint8
		want     nasMessage.MsgType
	}{
		{"a UE that registered with its SUCI", ie.IdType_5GS_SUCI, nasMessage.MsgTypeAuthRej},
		{"a UE that registered with its 5G-GUTI", ie.IdType_5GS_GUTI, nasMessage.MsgTypeIdReq},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const anType = models.AccessType_3_GPP_ACCESS
			ue, conn := newNssaiTestUe(t)

			mux := http.NewServeMux()
			mux.HandleFunc("POST /nausf-auth/v1/ue-authentications/1/eap-session",
				func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/problem+json")
					w.WriteHeader(http.StatusInternalServerError)
					if _, err := w.Write([]byte(`{"status":500,"cause":"UPSTREAM_SERVER_ERROR"}`)); err != nil {
						t.Error(err)
					}
				})
			ausf := httptest.NewUnstartedServer(mux)
			ausf.Config.Protocols = new(http.Protocols)
			ausf.Config.Protocols.SetUnencryptedHTTP2(true) // the SBI client speaks HTTP/2 with prior knowledge
			ausf.Start()
			t.Cleanup(ausf.Close)

			ue.State[anType].Set(context.Authentication)
			ue.AusfUri = ausf.URL
			ue.IdentityTypeUsedForRegistration = tc.identity
			ue.AuthenticationCtx = &models.Ausf_UEAU_UEAuthenticationCtx{
				AuthType:      models.Ausf_UEAU_AuthType_EAP_AKA_PRIME,
				Var5gAuthData: "AQIDBA==",
				Links: map[string][]models.Link{"eap-session": {{
					Href: ausf.URL + "/nausf-auth/v1/ue-authentications/1/eap-session",
				}}},
			}

			require.NoError(t, GmmFSM.SendEvent(ue.State[anType], GmmMessageEvent, fsm.ArgsType{
				ArgAmfUe:      ue,
				ArgAccessType: anType,
				ArgNASMessage: &nasMessage.AuthRsp{EAPMsg: &ie.EAPMsg{Eap: []byte{2, 1, 0, 4}}},
			}, logger.GmmLog))
			ue.StopT3570()

			require.NotEmpty(t, conn.MsgList) // a reject is followed by the release of the connection
			decoded, err := ngapMessage.Parse(conn.MsgList[0])
			require.NoError(t, err)
			downlink, ok := decoded.(*ngapMessage.DownlinkNASTransport)
			require.True(t, ok, "NGAP message is %T", decoded)
			msg, err := nasMessage.Parse(downlink.NASPDU.Value, nil)
			require.NoError(t, err)
			require.Equal(t, tc.want, msg.MsgType())
		})
	}
}
