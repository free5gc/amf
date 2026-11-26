package gmm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// Regression for free5gc/free5gc#1278. Exercise the real OpenAPI client and
// consumer: a decoded AUSF rejection also carries a non-nil Go error. The
// handler must prefer ProblemDetails and map Status + Cause to the NAS message.
// TS 29.524 V17.4.0, Table 4.2.2-1. Unknown combinations use the chosen
// Registration Reject / Congestion fallback; that fallback is not a claim
// that the specification mandates it for every unknown error.
//
// HTTP 504 mappings are not covered here: the current UeAuthenticationsPost
// OpenAPI client does not decode a 504 ProblemDetails body. It must preserve
// that response before the handler's 504 application-cause branches can be
// exercised through the real client. This suite does not prove 504 support.
// Reuses newNssaiTestUe from requested_nssai_test.go.
//
// Call the procedure directly so the separate duplicate-reject issue in the
// FSM's HandleAuthenticationError does not affect this test.
func TestAuthenticationProcedureAUSFRejectionCause(t *testing.T) {
	tests := []struct {
		name           string
		status         int
		body           string
		invalidMNC     bool
		wantAuthReject bool
		wantCause      uint8
		wantAUSF       int32
	}{
		{
			name: "serving_network_not_authorized", status: 403,
			body:           `{"status":403,"cause":"SERVING_NETWORK_NOT_AUTHORIZED"}`,
			wantAuthReject: false, wantCause: ie.Cause5GMM_ServingNwNotAutho, wantAUSF: 1,
		},
		{
			name: "authentication_rejected", status: 403,
			body:           `{"status":403,"cause":"AUTHENTICATION_REJECTED"}`,
			wantAuthReject: true, wantCause: 0, wantAUSF: 1,
		},
		{
			name: "invalid_hn_public_key", status: 403,
			body:           `{"status":403,"cause":"INVALID_HN_PUBLIC_KEY_IDENTIFIER"}`,
			wantAuthReject: true, wantCause: 0, wantAUSF: 1,
		},
		{
			name: "user_not_found", status: 404,
			body:           `{"status":404,"cause":"USER_NOT_FOUND"}`,
			wantAuthReject: true, wantCause: 0, wantAUSF: 1,
		},
		{
			name: "context_not_found", status: 404,
			body:           `{"status":404,"cause":"CONTEXT_NOT_FOUND"}`,
			wantAuthReject: true, wantCause: 0, wantAUSF: 1,
		},
		{
			name: "av_generation_problem", status: 500,
			body:           `{"status":500,"cause":"AV_GENERATION_PROBLEM"}`,
			wantAuthReject: true, wantCause: 0, wantAUSF: 1,
		},
		{
			name: "unsupported_protection_scheme", status: 501,
			body:           `{"status":501,"cause":"UNSUPPORTED_PROTECTION_SCHEME"}`,
			wantAuthReject: true, wantCause: 0, wantAUSF: 1,
		},
		{
			name: "system_failure_fallback", status: 500,
			body:           `{"status":500,"cause":"SYSTEM_FAILURE"}`,
			wantAuthReject: false, wantCause: ie.Cause5GMM_Congestion, wantAUSF: 1,
		},
		{
			name: "unknown_403_cause", status: 403,
			body:           `{"status":403,"cause":"UNRECOGNIZED_CAUSE"}`,
			wantAuthReject: false, wantCause: ie.Cause5GMM_Congestion, wantAUSF: 1,
		},
		{
			name: "unknown_404_cause", status: 404,
			body:           `{"status":404,"cause":"UNRECOGNIZED_CAUSE"}`,
			wantAuthReject: false, wantCause: ie.Cause5GMM_Congestion, wantAUSF: 1,
		},
		{
			name: "missing_cause", status: 403,
			body:           `{"status":403,"cause":""}`,
			wantAuthReject: false, wantCause: ie.Cause5GMM_Congestion, wantAUSF: 1,
		},
		{
			name: "cause_with_wrong_status", status: 400,
			body:           `{"status":400,"cause":"AUTHENTICATION_REJECTED"}`,
			wantAuthReject: false, wantCause: ie.Cause5GMM_Congestion, wantAUSF: 1,
		},
		{
			name: "malformed_body", status: http.StatusNotFound,
			body:      `{"status":`,
			wantCause: ie.Cause5GMM_Congestion, wantAUSF: 1,
		},
		{
			// Return an err without ProblemDetails before sending the request.
			name: "local_error_without_problem_details", invalidMNC: true,
			wantCause: ie.Cause5GMM_Congestion,
		},
	}

	// These cases use the package's shared AMF context and consumer; do not
	// run them in parallel.
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			self := context.GetSelf()
			oldGuamis, oldTais := self.ServedGuamiList, self.SupportTaiLists
			oldPlmns, oldNrf := self.PlmnSupportList, self.NrfUri
			oldOAuth, oldConfig := self.OAuth2Required.Load(), factory.AmfConfig
			t.Cleanup(func() {
				self.ServedGuamiList, self.SupportTaiLists = oldGuamis, oldTais
				self.PlmnSupportList, self.NrfUri = oldPlmns, oldNrf
				self.OAuth2Required.Store(oldOAuth)
				factory.AmfConfig = oldConfig
			})

			ue, conn := newNssaiTestUe(t)
			self.OAuth2Required.Store(false)
			ue.SetSuci("suci-0-208-93-0000-0-0-0000000099")
			ue.SecurityContextAvailable = false

			var ausfCalls atomic.Int32
			var server *httptest.Server
			mux := http.NewServeMux()
			mux.HandleFunc("GET /nnrf-disc/v1/nf-instances", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				err := json.NewEncoder(w).Encode(models.Nrf_NFDisc_SearchResult{
					NfInstances: []models.Nrf_NFDisc_NFProfile{{
						NfInstanceId: "ausf", NfType: models.Nrf_NFMgmt_NFType_AUSF,
						NfStatus: models.Nrf_NFMgmt_NFStatus_REGISTERED,
						NfServices: []models.Nrf_NFDisc_NFService{{
							ServiceInstanceId: "1", ServiceName: models.Nrf_NFMgmt_ServiceName_NAUSF_AUTH,
							Scheme:          models.UriScheme_HTTP,
							NfServiceStatus: models.Nrf_NFMgmt_NFServiceStatus_REGISTERED,
							ApiPrefix:       server.URL,
						}},
					}},
				})
				if err != nil {
					t.Error(err)
				}
			})
			mux.HandleFunc("POST /nausf-auth/v1/ue-authentications", func(w http.ResponseWriter, _ *http.Request) {
				ausfCalls.Add(1)
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(tc.status)
				if _, err := w.Write([]byte(tc.body)); err != nil {
					t.Error(err)
				}
			})
			server = httptest.NewUnstartedServer(mux)
			server.Config.Protocols = new(http.Protocols)
			server.Config.Protocols.SetUnencryptedHTTP2(true)
			server.Start()
			t.Cleanup(server.Close)
			self.NrfUri = server.URL
			if tc.invalidMNC {
				self.ServedGuamiList[0].PlmnId.Mnc = "invalid"
			}

			pass, err := AuthenticationProcedure(ue, models.AccessType_3_GPP_ACCESS)
			require.Error(t, err)
			require.False(t, pass)
			require.Equal(t, tc.wantAUSF, ausfCalls.Load(),
				"ensure the test reaches the intended AUSF response or local error")
			require.Nil(t, ue.AuthenticationCtx, "a rejected authentication must not install a context")
			require.Len(t, conn.MsgList, 1, "the procedure must send a reject, not a challenge")

			decoded, err := ngapMessage.Parse(conn.MsgList[0])
			require.NoError(t, err)
			downlink, ok := decoded.(*ngapMessage.DownlinkNASTransport)
			require.True(t, ok, "NGAP message is %T", decoded)
			nasMsg, err := nasMessage.ParseGMM(downlink.NASPDU.Value)
			require.NoError(t, err)
			if tc.wantAuthReject {
				require.IsType(t, &nasMessage.AuthRej{}, nasMsg,
					"this application cause requires Authentication Reject")
				// Authentication Reject has no Cause5GMM field.
				return
			}
			reject, ok := nasMsg.(*nasMessage.RegRej)
			require.True(t, ok, "NAS message is %T", nasMsg)
			require.NotNil(t, reject.Cause5GMM)
			require.Equal(t, tc.wantCause, reject.Cause5GMM.Value)
		})
	}
}
