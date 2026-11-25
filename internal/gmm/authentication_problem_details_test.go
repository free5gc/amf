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
// handler must prefer its ProblemDetails when choosing the NAS reject cause.
//
// Call the procedure directly so the separate duplicate-reject issue in the
// FSM's HandleAuthenticationError does not affect this test.
func TestAuthenticationProcedureAUSFRejectionCause(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		invalidMNC bool
		wantCause  uint8
		wantAUSF   int32
	}{
		{
			name: "forbidden", status: http.StatusForbidden,
			body:      `{"status":403,"cause":"AUTHENTICATION_REJECTED"}`,
			wantCause: ie.Cause5GMM_IllegalUE, wantAUSF: 1,
		},
		{
			name: "not_found", status: http.StatusNotFound,
			body:      `{"status":404,"cause":"USER_NOT_FOUND"}`,
			wantCause: ie.Cause5GMM_IllegalUE, wantAUSF: 1,
		},
		{
			name: "server_error", status: http.StatusInternalServerError,
			body:      `{"status":500,"cause":"SYSTEM_FAILURE"}`,
			wantCause: ie.Cause5GMM_Congestion, wantAUSF: 1,
		},
		{
			name: "malformed_body", status: http.StatusNotFound,
			body:      `{"status":`,
			wantCause: ie.Cause5GMM_Congestion, wantAUSF: 1,
		},
		{
			// strconv.Atoi in the consumer returns an error without
			// ProblemDetails, before sending the AUSF request.
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
			reject, ok := nasMsg.(*nasMessage.RegRej)
			require.True(t, ok, "NAS message is %T", nasMsg)
			require.NotNil(t, reject.Cause5GMM)
			require.Equal(t, tc.wantCause, reject.Cause5GMM.Value)
		})
	}
}
