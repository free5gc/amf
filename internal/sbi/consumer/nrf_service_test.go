package consumer

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/h2non/gock"
	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	Nnrf_NFDiscovery "github.com/free5gc/openapi/nrf/NFDisc"
	"github.com/free5gc/util/nfheartbeat"
)

const (
	testNrfUri   = "http://127.0.0.10:8000"
	testNfId     = "6ba7b810-9dad-41d1-80b4-00c04fd430c8"
	testNfIdPath = "/nnrf-nfm/v1/nf-instances/" + testNfId

	causeNotFound      = "RESOURCE_URI_STRUCTURE_NOT_FOUND"
	causeSystemFailure = "SYSTEM_FAILURE"
)

// newNrfTestConsumer builds a Consumer over a private AMF context pointed at the
// test NRF and intercepts the openapi cleartext HTTP/2 client with gock.
func newNrfTestConsumer(t *testing.T) *Consumer {
	t.Helper()

	c := newTestConsumer(t, newTestAmfContext())

	openapi.InterceptInnerHttp2Client(t, false)
	t.Cleanup(func() {
		// OffAll, not Off: only OffAll clears the unmatched request registry the
		// shutdown tests assert on.
		gock.OffAll()
	})
	return c
}

// nfProfileJSON is an NRF NF profile reply body. It omits heartBeatTimer when
// timer is 0 and customInfo when it is nil.
func nfProfileJSON(timer int32, customInfo map[string]any) map[string]any {
	body := map[string]any{
		"nfInstanceId": testNfId,
		"nfType":       "AMF",
		"nfStatus":     "REGISTERED",
	}
	if timer > 0 {
		body["heartBeatTimer"] = timer
	}
	if customInfo != nil {
		body["customInfo"] = customInfo
	}
	return body
}

func problemJSON(status int, cause string) map[string]any {
	return map[string]any{"status": status, "cause": cause}
}

func TestSendSearchNFInstances(t *testing.T) {
	openapi.InterceptInnerHttp2Client(t, false)
	defer gock.OffAll()

	gock.New(testNrfUri).
		Get("/nnrf-disc/v1/nf-instances").
		MatchParam("target-nf-type", "UDM").
		MatchParam("requester-nf-type", "AMF").
		Reply(http.StatusOK).
		JSON(map[string]interface{}{
			"validityPeriod": 60,
			"nfInstances":    []interface{}{},
		})

	c := newTestConsumer(t, &amf_context.AMFContext{NrfUri: testNrfUri})
	targetNFType := models.Nrf_NFMgmt_NFType_UDM
	requesterNFType := models.Nrf_NFMgmt_NFType_AMF
	request := Nnrf_NFDiscovery.SearchNFInstancesRequest{
		TargetNfType:    &targetNFType,
		RequesterNfType: &requesterNFType,
	}

	result, err := c.SendSearchNFInstances(testNrfUri, targetNFType, requesterNFType, &request)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, int32(60), result.ValidityPeriod)
	require.Empty(t, result.NfInstances)
	require.True(t, gock.IsDone())
}

func TestSendUpdateNFInstance(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		body      map[string]any
		wantTimer int32
		wantErr   bool
	}{
		{
			name:      "200 returns the updated profile",
			status:    http.StatusOK,
			body:      nfProfileJSON(20, nil),
			wantTimer: 20,
		},
		{
			name:   "204 returns an empty profile",
			status: http.StatusNoContent,
		},
		{
			name:    "404 reports the unknown profile",
			status:  http.StatusNotFound,
			body:    problemJSON(http.StatusNotFound, causeNotFound),
			wantErr: true,
		},
		{
			name:    "500 reports the NRF failure",
			status:  http.StatusInternalServerError,
			body:    problemJSON(http.StatusInternalServerError, causeSystemFailure),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newNrfTestConsumer(t)

			reply := gock.New(testNrfUri).
				Patch(testNfIdPath).
				MatchHeader("Content-Type", "application/json-patch+json").
				JSON([]map[string]any{
					{"op": "replace", "path": "/nfStatus", "value": "REGISTERED"},
				}).
				Reply(tt.status)
			if tt.body != nil {
				reply.JSON(tt.body)
			}

			nf, pd, err := c.SendUpdateNFInstance(t.Context(), nfheartbeat.PatchItems())

			if !gock.IsDone() {
				t.Fatal("the heartbeat PATCH was not sent as expected")
			}
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("SendUpdateNFInstance: pd=%+v err=%v", pd, err)
				}
				if nf.HeartBeatTimer != tt.wantTimer {
					t.Errorf("HeartBeatTimer = %d, want %d", nf.HeartBeatTimer, tt.wantTimer)
				}
				return
			}

			var apiErr openapi.GenericOpenAPIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("err = %T (%v), want openapi.GenericOpenAPIError", err, err)
			}
			if apiErr.ErrorStatus != tt.status {
				t.Errorf("ErrorStatus = %d, want %d", apiErr.ErrorStatus, tt.status)
			}
			if pd == nil || pd.Status != int32(tt.status) {
				t.Errorf("ProblemDetails = %+v, want status %d", pd, tt.status)
			}
		})
	}
}

func TestSendUpdateNFInstanceWithoutNrfUri(t *testing.T) {
	c := newTestConsumer(t, &amf_context.AMFContext{NfId: testNfId})

	if _, _, err := c.SendUpdateNFInstance(t.Context(), nfheartbeat.PatchItems()); err == nil {
		t.Error("SendUpdateNFInstance must report the missing NRF instead of panicking")
	}
}

func TestSendDeregisterNFInstance(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       map[string]any
		wantErr    bool
		wantDetail bool
	}{
		{
			name:   "204 deregisters the profile",
			status: http.StatusNoContent,
		},
		{
			name:       "404 reports the unknown profile",
			status:     http.StatusNotFound,
			body:       problemJSON(http.StatusNotFound, causeNotFound),
			wantErr:    true,
			wantDetail: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newNrfTestConsumer(t)

			reply := gock.New(testNrfUri).
				Delete(testNfIdPath).
				Reply(tt.status)
			if tt.body != nil {
				reply.JSON(tt.body)
			}

			pd, err := c.SendDeregisterNFInstance()

			if !gock.IsDone() {
				t.Fatal("the deregistration DELETE was not sent as expected")
			}
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Errorf("SendDeregisterNFInstance err = %v, want error %v", err, tt.wantErr)
			}
			if gotDetail := pd != nil; gotDetail != tt.wantDetail {
				t.Errorf("ProblemDetails = %+v, want detail %v", pd, tt.wantDetail)
			}
			if tt.wantDetail && pd.Status != int32(tt.status) {
				t.Errorf("ProblemDetails.Status = %d, want %d", pd.Status, tt.status)
			}
		})
	}
}

// TestRegisterNFInstanceRetriesUntilSuccess drives the retry loop: the first
// PUT fails on the NRF, the retry one interval later succeeds.
func TestRegisterNFInstanceRetriesUntilSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newNrfTestConsumer(t)

		gock.New(testNrfUri).
			Put(testNfIdPath).
			Reply(http.StatusInternalServerError).
			JSON(problemJSON(http.StatusInternalServerError, causeSystemFailure))
		gock.New(testNrfUri).
			Put(testNfIdPath).
			Reply(http.StatusCreated).
			JSON(nfProfileJSON(15, nil))

		if err := c.SendRegisterNFInstance(t.Context(), false); err != nil {
			t.Fatalf("RegisterNFInstance: %v", err)
		}
		if !gock.IsDone() {
			t.Fatal("expected a failed PUT followed by a successful retry")
		}
		if c.heartbeatTimer != 15 {
			t.Errorf("heartbeatTimer = %d, want 15 from the retry", c.heartbeatTimer)
		}
	})
}

// TestRegisterNFInstanceStopsOnCancel proves the retry loop gives up once the
// context is canceled instead of retrying forever.
func TestRegisterNFInstanceStopsOnCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := newNrfTestConsumer(t)

		gock.New(testNrfUri).
			Put(testNfIdPath).
			Persist().
			Reply(http.StatusInternalServerError).
			JSON(problemJSON(http.StatusInternalServerError, causeSystemFailure))

		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()

		if err := c.SendRegisterNFInstance(ctx, false); err == nil {
			t.Fatal("RegisterNFInstance must fail once the context is canceled")
		}
	})
}

func TestSendRegisterNFInstance(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        map[string]any
		applyOAuth2 bool
		wantTimer   int32
		wantOAuth2  bool
	}{
		{
			name:        "201 adopts the returned timer",
			status:      http.StatusCreated,
			body:        nfProfileJSON(15, map[string]any{"oauth2": true}),
			applyOAuth2: true,
			wantTimer:   15,
			wantOAuth2:  true,
		},
		{
			name:      "200 on a profile the NRF already holds",
			status:    http.StatusOK,
			body:      nfProfileJSON(25, nil),
			wantTimer: 25,
		},
		{
			name:        "re-registration leaves the oauth2 setting untouched",
			status:      http.StatusCreated,
			body:        nfProfileJSON(0, map[string]any{"oauth2": true}),
			applyOAuth2: false,
			wantOAuth2:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newNrfTestConsumer(t)

			gock.New(testNrfUri).
				Put(testNfIdPath).
				Reply(tt.status).
				JSON(tt.body)

			if err := c.SendRegisterNFInstance(t.Context(), tt.applyOAuth2); err != nil {
				t.Fatalf("RegisterNFInstance: %v", err)
			}
			if !gock.IsDone() {
				t.Fatal("the registration PUT was not sent as expected")
			}
			if c.heartbeatTimer != tt.wantTimer {
				t.Errorf("heartbeatTimer = %d, want %d", c.heartbeatTimer, tt.wantTimer)
			}
			if got := c.Context().OAuth2Required; got != tt.wantOAuth2 {
				t.Errorf("OAuth2Required = %v, want %v", got, tt.wantOAuth2)
			}
			// The AMF keeps the instance ID it chose, whatever the NRF echoes back.
			if got := c.Context().NfId; got != testNfId {
				t.Errorf("NfId = %q, want %q", got, testNfId)
			}
		})
	}
}
