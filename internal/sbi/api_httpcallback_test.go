package sbi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/openapi/models"
)

func TestNotificationRoutesWithoutOAuthToken(t *testing.T) {
	amfContext := amf_context.GetSelf()
	previousOAuth := amfContext.OAuth2Required.Load()
	previousConfig := factory.AmfConfig
	t.Cleanup(func() {
		amfContext.OAuth2Required.Store(previousOAuth)
		factory.AmfConfig = previousConfig
	})
	amfContext.OAuth2Required.Store(true)
	factory.AmfConfig = &factory.Config{
		Configuration: &factory.Configuration{
			ServiceNameList: []string{string(models.Nrf_NFMgmt_ServiceName_NAMF_COMM)},
		},
	}

	router := newRouter(&Server{})
	for _, path := range []string{
		"/am-policy/test/update",
		"/am-policy/test/terminate",
		"/smContextStatus/imsi-208930000001155/1",
		"/n1-message-notify",
		"/deregistration/imsi-208930000001155",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequestWithContext(
				t.Context(), http.MethodPost, factory.AmfCallbackResUriPrefix+path, strings.NewReader("{"),
			)
			req.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			router.ServeHTTP(response, req)

			// Malformed input lets the actual handler respond without invoking the processor.
			require.Equal(t, http.StatusBadRequest, response.Code)
			require.Contains(t, response.Body.String(), "INVALID_MSG_FORMAT")
		})
	}

	t.Run("non-notification services still require OAuth", func(t *testing.T) {
		req := httptest.NewRequestWithContext(
			t.Context(), http.MethodPost, factory.AmfCommResUriPrefix+"/ue-contexts/test/n1-n2-messages", nil,
		)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		require.Equal(t, http.StatusUnauthorized, response.Code)
	})
}
