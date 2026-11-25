package gmm

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/openapi/models"
)

const implicitDeregistrationTestSupi = "imsi-208930000005370"

// newImplicitDeregistrationTestUe returns an idle UE registered over 3GPP access, with a
// subscription and a registration in a UDM that records the requests it gets.
func newImplicitDeregistrationTestUe(t *testing.T) (*context.AmfUe, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var requests []string
	udm := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	udm.Config.Protocols = new(http.Protocols)
	udm.Config.Protocols.SetUnencryptedHTTP2(true) // the SBI client speaks HTTP/2 with prior knowledge
	udm.Start()
	t.Cleanup(udm.Close)

	amfSelf := context.GetSelf()
	amfSelf.ServedGuamiList = []models.Guami{{PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"}, AmfId: "cafe00"}}
	if factory.AmfConfig == nil {
		factory.AmfConfig = &factory.Config{Configuration: &factory.Configuration{}}
	}
	_, err := consumer.NewConsumer(nssaiTestApp{})
	require.NoError(t, err)

	ue := amfSelf.NewAmfUe(implicitDeregistrationTestSupi)
	ue.State[models.AccessType_3_GPP_ACCESS].Set(context.Registered)
	ue.ContextValid = true
	ue.NudmSDMUri = udm.URL
	ue.SdmSubscriptionId = "1"
	ue.NudmUECMUri = udm.URL
	ue.UeCmRegistered[models.AccessType_3_GPP_ACCESS] = true
	return ue, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), requests...)
	}
}

// TS 24.501 5.3.7, TS 23.502 4.2.2.3.3: the implicit de-registration releases the UE's
// subscription and registration in the UDM and removes its context.
func TestImplicitDeregistrationRemovesUe(t *testing.T) {
	ue, udmRequests := newImplicitDeregistrationTestUe(t)

	HandleImplicitDeregistration(ue)

	require.ElementsMatch(t, []string{
		"DELETE /nudm-sdm/v2/" + implicitDeregistrationTestSupi + "/sdm-subscriptions/1",
		"PATCH /nudm-uecm/v1/" + implicitDeregistrationTestSupi + "/registrations/amf-3gpp-access",
	}, udmRequests())
	_, ok := context.GetSelf().AmfUeFindBySupi(implicitDeregistrationTestSupi)
	require.False(t, ok, "the UE context was not removed")
}

// A UE that has contacted the network over 3GPP access, or that is still registered over
// non-3GPP access, is not implicitly de-registered over 3GPP access.
func TestNoImplicitDeregistration(t *testing.T) {
	tests := []struct {
		name  string
		setup func(ue *context.AmfUe)
	}{
		{
			name: "CM-CONNECTED over 3GPP access",
			setup: func(ue *context.AmfUe) {
				ran := &context.AmfRan{
					AnType: models.AccessType_3_GPP_ACCESS, Conn: new(ngaptesting.SctpConnStub), Log: logger.NgapLog,
				}
				ue.AttachRanUe(&context.RanUe{Ran: ran, RanUeNgapId: 1, AmfUeNgapId: 1, Log: logger.NgapLog})
			},
		},
		{
			name: "registered over non-3GPP access",
			setup: func(ue *context.AmfUe) {
				ue.State[models.AccessType_NON_3_GPP_ACCESS].Set(context.Registered)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ue, udmRequests := newImplicitDeregistrationTestUe(t)
			t.Cleanup(ue.Remove)
			tc.setup(ue)

			HandleImplicitDeregistration(ue)

			require.Empty(t, udmRequests())
			got, ok := context.GetSelf().AmfUeFindBySupi(implicitDeregistrationTestSupi)
			require.True(t, ok)
			require.Same(t, ue, got)
		})
	}
}

// A new registration of the UE replaced its context, and the new context holds the UE's
// registration in the UDM: the implicit de-registration of the old context leaves both to it.
func TestImplicitDeregistrationOfReplacedContextKeepsNewContext(t *testing.T) {
	oldUe, udmRequests := newImplicitDeregistrationTestUe(t)
	newUe := context.GetSelf().NewAmfUe(implicitDeregistrationTestSupi)
	t.Cleanup(newUe.Remove)

	HandleImplicitDeregistration(oldUe)

	require.Equal(t, []string{
		"DELETE /nudm-sdm/v2/" + implicitDeregistrationTestSupi + "/sdm-subscriptions/1",
	}, udmRequests(), "the registration in the UDM was purged")
	got, ok := context.GetSelf().AmfUeFindBySupi(implicitDeregistrationTestSupi)
	require.True(t, ok, "the new UE context was removed")
	require.Same(t, newUe, got)
}
