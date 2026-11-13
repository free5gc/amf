package gmm

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	ngapType "github.com/free5gc/ngap/ie"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
)

// newSmfTestSmContext gives the UE PDU session 5 at an SMF that answers every SM context update with
// status and an SmContextUpdateError with cause, or with a ProblemDetails body if cause is "".
func newSmfTestSmContext(t *testing.T, ue *context.AmfUe, status int, cause string) {
	t.Helper()
	ct, body := "application/problem+json", []byte(`{"status":503,"cause":"NF_CONGESTION"}`)
	if cause != "" {
		var err error
		ct, body, err = openapi.Serialize(models.UpdateSmContextResponse403{
			JsonData: &models.Smf_PDUSess_SmContextUpdateError{
				Error: &models.Smf_PDUSess_ExtProblemDetails{Status: int32(status), Cause: cause},
			},
		}, "application/json")
		require.NoError(t, err)
	}
	smf := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(status)
		if _, err := w.Write(body); err != nil {
			t.Error(err)
		}
	}))
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	smf.Config.Protocols = protocols
	smf.Start()
	t.Cleanup(smf.Close)

	sm := context.NewSmContext(5)
	sm.SetSmfUri(smf.URL)
	sm.SetSmContextRef("sm-context-5")
	sm.SetSnssai(nssaiTestServed)
	sm.SetAccessType(models.AccessType_3_GPP_ACCESS)
	ue.StoreSmContext(5, sm)
}

// TS 24.501 5.6.1.4.1 a) and b): the user-plane resources of a PDU session that the SMF refuses to
// re-establish for a service request (TS 29.502 6.1.3.3.4.2.2) are in the PDU session reactivation result
// error cause IE with the 5GMM cause of the SMF's cause. A ProblemDetails body on a 503 stays an error
// of the request.
func TestServiceRequestReactivationRefusedBySmf(t *testing.T) {
	for name, test := range map[string]struct {
		status   int
		cause    string
		errCause []uint8
	}{
		"out of LADN service area": {
			http.StatusForbidden, "OUT_OF_LADN_SERVICE_AREA", []uint8{ie.Cause5GMM_LADNNotAvailable},
		},
		"prioritized services only": {
			http.StatusForbidden, "PRIORITIZED_SERVICES_ONLY", []uint8{ie.Cause5GMM_RestrictedSvcArea},
		},
		"ProblemDetails body on 503": {http.StatusServiceUnavailable, "", nil},
	} {
		t.Run(name, func(t *testing.T) {
			ue, _ := newNssaiTestUe(t)
			newSmfTestSmContext(t, ue, test.status, test.cause)
			var uplinkDataPsi, reactivationResult [psiArraySize]bool
			uplinkDataPsi[5] = true

			errPduSessionID, errCause := reactivatePendingULDataPDUSession(ue, models.AccessType_3_GPP_ACCESS,
				uint8(ie.SvcType_Data), &uplinkDataPsi, 0, &ngapType.PDUSessionResourceSetupListCxtReq{},
				&reactivationResult, nil, nil)
			require.True(t, reactivationResult[5], "user-plane resources not re-established")
			require.Equal(t, test.errCause, errCause)
			if test.errCause != nil {
				require.Equal(t, []uint8{5}, errPduSessionID)
			}
		})
	}
}

// TS 24.501 5.4.5.2.5 a) 12): the SM context of a PDU session ID that an initial request reuses is
// released locally when the SMF refuses to release it, as when the request fails.
func TestDuplicatePduSessionIDReleasedLocallyWhenSmfRefuses(t *testing.T) {
	ue, _ := newNssaiTestUe(t)
	ue.Guti = "20893cafe0000000001"
	newSmfTestSmContext(t, ue, http.StatusNotFound, "CONTEXT_NOT_FOUND")

	err := transport5GSMMessage(ue, models.AccessType_3_GPP_ACCESS, &nasMessage.ULNASTransport{
		PayloadCntrType: &ie.PayloadCntrType{Value: ie.PayloadCntrType_N1SMInfo},
		PayloadCntr:     &ie.PayloadCntr{Contents: []byte{0x2e, 0x05, 0x01, 0xc1, 0xff, 0xff, 0x91}},
		PDUSessID:       &ie.PDUSessId2{Value: 5},
		ReqType:         &ie.ReqType{Value: ie.ReqType_InitialReq},
	})
	_, ok := ue.SmContextFindByPDUSessionID(5)
	require.False(t, ok, "not released locally (%v)", err)
}
