package gmm

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/nas/ie"
	ngapType "github.com/free5gc/ngap/ie"
	"github.com/free5gc/openapi/models"
)

// TS 23.502 4.2.3.2: a service request activates the user plane of a PDU session at the UE's N2 connection. Once the
// SMF accepted it, a late deactivation for an N2 connection of the UE released before is not sent; when the SMF
// rejects it, the deactivation is sent.
func TestServiceRequestActivatesUserPlaneAtItsConnection(t *testing.T) {
	const anType = models.AccessType_3_GPP_ACCESS
	for name, accepted := range map[string]bool{"accepted": true, "rejected": false} {
		t.Run(name, func(t *testing.T) {
			smf := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if !accepted {
					w.Header().Set("Content-Type", "application/problem+json")
					w.WriteHeader(http.StatusInternalServerError)
					if err := json.NewEncoder(w).Encode(models.ProblemDetails{
						Status: http.StatusInternalServerError, Cause: "SYSTEM_FAILURE",
					}); err != nil {
						t.Errorf("SMF stub write: %v", err)
					}
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(models.Smf_PDUSess_SmContextUpdatedData{
					UpCnxState: models.Smf_PDUSess_UpCnxState_ACTIVATING,
				}); err != nil {
					t.Errorf("SMF stub write: %v", err)
				}
			}))
			smf.Config.Protocols = new(http.Protocols)
			smf.Config.Protocols.SetUnencryptedHTTP2(true) // the SBI client uses h2c
			smf.Start()
			t.Cleanup(smf.Close)
			ue, _ := newNssaiTestUe(t)
			smContext := context.NewSmContext(5)
			smContext.SetSmfUri(smf.URL)
			smContext.SetSmContextRef("sm-context-5")
			smContext.SetSnssai(nssaiTestServed)
			smContext.SetAccessType(anType)
			ue.StoreSmContext(5, smContext)
			ranUe := ue.GetRanUe(anType)
			released := &context.RanUe{Ran: ranUe.Ran}

			var uplinkDataPsi, reactivationResult [psiArraySize]bool
			uplinkDataPsi[5] = true
			var cxtList ngapType.PDUSessionResourceSetupListCxtReq
			errPduSessionID, _ := reactivatePendingULDataPDUSession(ue, anType, uint8(ie.SvcType_Data), &uplinkDataPsi, 0,
				&cxtList, &reactivationResult, nil, nil)
			if accepted {
				require.Empty(t, errPduSessionID)
				require.Len(t, cxtList.List, 1, "the user plane is not activated")
			} else {
				require.True(t, reactivationResult[5], "the failed activation is not reported")
			}

			require.Equal(t, !accepted, smContext.DeactivateUpCnx(ranUe.Ran, released, func() {}),
				"the deactivation for the released connection is sent: %v", !accepted)
		})
	}
}
