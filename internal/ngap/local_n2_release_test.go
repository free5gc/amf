package ngap

import (
	"encoding/json"
	"fmt"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/pkg/app"
	ngapType "github.com/free5gc/ngap/ie"
	"github.com/free5gc/openapi/models"
)

// TS 23.502 4.2.6: when the NG-AP signaling connection is lost due to (R)AN or AMF failure, the AMF performs
// the AN release locally, and the AN release causes all UP connections of the UE to be deactivated. When the
// SCTP association of a gNB is lost, or an NG RESET releases a UE's connection, the AMF asks the SMF of each
// PDU session of the UE on that access to deactivate its user plane.
func TestLocalN2ReleaseDeactivatesUserPlane(t *testing.T) {
	const anType = models.AccessType_3_GPP_ACCESS
	releases := []struct {
		name    string
		release func(conn *ngaptesting.SctpConnStub, ran *amf_context.AmfRan, ranUe *amf_context.RanUe)
	}{
		{"SCTP association closed by the gNB", func(conn *ngaptesting.SctpConnStub, _ *amf_context.AmfRan,
			_ *amf_context.RanUe,
		) {
			Dispatch(conn, nil)
		}},
		{"SCTP connection error", func(conn *ngaptesting.SctpConnStub, _ *amf_context.AmfRan, _ *amf_context.RanUe) {
			HandleSCTPConnError(conn)
		}},
		{"NG Reset all", func(_ *ngaptesting.SctpConnStub, ran *amf_context.AmfRan, _ *amf_context.RanUe) {
			handleNGResetMain(ran, nil, &ngapType.ResetType{Choice: &ngapType.ResetAll{}})
		}},
		{"NG Reset part of NG interface", func(_ *ngaptesting.SctpConnStub, ran *amf_context.AmfRan,
			ranUe *amf_context.RanUe,
		) {
			handleNGResetMain(ran, nil, &ngapType.ResetType{Choice: &ngapType.UEAssociatedLogicalNGConnectionList{
				List: []ngapType.UEAssociatedLogicalNGConnectionItem{{
					AMFUENGAPID: &ngapType.AMFUENGAPID{Value: ranUe.AmfUeNgapId},
				}},
			}})
		}},
	}

	for _, release := range releases {
		t.Run(release.name, func(t *testing.T) {
			var mu sync.Mutex
			var updates []models.Smf_PDUSess_SmContextUpdateData
			smf := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// The update is a multipart/related body whose first part is the JSON data.
				var update models.Smf_PDUSess_SmContextUpdateData
				_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
				if err != nil {
					t.Errorf("SMF stub content type: %v", err)
				} else if part, errPart := multipart.NewReader(r.Body, params["boundary"]).NextPart(); errPart != nil {
					t.Errorf("SMF stub part: %v", errPart)
				} else if errDecode := json.NewDecoder(part).Decode(&update); errDecode != nil {
					t.Errorf("SMF stub decode: %v", errDecode)
				}
				mu.Lock()
				updates = append(updates, update)
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				if errEncode := json.NewEncoder(w).Encode(models.Smf_PDUSess_SmContextUpdatedData{
					UpCnxState: models.Smf_PDUSess_UpCnxState_DEACTIVATED,
				}); errEncode != nil {
					t.Errorf("SMF stub write: %v", errEncode)
				}
			}))
			smf.Config.Protocols = new(http.Protocols)
			smf.Config.Protocols.SetUnencryptedHTTP2(true) // the SBI client uses h2c
			smf.Start()
			defer smf.Close()
			_, err := consumer.NewConsumer(struct{ app.App }{})
			require.NoError(t, err)

			amfSelf := amf_context.GetSelf()
			NewAmfContext(amfSelf)
			conn := new(ngaptesting.SctpConnStub)
			ran := NewAmfRan(conn)
			amfSelf.AmfRanPool.Store(conn, ran)
			ranUe, err := ran.NewRanUe(1)
			require.NoError(t, err)
			amfUe := amfSelf.NewAmfUe("imsi-208930000000004")
			t.Cleanup(amfUe.Remove)
			amfUe.AttachRanUe(ranUe)
			amfUe.State[anType].Set(amf_context.Registered)
			for _, id := range []int32{5, 6} {
				smContext := amf_context.NewSmContext(id)
				smContext.SetSmfUri(smf.URL)
				smContext.SetSmContextRef(fmt.Sprintf("sm-context-%d", id))
				smContext.SetAccessType(anType)
				amfUe.StoreSmContext(id, smContext)
			}

			release.release(conn, ran, ranUe)

			mu.Lock()
			defer mu.Unlock()
			require.Len(t, updates, 2, "one SmContext update per PDU session")
			for _, update := range updates {
				require.Equal(t, models.Smf_PDUSess_UpCnxState_DEACTIVATED, update.UpCnxState)
				require.NotNil(t, update.NgApCause)
			}
			require.Nil(t, amfUe.GetRanUe(anType), "the UE's N2 connection is released")
		})
	}
}
