package ngap

import (
	"encoding/json"
	"fmt"
	"maps"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	ngap_message "github.com/free5gc/amf/internal/ngap/message"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/pkg/app"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// localReleaseSmf is an SMF that records the SmContext updates it receives. While hold is open, it answers none.
type localReleaseSmf struct {
	mu      sync.Mutex
	updates map[string]models.Smf_PDUSess_SmContextUpdateData // by SM context reference
	hold    chan struct{}
}

func newLocalReleaseSmf(t *testing.T, hold chan struct{}) (*localReleaseSmf, string) {
	t.Helper()
	smf := &localReleaseSmf{updates: make(map[string]models.Smf_PDUSess_SmContextUpdateData), hold: hold}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if smf.hold != nil {
			<-smf.hold
		}
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
		smf.mu.Lock()
		smf.updates[path.Base(strings.TrimSuffix(r.URL.Path, "/modify"))] = update
		smf.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if errEncode := json.NewEncoder(w).Encode(models.Smf_PDUSess_SmContextUpdatedData{
			UpCnxState: models.Smf_PDUSess_UpCnxState_DEACTIVATED,
		}); errEncode != nil {
			t.Errorf("SMF stub write: %v", errEncode)
		}
	}))
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetUnencryptedHTTP2(true) // the SBI client uses h2c
	server.Start()
	t.Cleanup(server.Close)
	_, err := consumer.NewConsumer(struct{ app.App }{})
	require.NoError(t, err)
	return smf, server.URL
}

// received returns the SmContext updates received so far, by SM context reference.
func (smf *localReleaseSmf) received() map[string]models.Smf_PDUSess_SmContextUpdateData {
	smf.mu.Lock()
	defer smf.mu.Unlock()
	return maps.Clone(smf.updates)
}

// newLocalReleaseTestUe returns a registered UE connected to a gNB, with PDU sessions 5 and 6 on 3GPP access and 7
// on non-3GPP access, each with the SM context reference sm-context-<PDU session ID> at smfURL.
func newLocalReleaseTestUe(t *testing.T, smfURL string) (*ngaptesting.SctpConnStub, *amf_context.AmfRan,
	*amf_context.RanUe, *amf_context.AmfUe,
) {
	t.Helper()
	const anType = models.AccessType_3_GPP_ACCESS
	amfSelf := amf_context.GetSelf()
	NewAmfContext(amfSelf)
	conn := new(ngaptesting.SctpConnStub)
	ran := NewAmfRan(conn)
	amfSelf.AmfRanPool.Store(conn, ran)
	t.Cleanup(func() { amfSelf.AmfRanPool.Delete(conn) })
	ranUe, err := ran.NewRanUe(1)
	require.NoError(t, err)
	amfUe := amfSelf.NewAmfUe("imsi-208930000000004")
	t.Cleanup(amfUe.Remove)
	amfUe.AttachRanUe(ranUe)
	amfUe.State[anType].Set(amf_context.Registered)
	for id, access := range map[int32]models.AccessType{
		5: anType, 6: anType, 7: models.AccessType_NON_3_GPP_ACCESS,
	} {
		smContext := amf_context.NewSmContext(id)
		smContext.SetSmfUri(smfURL)
		smContext.SetSmContextRef(fmt.Sprintf("sm-context-%d", id))
		smContext.SetAccessType(access)
		amfUe.StoreSmContext(id, smContext)
	}
	return conn, ran, ranUe, amfUe
}

func localReleaseCause(group int, value int) *models.NgApCause {
	return &models.NgApCause{Group: int32(group), Value: int32(value)}
}

// TS 23.502 4.2.6: when the NG-AP signaling connection is lost due to (R)AN or AMF failure, the AMF performs
// the AN release locally, and the AN release causes all UP connections of the UE to be deactivated. When the
// AMF releases a UE's N2 connection locally, it asks the SMF of each PDU session of the UE on that access to
// deactivate its user plane, with the cause of the release.
func TestLocalN2ReleaseDeactivatesUserPlane(t *testing.T) {
	const anType = models.AccessType_3_GPP_ACCESS
	transportLost := localReleaseCause(ngap_message.CauseChoiceTransport,
		int(ngapType.CauseTransportPresentTransportResourceUnavailable))
	unspecified := localReleaseCause(ngap_message.CauseChoiceMisc, int(ngapType.CauseMiscPresentUnspecified))
	releases := []struct {
		name    string
		release func(conn *ngaptesting.SctpConnStub, ran *amf_context.AmfRan, ranUe *amf_context.RanUe)
		cause   *models.NgApCause
	}{
		{"SCTP association closed by the gNB", func(conn *ngaptesting.SctpConnStub, _ *amf_context.AmfRan,
			_ *amf_context.RanUe,
		) {
			Dispatch(conn, nil)
		}, transportLost},
		{"SCTP connection error", func(conn *ngaptesting.SctpConnStub, _ *amf_context.AmfRan, _ *amf_context.RanUe) {
			HandleSCTPConnError(conn)
		}, transportLost},
		{"NG Reset all without a cause", func(_ *ngaptesting.SctpConnStub, ran *amf_context.AmfRan,
			_ *amf_context.RanUe,
		) {
			handleNGResetMain(ran, nil, &ngapType.ResetType{Choice: &ngapType.ResetAll{}})
		}, unspecified},
		{"NG Reset part of NG interface", func(_ *ngaptesting.SctpConnStub, ran *amf_context.AmfRan,
			ranUe *amf_context.RanUe,
		) {
			handleNGResetMain(ran, &ngapType.Cause{Choice: &ngapType.CauseRadioNetwork{
				Value: ngapType.CauseRadioNetworkPresentReleaseDueToNgranGeneratedReason,
			}}, &ngapType.ResetType{Choice: &ngapType.UEAssociatedLogicalNGConnectionList{
				List: []ngapType.UEAssociatedLogicalNGConnectionItem{{
					AMFUENGAPID: &ngapType.AMFUENGAPID{Value: ranUe.AmfUeNgapId},
				}},
			}})
		}, localReleaseCause(ngap_message.CauseChoiceRadioNetwork,
			int(ngapType.CauseRadioNetworkPresentReleaseDueToNgranGeneratedReason))},
		// TS 38.413 10.6: a local release of the connection that has an erroneous AP ID.
		{"erroneous AP ID", func(_ *ngaptesting.SctpConnStub, ran *amf_context.AmfRan, ranUe *amf_context.RanUe) {
			removeRanUeByInvalidUE(ran, &ngapType.AMFUENGAPID{Value: ranUe.AmfUeNgapId}, nil)
		}, unspecified},
		// TS 38.413 8.6.1.2: an INITIAL UE MESSAGE whose RAN UE NGAP ID an existing connection has.
		{"INITIAL UE MESSAGE that reuses the RAN UE NGAP ID", func(_ *ngaptesting.SctpConnStub,
			ran *amf_context.AmfRan, ranUe *amf_context.RanUe,
		) {
			handleInitialUEMessageMain(ran, nil, &ngapType.RANUENGAPID{Value: ranUe.RanUeNgapId},
				&ngapType.NASPDU{Value: []byte{0x7e, 0x00}}, nil, nil, nil, nil)
		}, unspecified},
	}

	for _, release := range releases {
		t.Run(release.name, func(t *testing.T) {
			smf, smfURL := newLocalReleaseSmf(t, nil)
			conn, ran, ranUe, amfUe := newLocalReleaseTestUe(t, smfURL)

			release.release(conn, ran, ranUe)

			// After an NG RESET, the SMFs are told on goroutines of their own.
			require.Eventually(t, func() bool { return len(smf.received()) >= 2 }, 5*time.Second, 10*time.Millisecond)
			updates := smf.received()
			require.Len(t, updates, 2, "one SmContext update per PDU session on the access")
			for _, ref := range []string{"sm-context-5", "sm-context-6"} {
				update, ok := updates[ref]
				require.True(t, ok, "no SmContext update for %s", ref)
				require.Equal(t, models.Smf_PDUSess_UpCnxState_DEACTIVATED, update.UpCnxState)
				require.Equal(t, release.cause, update.NgApCause)
			}
			require.NotEqual(t, ranUe, amfUe.GetRanUe(anType), "the UE's N2 connection is released")
		})
	}
}

// The NG RESET ACKNOWLEDGE does not wait for the SMFs, which are told afterwards.
func TestNGResetAcknowledgedBeforeTheSmfAnswers(t *testing.T) {
	hold := make(chan struct{})
	smf, smfURL := newLocalReleaseSmf(t, hold)
	conn, ran, _, _ := newLocalReleaseTestUe(t, smfURL)

	done := make(chan struct{})
	go func() {
		handleNGResetMain(ran, nil, &ngapType.ResetType{Choice: &ngapType.ResetAll{}})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(hold)
		<-done
		t.Fatal("the NG RESET waits for the SMF")
	}
	require.Len(t, conn.MsgList, 1)
	decoded, err := ngapMessage.Parse(conn.MsgList[0])
	require.NoError(t, err)
	require.IsType(t, &ngapMessage.NGResetAcknowledge{}, decoded)

	close(hold)
	require.Eventually(t, func() bool { return len(smf.received()) == 2 }, 5*time.Second, 10*time.Millisecond)
}

// A connection that is not the UE's connection on its access, such as the target of a handover that has not
// completed, is released without the UE's PDU sessions: they stay on the UE's connection.
func TestLocalN2ReleaseOfAnotherConnectionKeepsUserPlane(t *testing.T) {
	const anType = models.AccessType_3_GPP_ACCESS
	smf, smfURL := newLocalReleaseSmf(t, nil)
	_, _, ranUe, amfUe := newLocalReleaseTestUe(t, smfURL)
	targetConn := new(ngaptesting.SctpConnStub)
	target := NewAmfRan(targetConn)
	amf_context.GetSelf().AmfRanPool.Store(targetConn, target)
	targetUe, err := target.NewRanUe(2)
	require.NoError(t, err)
	targetUe.AmfUe = amfUe

	Dispatch(targetConn, nil) // the SCTP association of the target gNB is lost

	require.Empty(t, smf.received())
	require.Equal(t, ranUe, amfUe.GetRanUe(anType))
}

// TS 23.502 4.2.6: the deactivation carries the UE's location at the connection when the AMF released it, not a
// location that the connection reports while the SMF is told.
func TestLocalN2ReleaseSendsTheLocationOfTheRelease(t *testing.T) {
	smf, smfURL := newLocalReleaseSmf(t, nil)
	_, ran, ranUe, _ := newLocalReleaseTestUe(t, smfURL)
	plmnID := &models.PlmnId{Mcc: "208", Mnc: "93"}
	ranUe.Location = models.UserLocation{NrLocation: &models.NrLocation{Tai: &models.Tai{PlmnId: plmnID, Tac: "000001"}}}
	anRelease := newLocalAnRelease(ran, ranUe,
		ngapCause(ngap_message.CauseChoiceMisc, ngapType.CauseMiscPresentUnspecified))
	require.NotNil(t, anRelease)
	ranUe.Location.NrLocation.Tai = &models.Tai{PlmnId: plmnID, Tac: "000002"}

	anRelease.deactivateUpConnections()

	update := smf.received()["sm-context-5"]
	require.NotNil(t, update.UeLocation)
	require.NotNil(t, update.UeLocation.NrLocation)
	require.Equal(t, "000001", update.UeLocation.NrLocation.Tai.Tac)
}
