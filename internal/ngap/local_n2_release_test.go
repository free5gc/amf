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
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	ngap_message "github.com/free5gc/amf/internal/ngap/message"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/pkg/app"
	"github.com/free5gc/ngap/aper"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// localReleaseSmf is an SMF that records the SmContext updates as they arrive. While hold is open, it answers none.
type localReleaseSmf struct {
	mu      sync.Mutex
	updates map[string]models.Smf_PDUSess_SmContextUpdateData // the last one, by SM context reference
	states  map[string][]models.Smf_PDUSess_UpCnxState        // each update's upCnxState, by SM context reference
	hold    chan struct{}                                     // the SMF answers once hold is closed
	// status, when set, gives the HTTP status of the answer to an update: 200 with a body otherwise.
	status func(models.Smf_PDUSess_SmContextUpdateData) int
}

// noUpCnxState is the upCnxState of an update that has none, such as the N2 SM information of a setup.
const noUpCnxState = models.Smf_PDUSess_UpCnxState("")

func newLocalReleaseSmf(t *testing.T, hold chan struct{}) (*localReleaseSmf, string) {
	t.Helper()
	smf := &localReleaseSmf{
		updates: make(map[string]models.Smf_PDUSess_SmContextUpdateData),
		states:  make(map[string][]models.Smf_PDUSess_UpCnxState),
		hold:    hold,
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		ref := path.Base(strings.TrimSuffix(r.URL.Path, "/modify"))
		smf.mu.Lock()
		smf.updates[ref] = update
		smf.states[ref] = append(smf.states[ref], update.UpCnxState)
		status := http.StatusOK
		if smf.status != nil {
			status = smf.status(update)
		}
		smf.mu.Unlock()
		if smf.hold != nil {
			<-smf.hold
		}
		switch status {
		case http.StatusNoContent:
			w.WriteHeader(status)
			return
		case http.StatusInternalServerError:
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(status)
			if errEncode := json.NewEncoder(w).Encode(models.ProblemDetails{
				Status: http.StatusInternalServerError, Cause: "SYSTEM_FAILURE",
			}); errEncode != nil {
				t.Errorf("SMF stub write: %v", errEncode)
			}
			return
		}
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

// answer sets the HTTP status of the SMF's answers: 204 No Content, 500 with a problem, or 200 with a body.
func (smf *localReleaseSmf) answer(status func(models.Smf_PDUSess_SmContextUpdateData) int) {
	smf.mu.Lock()
	defer smf.mu.Unlock()
	smf.status = status
}

// statusFor is an answer with status to the updates of N2 SM information n2SmInfoType or of HO state hoState.
func statusFor(status int, n2SmInfoType models.Smf_PDUSess_N2SmInfoType, hoState models.Smf_PDUSess_HoState,
) func(models.Smf_PDUSess_SmContextUpdateData) int {
	return func(update models.Smf_PDUSess_SmContextUpdateData) int {
		if (n2SmInfoType != "" && update.N2SmInfoType == n2SmInfoType) || (hoState != "" && update.HoState == hoState) {
			return status
		}
		return http.StatusOK
	}
}

// received returns the SmContext updates received so far, by SM context reference.
func (smf *localReleaseSmf) received() map[string]models.Smf_PDUSess_SmContextUpdateData {
	smf.mu.Lock()
	defer smf.mu.Unlock()
	return maps.Clone(smf.updates)
}

// upCnxStates returns the upCnxState of each update of an SM context so far.
func (smf *localReleaseSmf) upCnxStates(ref string) []models.Smf_PDUSess_UpCnxState {
	smf.mu.Lock()
	defer smf.mu.Unlock()
	return append([]models.Smf_PDUSess_UpCnxState(nil), smf.states[ref]...)
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
		// An INITIAL UE MESSAGE whose RAN UE NGAP ID an existing connection has: that connection is released.
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

// setupList is the list of a PDU SESSION RESOURCE SETUP RESPONSE that sets up the PDU sessions ids.
func setupList(ids ...int64) *ngapType.PDUSessionResourceSetupListSURes {
	list := new(ngapType.PDUSessionResourceSetupListSURes)
	for _, id := range ids {
		list.List = append(list.List, ngapType.PDUSessionResourceSetupItemSURes{
			PDUSessionID:                            &ngapType.PDUSessionID{Value: id},
			PDUSessionResourceSetupResponseTransfer: &aper.OctetString{0x00},
		})
	}
	return list
}

// newConnection is a new N2 connection of the UE at ran, made its connection, as after an INITIAL UE MESSAGE.
func newConnection(t *testing.T, ran *amf_context.AmfRan, amfUe *amf_context.AmfUe) *amf_context.RanUe {
	t.Helper()
	ranUe, err := ran.NewRanUe(2)
	require.NoError(t, err)
	amfUe.AttachRanUe(ranUe)
	return ranUe
}

// A late deactivation, such as one sent after an NG RESET ACKNOWLEDGE, does not undo an activation of the user plane
// at a new connection of the UE that the SMF accepted since the release: that session stays activated.
func TestLocalN2ReleaseKeepsUserPlaneActivatedAtANewConnection(t *testing.T) {
	for name, activate := range map[string]func(*amf_context.AmfRan, *amf_context.RanUe){
		"PDU SESSION RESOURCE SETUP RESPONSE": func(ran *amf_context.AmfRan, ranUe *amf_context.RanUe) {
			handlePDUSessionResourceSetupResponseMain(ran, ranUe, setupList(5), nil, nil)
		},
		"INITIAL CONTEXT SETUP RESPONSE": func(ran *amf_context.AmfRan, ranUe *amf_context.RanUe) {
			ranUe.InitialContextSetupPending.Store(1)
			handleInitialContextSetupResponseMain(ran, ranUe, &ngapType.PDUSessionResourceSetupListCxtRes{
				List: []ngapType.PDUSessionResourceSetupItemCxtRes{{
					PDUSessionID:                            &ngapType.PDUSessionID{Value: 5},
					PDUSessionResourceSetupResponseTransfer: &aper.OctetString{0x00},
				}},
			}, nil, nil)
		},
	} {
		t.Run(name, func(t *testing.T) {
			smf, smfURL := newLocalReleaseSmf(t, nil)
			_, ran, ranUe, amfUe := newLocalReleaseTestUe(t, smfURL)
			anRelease := newLocalAnRelease(ran, ranUe,
				ngapCause(ngap_message.CauseChoiceMisc, ngapType.CauseMiscPresentUnspecified))
			require.NotNil(t, anRelease)

			activate(ran, newConnection(t, ran, amfUe))
			anRelease.deactivateUpConnections()

			require.Equal(t, []models.Smf_PDUSess_UpCnxState{noUpCnxState}, smf.upCnxStates("sm-context-5"),
				"a session activated at the new connection is deactivated")
			require.Equal(t, []models.Smf_PDUSess_UpCnxState{models.Smf_PDUSess_UpCnxState_DEACTIVATED},
				smf.upCnxStates("sm-context-6"))
		})
	}
}

// TS 38.413 8.7.4.2.2: an NG RESET aborts the other procedures of the UE associations that it resets. A setup response
// of the released connection, handled after the release, keeps no user plane at that connection: the session is
// deactivated after it, and a setup response handled after the deactivation is not sent to the SMF.
func TestLocalN2ReleaseDeactivatesUserPlaneActivatedByTheReleasedConnection(t *testing.T) {
	smf, smfURL := newLocalReleaseSmf(t, nil)
	_, ran, ranUe, _ := newLocalReleaseTestUe(t, smfURL)
	anRelease := newLocalAnRelease(ran, ranUe,
		ngapCause(ngap_message.CauseChoiceMisc, ngapType.CauseMiscPresentUnspecified))
	require.NotNil(t, anRelease)

	handlePDUSessionResourceSetupResponseMain(ran, ranUe, setupList(5), nil, nil)
	anRelease.deactivateUpConnections()
	handlePDUSessionResourceSetupResponseMain(ran, ranUe, setupList(6), nil, nil)

	require.Equal(t, []models.Smf_PDUSess_UpCnxState{noUpCnxState, models.Smf_PDUSess_UpCnxState_DEACTIVATED},
		smf.upCnxStates("sm-context-5"))
	require.Equal(t, []models.Smf_PDUSess_UpCnxState{models.Smf_PDUSess_UpCnxState_DEACTIVATED},
		smf.upCnxStates("sm-context-6"))
}

// An activation at a new connection that the SMF rejects does not keep the late deactivation from being sent.
func TestLocalN2ReleaseDeactivatesAfterARejectedActivation(t *testing.T) {
	smf, smfURL := newLocalReleaseSmf(t, nil)
	smf.answer(statusFor(http.StatusInternalServerError, models.Smf_PDUSess_N2SmInfoType_PDU_RES_SETUP_RSP, ""))
	_, ran, ranUe, amfUe := newLocalReleaseTestUe(t, smfURL)
	anRelease := newLocalAnRelease(ran, ranUe,
		ngapCause(ngap_message.CauseChoiceMisc, ngapType.CauseMiscPresentUnspecified))
	require.NotNil(t, anRelease)

	handlePDUSessionResourceSetupResponseMain(ran, newConnection(t, ran, amfUe), setupList(5), nil, nil)
	anRelease.deactivateUpConnections()

	require.Equal(t, []models.Smf_PDUSess_UpCnxState{noUpCnxState, models.Smf_PDUSess_UpCnxState_DEACTIVATED},
		smf.upCnxStates("sm-context-5"))
}

// The AMF removes a gNB whose SCTP association is lost before the SMFs answer the deactivations, so that a slow SMF
// does not keep the gNB that is gone.
func TestLostAssociationRemovesTheRanBeforeTheSmfAnswers(t *testing.T) {
	hold := make(chan struct{})
	smf, smfURL := newLocalReleaseSmf(t, hold)
	conn, ran, _, _ := newLocalReleaseTestUe(t, smfURL)

	done := make(chan struct{})
	go func() {
		Dispatch(conn, nil)
		close(done)
	}()
	gone := func() bool {
		_, ok := amf_context.GetSelf().AmfRanFindByConn(ran.Conn)
		return !ok
	}
	if !assert.Eventually(t, gone, 2*time.Second, 10*time.Millisecond, "the gNB stays while the SMF answers") {
		close(hold)
		<-done
		t.FailNow()
	}
	close(hold)
	<-done
	require.Len(t, smf.received(), 2)
}

// newLocalReleaseTarget prepares the target of a handover of sourceUe for PDU sessions 5 and 6.
func newLocalReleaseTarget(t *testing.T, sourceUe *amf_context.RanUe) (*amf_context.AmfRan, *amf_context.RanUe) {
	t.Helper()
	targetConn := new(ngaptesting.SctpConnStub)
	targetRan := NewAmfRan(targetConn)
	amf_context.GetSelf().AmfRanPool.Store(targetConn, targetRan)
	t.Cleanup(func() { amf_context.GetSelf().AmfRanPool.Delete(targetConn) })
	targetUe, err := targetRan.NewRanUe(2)
	require.NoError(t, err)
	amf_context.AttachSourceUeTargetUe(sourceUe, targetUe)
	targetUe.SuccessPduSessionId = []int32{5, 6}
	return targetRan, targetUe
}

// A late deactivation does not undo the completion of a handover at the target, whose user plane the SMF switches
// there, when the source gNB's association is lost during the handover. When the SMF rejects the completion, the
// user plane stays at the source and is deactivated.
func TestLocalN2ReleaseKeepsUserPlaneOfCompletedHandover(t *testing.T) {
	const anType = models.AccessType_3_GPP_ACCESS
	for name, status := range map[string]int{"accepted": http.StatusOK, "rejected": http.StatusInternalServerError} {
		t.Run(name, func(t *testing.T) {
			smf, smfURL := newLocalReleaseSmf(t, nil)
			smf.answer(statusFor(status, "", models.Smf_PDUSess_HoState_COMPLETED))
			_, sourceRan, sourceUe, amfUe := newLocalReleaseTestUe(t, smfURL)
			targetRan, targetUe := newLocalReleaseTarget(t, sourceUe)
			targetUe.HandoverCommandSent = true

			// removeRan of the source: the release is decided and the source removed; the HANDOVER NOTIFY of the
			// target, on another worker, completes the handover before the SMFs are told.
			anRelease := newLocalAnRelease(sourceRan, sourceUe,
				ngapCause(ngap_message.CauseChoiceTransport, ngapType.CauseTransportPresentTransportResourceUnavailable))
			require.NotNil(t, anRelease)
			completeUeContextReleases(sourceRan)
			sourceRan.Remove()
			handleHandoverNotifyMain(targetRan, targetUe, nil)
			require.Equal(t, targetUe, amfUe.GetRanUe(anType), "the handover completed at the target")

			anRelease.deactivateUpConnections()

			for _, ref := range []string{"sm-context-5", "sm-context-6"} {
				if status == http.StatusOK {
					require.NotContains(t, smf.upCnxStates(ref), models.Smf_PDUSess_UpCnxState_DEACTIVATED,
						"%s: the user plane at the target is deactivated", ref)
				} else {
					require.Contains(t, smf.upCnxStates(ref), models.Smf_PDUSess_UpCnxState_DEACTIVATED, ref)
				}
			}
		})
	}
}

// An activation of a session that the SMF has not answered yet, a setup response of the connection being released,
// does not hold up the release of the connection: neither the NG RESET ACKNOWLEDGE nor the removal of a gNB whose
// association is lost. The deactivation of each session follows its activation, if any.
func TestLocalReleaseDoesNotWaitForAnActivationInFlight(t *testing.T) {
	for name, release := range map[string]func(*ngaptesting.SctpConnStub, *amf_context.AmfRan){
		"NG RESET": func(_ *ngaptesting.SctpConnStub, ran *amf_context.AmfRan) {
			handleNGResetMain(ran, nil, &ngapType.ResetType{Choice: &ngapType.ResetAll{}})
		},
		"lost association": func(conn *ngaptesting.SctpConnStub, _ *amf_context.AmfRan) {
			Dispatch(conn, nil)
		},
	} {
		t.Run(name, func(t *testing.T) {
			hold := make(chan struct{})
			smf, smfURL := newLocalReleaseSmf(t, hold)
			conn, ran, ranUe, _ := newLocalReleaseTestUe(t, smfURL)
			activated := make(chan struct{})
			go func() {
				defer close(activated)
				handlePDUSessionResourceSetupResponseMain(ran, ranUe, setupList(5, 6), nil, nil)
			}()
			require.Eventually(t, func() bool { return len(smf.upCnxStates("sm-context-5")) == 1 },
				2*time.Second, 10*time.Millisecond, "the activation reaches the SMF")

			done := make(chan struct{})
			go func() {
				release(conn, ran)
				close(done)
			}()
			released := func() bool {
				if name == "NG RESET" {
					select {
					case <-done:
						return true
					default:
						return false
					}
				}
				_, found := amf_context.GetSelf().AmfRanFindByConn(ran.Conn)
				return !found
			}
			ok := assert.Eventually(t, released, 2*time.Second, 10*time.Millisecond,
				"%s waits for the answer to an activation in flight", name)
			// The deactivation of session 5 waits for the answer to its activation, which it follows.
			time.Sleep(100 * time.Millisecond)
			overtaken := len(smf.upCnxStates("sm-context-5")) != 1
			close(hold)
			<-done
			<-activated
			require.True(t, ok)
			require.False(t, overtaken, "the deactivation reached the SMF before the activation was answered")
			for _, ref := range []string{"sm-context-5", "sm-context-6"} {
				require.Eventually(t, func() bool {
					return slices.Contains(smf.upCnxStates(ref), models.Smf_PDUSess_UpCnxState_DEACTIVATED)
				}, 2*time.Second, 10*time.Millisecond, "%s is not deactivated", ref)
			}
			require.Equal(t, []models.Smf_PDUSess_UpCnxState{noUpCnxState, models.Smf_PDUSess_UpCnxState_DEACTIVATED},
				smf.upCnxStates("sm-context-5"))
			states := smf.upCnxStates("sm-context-6")
			require.Equal(t, models.Smf_PDUSess_UpCnxState_DEACTIVATED, states[len(states)-1],
				"session 6 is activated at the released connection after its deactivation: %v", states)
		})
	}
}

// A deactivation that the SMF has not answered yet keeps an activation of the same session from overtaking it.
func TestActivationWaitsForADeactivationBeingSent(t *testing.T) {
	hold := make(chan struct{})
	smf, smfURL := newLocalReleaseSmf(t, hold)
	_, ran, ranUe, amfUe := newLocalReleaseTestUe(t, smfURL)
	smContext, ok := amfUe.SmContextFindByPDUSessionID(5)
	require.True(t, ok)
	// The release of session 5 alone, so that its deactivation is the first request.
	anRelease := &localAnRelease{
		ran: ran, ranUe: ranUe, smContexts: []*amf_context.SmContext{smContext},
		cause: ngapCause(ngap_message.CauseChoiceMisc, ngapType.CauseMiscPresentUnspecified), log: ranUe.Log,
	}

	deactivated := make(chan struct{})
	go func() {
		defer close(deactivated)
		anRelease.deactivateUpConnections()
	}()
	require.Eventually(t, func() bool { return len(smf.upCnxStates("sm-context-5")) == 1 },
		2*time.Second, 10*time.Millisecond, "the deactivation reaches the SMF")
	newUe := newConnection(t, ran, amfUe)
	activated := make(chan struct{})
	go func() {
		defer close(activated)
		handlePDUSessionResourceSetupResponseMain(ran, newUe, setupList(5), nil, nil)
	}()
	time.Sleep(200 * time.Millisecond)
	overtaken := len(smf.upCnxStates("sm-context-5")) != 1
	close(hold)
	<-deactivated
	<-activated

	require.False(t, overtaken, "the activation reached the SMF before the deactivation was answered")
	require.Equal(t, []models.Smf_PDUSess_UpCnxState{models.Smf_PDUSess_UpCnxState_DEACTIVATED, noUpCnxState},
		smf.upCnxStates("sm-context-5"))
}

// A setup at a new connection that fails, which activates no user plane, does not keep a late deactivation from
// being sent.
func TestLocalN2ReleaseAfterAFailedSetupDeactivates(t *testing.T) {
	smf, smfURL := newLocalReleaseSmf(t, nil)
	_, ran, ranUe, amfUe := newLocalReleaseTestUe(t, smfURL)
	anRelease := newLocalAnRelease(ran, ranUe,
		ngapCause(ngap_message.CauseChoiceMisc, ngapType.CauseMiscPresentUnspecified))
	require.NotNil(t, anRelease)

	handlePDUSessionResourceSetupResponseMain(ran, newConnection(t, ran, amfUe), nil,
		&ngapType.PDUSessionResourceFailedToSetupListSURes{List: []ngapType.PDUSessionResourceFailedToSetupItemSURes{{
			PDUSessionID: &ngapType.PDUSessionID{Value: 5},
			PDUSessionResourceSetupUnsuccessfulTransfer: &aper.OctetString{0x00},
		}}}, nil)
	anRelease.deactivateUpConnections()

	require.Contains(t, smf.upCnxStates("sm-context-5"), models.Smf_PDUSess_UpCnxState_DEACTIVATED)
}

// A setup that the SMF accepts with 204 No Content activates the user plane at its connection, as Open5GS's SMF
// answers for a session that it was not activating: the release of that connection deactivates it, although the
// session was activated at an earlier connection before.
func TestLocalN2ReleaseDeactivatesUserPlaneSetUpWithNoContent(t *testing.T) {
	smf, smfURL := newLocalReleaseSmf(t, nil)
	conn, ran, oldUe, amfUe := newLocalReleaseTestUe(t, smfURL)
	handlePDUSessionResourceSetupResponseMain(ran, oldUe, setupList(5), nil, nil)
	require.NoError(t, oldUe.Remove()) // released by the N2 messages of the procedure
	smf.answer(statusFor(http.StatusNoContent, models.Smf_PDUSess_N2SmInfoType_PDU_RES_SETUP_RSP, ""))
	handlePDUSessionResourceSetupResponseMain(ran, newConnection(t, ran, amfUe), setupList(5), nil, nil)

	Dispatch(conn, nil) // the gNB's SCTP association is lost

	require.Equal(t, []models.Smf_PDUSess_UpCnxState{
		noUpCnxState, noUpCnxState, models.Smf_PDUSess_UpCnxState_DEACTIVATED,
	}, smf.upCnxStates("sm-context-5"))
}

// Each activation at a connection is sent, and the release of the connection deactivates the session after them.
func TestLocalN2ReleaseAfterTwoActivationsAtTheConnectionDeactivates(t *testing.T) {
	smf, smfURL := newLocalReleaseSmf(t, nil)
	conn, ran, ranUe, _ := newLocalReleaseTestUe(t, smfURL)
	handlePDUSessionResourceSetupResponseMain(ran, ranUe, setupList(5), nil, nil)
	handlePDUSessionResourceSetupResponseMain(ran, ranUe, setupList(5), nil, nil)

	Dispatch(conn, nil)

	require.Equal(t, []models.Smf_PDUSess_UpCnxState{
		noUpCnxState, noUpCnxState, models.Smf_PDUSess_UpCnxState_DEACTIVATED,
	}, smf.upCnxStates("sm-context-5"))
}

// A path switch that the SMF rejects leaves the user plane at the source: the release of the source deactivates it.
func TestLocalN2ReleaseAfterARejectedPathSwitchDeactivates(t *testing.T) {
	e := newHoTestEnv(t, false)
	smf, smfURL := newLocalReleaseSmf(t, nil)
	smf.answer(statusFor(http.StatusInternalServerError, models.Smf_PDUSess_N2SmInfoType_PATH_SWITCH_REQ, ""))
	smContext, ok := e.amfUe.SmContextFindByPDUSessionID(5)
	require.True(t, ok)
	smContext.SetSmfUri(smfURL)
	anRelease := newLocalAnRelease(e.srcRan, e.src,
		ngapCause(ngap_message.CauseChoiceTransport, ngapType.CauseTransportPresentTransportResourceUnavailable))
	require.NotNil(t, anRelease)
	sendXnPathSwitch(e, 10, 5)

	anRelease.deactivateUpConnections()

	require.Equal(t, []models.Smf_PDUSess_UpCnxState{noUpCnxState, models.Smf_PDUSess_UpCnxState_DEACTIVATED},
		smf.upCnxStates("sm-context-5"))
}

// A late deactivation does not undo a path switch to the target when the source gNB's association is lost during the
// switch: the UE's connection, moved to the target, keeps its user plane there.
func TestLocalN2ReleaseKeepsUserPlaneOfAPathSwitch(t *testing.T) {
	e := newHoTestEnv(t, false)
	anRelease := newLocalAnRelease(e.srcRan, e.src,
		ngapCause(ngap_message.CauseChoiceTransport, ngapType.CauseTransportPresentTransportResourceUnavailable))
	require.NotNil(t, anRelease)
	sendXnPathSwitch(e, 10, 5)
	completeUeContextReleases(e.srcRan)
	e.srcRan.Remove()

	anRelease.deactivateUpConnections()

	e.smf.requireRequests(t, 0, "the user plane switched to the target is deactivated", "PATH_SWITCH_REQ")
	require.Same(t, e.src, e.amfUe.GetRanUe(hoTestAnType))
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

// When the AMF has ordered the release of the UE context with the connection, it removes the UE context, and
// deactivates no user plane.
func TestLocalN2ReleaseOfAReleasedUeContextDeactivatesNothing(t *testing.T) {
	smf, smfURL := newLocalReleaseSmf(t, nil)
	conn, _, ranUe, _ := newLocalReleaseTestUe(t, smfURL)
	ranUe.ReleaseAction = amf_context.UeContextReleaseUeContext

	Dispatch(conn, nil)

	require.Empty(t, smf.received())
}
