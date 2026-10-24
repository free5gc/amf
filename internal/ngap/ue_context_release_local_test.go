package ngap

import (
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	gmm_common "github.com/free5gc/amf/internal/gmm/common"
	"github.com/free5gc/amf/internal/logger"
	nastesting "github.com/free5gc/amf/internal/nas/testing"
	ngap_message "github.com/free5gc/amf/internal/ngap/message"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/nas/ie"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// The AMF orders a UE CONTEXT RELEASE COMMAND that also releases the UE
// context (for example for a UE CONTEXT RELEASE REQUEST outside
// 5GMM-REGISTERED, after stopping the 5GMM timers). If the connection then
// ends without a matching UE CONTEXT RELEASE COMPLETE, the AmfUe must still be
// removed: no timer is left to move it out of its GMM state, and the
// subscriber's next registration would be dropped as a state mismatch.
func TestUeContextReleaseCompletedOnLocalN2Release(t *testing.T) {
	const anType = models.AccessType_3_GPP_ACCESS
	type releaseFunc func(t *testing.T, conn *ngaptesting.SctpConnStub, ran *amf_context.AmfRan,
		ranUe *amf_context.RanUe)
	releases := []struct {
		name    string
		release releaseFunc
	}{
		{
			name: "UE CONTEXT RELEASE COMPLETE with an inconsistent RAN-UE-NGAP-ID",
			release: func(_ *testing.T, _ *ngaptesting.SctpConnStub, ran *amf_context.AmfRan, ranUe *amf_context.RanUe) {
				dispatchMain(ran, &ngapMessage.UEContextReleaseComplete{
					AMFUENGAPID: &ngapType.AMFUENGAPID{Value: ranUe.AmfUeNgapId},
					RANUENGAPID: &ngapType.RANUENGAPID{Value: ranUe.RanUeNgapId + 1},
				}, nil)
			},
		},
		{
			name: "NG Reset part of NG interface",
			release: func(_ *testing.T, _ *ngaptesting.SctpConnStub, ran *amf_context.AmfRan, ranUe *amf_context.RanUe) {
				handleNGResetMain(ran, nil, &ngapType.ResetType{Choice: &ngapType.UEAssociatedLogicalNGConnectionList{
					List: []ngapType.UEAssociatedLogicalNGConnectionItem{{
						AMFUENGAPID: &ngapType.AMFUENGAPID{Value: ranUe.AmfUeNgapId},
					}},
				}})
			},
		},
		{
			name: "NG Reset all",
			release: func(_ *testing.T, _ *ngaptesting.SctpConnStub, ran *amf_context.AmfRan, _ *amf_context.RanUe) {
				handleNGResetMain(ran, nil, &ngapType.ResetType{Choice: &ngapType.ResetAll{}})
			},
		},
		{
			// The gNB has released the connection and allocated its RAN UE
			// NGAP ID to another UE before the AMF handled the UE CONTEXT
			// RELEASE COMPLETE: the AMF schedules the completion by AMF UE
			// NGAP ID and the INITIAL UE MESSAGE by RAN UE NGAP ID. The other
			// UE's 5G-S-TMSI names another AMF Set, so it never matches the
			// AmfUe under test.
			name: "INITIAL UE MESSAGE reusing the RAN-UE-NGAP-ID",
			release: func(t *testing.T, _ *ngaptesting.SctpConnStub, ran *amf_context.AmfRan, ranUe *amf_context.RanUe) {
				initialUEMessage := BuildInitialUEMessage(t, ranUe.RanUeNgapId,
					nastesting.GetServiceRequest(uint8(ie.SvcType_Data)), "010000000001")
				encoded, err := initialUEMessage.MarshalBinary()
				require.NoError(t, err)
				dispatchMain(ran, initialUEMessage, encoded)
			},
		},
		{
			name: "SCTP connection error",
			release: func(_ *testing.T, conn *ngaptesting.SctpConnStub, _ *amf_context.AmfRan, _ *amf_context.RanUe) {
				HandleSCTPConnError(conn)
			},
		},
		{
			name: "SCTP association closed by the gNB",
			release: func(_ *testing.T, conn *ngaptesting.SctpConnStub, _ *amf_context.AmfRan, _ *amf_context.RanUe) {
				Dispatch(conn, nil)
			},
		},
	}
	commands := []struct {
		name          string
		action        amf_context.RelAction
		amfUeReleased bool
	}{
		{name: "release UE context", action: amf_context.UeContextReleaseUeContext, amfUeReleased: true},
		{name: "N2 release only", action: amf_context.UeContextN2NormalRelease, amfUeReleased: false},
	}

	for _, release := range releases {
		for _, command := range commands {
			t.Run(release.name+"/"+command.name, func(t *testing.T) {
				amfSelf := amf_context.GetSelf()
				NewAmfContext(amfSelf)
				conn := new(ngaptesting.SctpConnStub)
				ran := NewAmfRan(conn)
				amfSelf.AmfRanPool.Store(conn, ran)
				ranUe, err := ran.NewRanUe(1)
				require.NoError(t, err)
				supi := fmt.Sprintf("imsi-20893000000%04d", int(command.action))
				amfUe := amfSelf.NewAmfUe(supi)
				amfUe.AttachRanUe(ranUe)
				amfUe.State[anType].Set(amf_context.ContextSetup)

				ngap_message.SendUEContextReleaseCommand(ranUe, command.action,
					ngap_message.CauseChoiceRadioNetwork, ngapType.CauseRadioNetworkPresentUnspecified)
				release.release(t, conn, ran, ranUe)

				_, pooled := amfSelf.AmfUeFindBySupi(supi)
				require.Equal(t, command.amfUeReleased, !pooled, "AmfUe removed")
				// Compare pointers: the INITIAL UE MESSAGE case allocates a new
				// RanUe, which may reuse the AMF UE NGAP ID.
				require.True(t, amfSelf.RanUeFindByAmfUeNgapID(ranUe.AmfUeNgapId) != ranUe, "RanUe removed")
				if !command.amfUeReleased {
					require.Nil(t, amfUe.RanUe[anType], "AmfUe kept without the released connection")
				}
			})
		}
	}
}

// A UE context release ordered on a RanUe the AmfUe has already left (for
// example the old connection released by
// AttachRanUeToAmfUeAndReleaseOldIfAny) must not remove the AmfUe, which now
// lives on another connection.
func TestUeContextReleaseOfDetachedRanUeKeepsAmfUe(t *testing.T) {
	const anType = models.AccessType_3_GPP_ACCESS
	amfSelf := amf_context.GetSelf()
	NewAmfContext(amfSelf)
	ran := NewAmfRan(new(ngaptesting.SctpConnStub))
	oldRanUe, err := ran.NewRanUe(1)
	require.NoError(t, err)
	newRanUe, err := ran.NewRanUe(2)
	require.NoError(t, err)
	amfUe := amfSelf.NewAmfUe("imsi-208930000000101")
	amfUe.AttachRanUe(oldRanUe)
	amfUe.State[anType].Set(amf_context.Registered)

	// Sends UE CONTEXT RELEASE COMMAND (release UE context) for oldRanUe.
	gmm_common.AttachRanUeToAmfUeAndReleaseOldIfAny(amfUe, newRanUe)
	handleNGResetMain(ran, nil, &ngapType.ResetType{Choice: &ngapType.UEAssociatedLogicalNGConnectionList{
		List: []ngapType.UEAssociatedLogicalNGConnectionItem{{
			AMFUENGAPID: &ngapType.AMFUENGAPID{Value: oldRanUe.AmfUeNgapId},
		}},
	}})

	_, pooled := amfSelf.AmfUeFindBySupi(amfUe.Supi)
	require.True(t, pooled)
	require.Equal(t, newRanUe, amfUe.RanUe[anType])
	require.Nil(t, amfSelf.RanUeFindByAmfUeNgapID(oldRanUe.AmfUeNgapId))
}

type logHookFunc func(*logrus.Entry)

func (logHookFunc) Levels() []logrus.Level       { return logrus.AllLevels }
func (f logHookFunc) Fire(e *logrus.Entry) error { f(e); return nil }

// The UE CONTEXT RELEASE COMPLETE (handled on the NGAP worker of its AMF UE
// NGAP ID) and a local release of the same connection (here a partial NG
// Reset, handled on worker 0) can both find the UE-context release pending.
// Each checks it before taking amfUe.Lock, so the one that gets the lock
// second must check again and leave the AmfUe alone. Each subtest runs the
// second path at the point where the first one has checked but not yet
// locked, from a log hook on the line the first path writes there.
func TestUeContextReleaseRemovesAmfUeOnce(t *testing.T) {
	const anType = models.AccessType_3_GPP_ACCESS
	type path func(t *testing.T, ran *amf_context.AmfRan, ranUe *amf_context.RanUe, amfUe *amf_context.AmfUe)
	var releaseComplete path = func(_ *testing.T, ran *amf_context.AmfRan, ranUe *amf_context.RanUe,
		_ *amf_context.AmfUe,
	) {
		dispatchMain(ran, &ngapMessage.UEContextReleaseComplete{
			AMFUENGAPID: &ngapType.AMFUENGAPID{Value: ranUe.AmfUeNgapId},
			RANUENGAPID: &ngapType.RANUENGAPID{Value: ranUe.RanUeNgapId},
		}, nil)
	}
	var ngReset path = func(_ *testing.T, ran *amf_context.AmfRan, ranUe *amf_context.RanUe, _ *amf_context.AmfUe) {
		handleNGResetMain(ran, nil, &ngapType.ResetType{Choice: &ngapType.UEAssociatedLogicalNGConnectionList{
			List: []ngapType.UEAssociatedLogicalNGConnectionItem{{
				AMFUENGAPID: &ngapType.AMFUENGAPID{Value: ranUe.AmfUeNgapId},
			}},
		}})
	}
	// The UE comes back on a new connection, which detaches the old one and
	// orders its release again (AttachRanUeToAmfUeAndReleaseOldIfAny).
	var reattach path = func(t *testing.T, ran *amf_context.AmfRan, _ *amf_context.RanUe, amfUe *amf_context.AmfUe) {
		newRanUe, err := ran.NewRanUe(2)
		require.NoError(t, err)
		gmm_common.AttachRanUeToAmfUeAndReleaseOldIfAny(amfUe, newRanUe)
	}
	const (
		localReleaseLogLine = "Release UE[%s] Context : Release Ue Context (N2 connection released locally)"
		completionLogLine   = "Release UE[%s] Context : Release Ue Context"
	)
	cases := []struct {
		name          string
		first, second path
		firstLogLine  string // written by the first path between its check and amfUe.Lock
		amfUeRemoved  bool
	}{
		{
			name:  "UE CONTEXT RELEASE COMPLETE while an NG Reset waits for the lock",
			first: ngReset, second: releaseComplete, firstLogLine: localReleaseLogLine, amfUeRemoved: true,
		},
		{
			name:  "NG Reset while the UE CONTEXT RELEASE COMPLETE waits for the lock",
			first: releaseComplete, second: ngReset, firstLogLine: completionLogLine, amfUeRemoved: true,
		},
		{
			// The AmfUe now lives on the new connection and is kept; the NG
			// Reset still removes the old RanUe.
			name:  "new connection while an NG Reset waits for the lock",
			first: ngReset, second: reattach, firstLogLine: localReleaseLogLine, amfUeRemoved: false,
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			amfSelf := amf_context.GetSelf()
			NewAmfContext(amfSelf)
			ran := NewAmfRan(new(ngaptesting.SctpConnStub))
			ranUe, err := ran.NewRanUe(1)
			require.NoError(t, err)
			supi := fmt.Sprintf("imsi-2089300000002%02d", i)
			amfUe := amfSelf.NewAmfUe(supi)
			amfUe.AttachRanUe(ranUe)
			amfUe.State[anType].Set(amf_context.ContextSetup)
			ngap_message.SendUEContextReleaseCommand(ranUe, amf_context.UeContextReleaseUeContext,
				ngap_message.CauseChoiceRadioNetwork, ngapType.CauseRadioNetworkPresentUnspecified)

			firstLogLine := fmt.Sprintf(tc.firstLogLine, supi)
			removedLogLine := fmt.Sprintf("AmfUe[%s] is removed", supi)
			secondRan, removals := false, 0
			hooks := make(logrus.LevelHooks)
			hooks.Add(logHookFunc(func(e *logrus.Entry) {
				switch {
				case e.Message == removedLogLine:
					removals++
				case e.Message == firstLogLine && !secondRan:
					secondRan = true
					if !amfUe.Lock.TryLock() {
						t.Error("the first path wrote its log line while holding amfUe.Lock")
						return
					}
					amfUe.Lock.Unlock()
					tc.second(t, ran, ranUe, amfUe)
				}
			}))
			prevHooks := logger.Log.ReplaceHooks(hooks)
			defer logger.Log.ReplaceHooks(prevHooks)
			if level := logger.Log.GetLevel(); level < logrus.InfoLevel {
				logger.Log.SetLevel(logrus.InfoLevel)
				defer logger.Log.SetLevel(level)
			}

			tc.first(t, ran, ranUe, amfUe)

			require.True(t, secondRan, "the second path did not run")
			wantRemovals := 0
			if tc.amfUeRemoved {
				wantRemovals = 1
			}
			require.Equal(t, wantRemovals, removals, "times the AmfUe was removed")
			_, pooled := amfSelf.AmfUeFindBySupi(supi)
			require.Equal(t, tc.amfUeRemoved, !pooled, "AmfUe removed")
			require.Nil(t, amfSelf.RanUeFindByAmfUeNgapID(ranUe.AmfUeNgapId), "old RanUe removed")
		})
	}
}
