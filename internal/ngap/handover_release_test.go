package ngap

import (
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
)

func sendHandoverCancel(e *hoTestEnv) {
	dispatchMain(e.srcRan, &ngapMessage.HandoverCancel{
		AMFUENGAPID: &ngapType.AMFUENGAPID{Value: e.src.AmfUeNgapId},
		RANUENGAPID: &ngapType.RANUENGAPID{Value: e.src.RanUeNgapId},
		Cause: &ngapType.Cause{Choice: &ngapType.CauseRadioNetwork{
			Value: ngapType.CauseRadioNetworkPresentTngrelocprepExpiry,
		}},
	}, nil)
}

func sendTargetReleaseComplete(e *hoTestEnv, ranID int64, pduSessionIDs ...int64) {
	msg := &ngapMessage.UEContextReleaseComplete{
		AMFUENGAPID: &ngapType.AMFUENGAPID{Value: e.tgt.AmfUeNgapId},
		RANUENGAPID: &ngapType.RANUENGAPID{Value: ranID},
	}
	if len(pduSessionIDs) > 0 {
		msg.PDUSessionResourceListCxtRelCpl = &ngapType.PDUSessionResourceListCxtRelCpl{}
		for _, id := range pduSessionIDs {
			msg.PDUSessionResourceListCxtRelCpl.List = append(msg.PDUSessionResourceListCxtRelCpl.List,
				ngapType.PDUSessionResourceItemCxtRelCpl{PDUSessionID: &ngapType.PDUSessionID{Value: id}})
		}
	}
	dispatchMain(e.tgtRan, msg, nil)
}

// TS 23.502 4.11.1.2.3: the source cancels an acknowledged handover; the AMF
// cancels the SMF preparation and releases the target, whose UE CONTEXT
// RELEASE COMPLETE (TS 38.413 8.3.3.2) must release only the target.
func TestHandoverCancelThenTargetReleaseComplete(t *testing.T) {
	e := newHoTestEnv(t, true)
	dispatchMain(e.tgtRan, newHoTestAck(e, 7, 5), nil)
	hoRequireSent(t, e.srcConn, "no HANDOVER COMMAND", "HandoverCommand")

	sendHandoverCancel(e)
	hoRequireSent(t, e.srcConn, "cancel not acknowledged", "HandoverCommand", "HandoverCancelAcknowledge")
	hoRequireSent(t, e.tgtConn, "target not released", "HandoverRequest", "UEContextReleaseCommand")
	smfBefore := len(e.smf.requests())

	// The target may list the PDU sessions it had admitted (TS 38.413 9.2.2.6).
	require.NotPanics(t, func() { sendTargetReleaseComplete(e, 7, 5) })

	require.Same(t, e.src, e.amfUe.RanUe[hoTestAnType], "serving source detached")
	require.Nil(t, e.src.TargetUe)
	require.Nil(t, amf_context.GetSelf().RanUeFindByAmfUeNgapID(e.tgt.AmfUeNgapId), "target RanUe not released")
	e.smf.requireRequests(t, smfBefore, "target release changed the sessions served by the source")
}

// TS 38.413 8.4.2.3: the target answers HANDOVER FAILURE; the AMF sends
// HANDOVER PREPARATION FAILURE to the source and releases the target.
func TestHandoverFailureThenTargetReleaseComplete(t *testing.T) {
	e := newHoTestEnv(t, true)
	dispatchMain(e.tgtRan, &ngapMessage.HandoverFailure{
		AMFUENGAPID: &ngapType.AMFUENGAPID{Value: e.tgt.AmfUeNgapId},
		Cause: &ngapType.Cause{Choice: &ngapType.CauseRadioNetwork{
			Value: ngapType.CauseRadioNetworkPresentNoRadioResourcesAvailableInTargetCell,
		}},
	}, nil)
	hoRequireSent(t, e.srcConn, "source not told", "HandoverPreparationFailure")
	hoRequireSent(t, e.tgtConn, "target not released", "HandoverRequest", "UEContextReleaseCommand")

	// The target never acknowledged, so the AMF still holds the placeholder
	// RAN-UE-NGAP-ID for it.
	require.NotPanics(t, func() { sendTargetReleaseComplete(e, amf_context.RanUeNgapIdUnspecified) })

	require.Same(t, e.src, e.amfUe.RanUe[hoTestAnType], "serving source detached")
	require.Nil(t, e.src.TargetUe)
	require.Nil(t, amf_context.GetSelf().RanUeFindByAmfUeNgapID(e.tgt.AmfUeNgapId), "target RanUe not released")
}

// After a canceled preparation the source may start a new handover at once
// (TS 38.413 8.4.1), before the old target has answered its release. The new
// HANDOVER REQUIRED must be served, not dropped as a duplicate.
func TestHandoverRequiredRightAfterCancel(t *testing.T) {
	e := newHoTestEnv(t, true)
	sendHandoverCancel(e)
	hoRequireSent(t, e.srcConn, "cancel not acknowledged", "HandoverCancelAcknowledge")

	dispatchMain(e.srcRan, newHoTestHandoverRequired(e.src), nil)
	hoRequireSent(t, e.tgtConn, "new HANDOVER REQUIRED dropped",
		"HandoverRequest", "UEContextReleaseCommand", "HandoverRequest")
	require.NotNil(t, e.src.TargetUe)
	require.NotSame(t, e.tgt, e.src.TargetUe)
}

// A HANDOVER CANCEL that crosses the HANDOVER NOTIFY reaches the AMF after the
// target already serves the UE. The release of the former target must not
// crash the NGAP worker.
func TestHandoverCancelAfterHandoverNotify(t *testing.T) {
	e := newHoTestEnv(t, true)
	dispatchMain(e.tgtRan, newHoTestAck(e, 7, 5), nil)
	dispatchMain(e.tgtRan, newHoTestNotify(e, 7), nil)
	require.Same(t, e.tgt, e.amfUe.RanUe[hoTestAnType])

	sendHandoverCancel(e)
	hoRequireSent(t, e.tgtConn, "target not released", "HandoverRequest", "UEContextReleaseCommand")

	require.NotPanics(t, func() { sendTargetReleaseComplete(e, 7) })
	require.Nil(t, e.amfUe.RanUe[hoTestAnType], "released RanUe still attached to the UE")
	require.Nil(t, amf_context.GetSelf().RanUeFindByAmfUeNgapID(e.tgt.AmfUeNgapId))
}
