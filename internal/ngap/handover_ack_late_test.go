package ngap

import (
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

const hoStateCanceled = string(models.Smf_PDUSess_HoState_CANCELLED) //nolint:misspell // OpenAPI enum value

func newHoTestReleaseRequest(ranUe *amf_context.RanUe) *ngapMessage.UEContextReleaseRequest {
	return &ngapMessage.UEContextReleaseRequest{
		AMFUENGAPID: &ngapType.AMFUENGAPID{Value: ranUe.AmfUeNgapId},
		RANUENGAPID: &ngapType.RANUENGAPID{Value: ranUe.RanUeNgapId},
		PDUSessionResourceListCxtRelReq: &ngapType.PDUSessionResourceListCxtRelReq{
			List: []ngapType.PDUSessionResourceItemCxtRelReq{{PDUSessionID: &ngapType.PDUSessionID{Value: 5}}},
		},
		Cause: &ngapType.Cause{Choice: &ngapType.CauseRadioNetwork{
			Value: ngapType.CauseRadioNetworkPresentUserInactivity,
		}},
	}
}

func newHoTestReleaseComplete(ranUe *amf_context.RanUe, ranID int64) *ngapMessage.UEContextReleaseComplete {
	return &ngapMessage.UEContextReleaseComplete{
		AMFUENGAPID: &ngapType.AMFUENGAPID{Value: ranUe.AmfUeNgapId},
		RANUENGAPID: &ngapType.RANUENGAPID{Value: ranID},
	}
}

// requireHandoverCancelledRelease checks that the second message sent to the
// target is UE CONTEXT RELEASE COMMAND with the HandoverCancelled cause.
func requireHandoverCancelledRelease(t *testing.T, e *hoTestEnv) {
	t.Helper()
	hoRequireSent(t, e.tgtConn, "target resources not released", "HandoverRequest", "UEContextReleaseCommand")
	m, err := ngapMessage.Parse(e.tgtConn.MsgList[1])
	require.NoError(t, err)
	release, ok := m.(*ngapMessage.UEContextReleaseCommand)
	require.True(t, ok)
	require.Equal(t, &ngapType.Cause{Choice: &ngapType.CauseRadioNetwork{
		Value: ngapType.CauseRadioNetworkPresentHandoverCancelled,
	}}, release.Cause)
}

// The source asks for the UE's release while the target is still preparing the
// handover. The handover cannot be executed any more, so the AMF cancels it as
// for a HANDOVER CANCEL (TS 23.502 4.9.1.4, 4.11.1.2.3): it cancels the
// preparation at the SMF and releases the target. A late acknowledge from the
// target gets no HANDOVER COMMAND, and the target's UE CONTEXT RELEASE COMPLETE
// removes it.
func TestUEContextReleaseRequestDuringHandoverPreparation(t *testing.T) {
	e := newHoTestEnv(t, true)
	smfBefore := len(e.smf.requests())

	dispatchMain(e.srcRan, newHoTestReleaseRequest(e.src), nil)

	e.smf.requireRequests(t, smfBefore, "SMF preparation not canceled before the AN release",
		hoStateCanceled, "DEACTIVATED")
	require.Equal(t, amf_context.OnGoingProcedureNothing, e.amfUe.OnGoing(hoTestAnType).Procedure)
	requireHandoverCancelledRelease(t, e)
	require.Nil(t, e.src.TargetUe)
	hoRequireSent(t, e.srcConn, "source not released", "UEContextReleaseCommand")

	dispatchMain(e.srcRan, newHoTestReleaseComplete(e.src, e.src.RanUeNgapId), nil)
	smfBefore = len(e.smf.requests())
	dispatchMain(e.tgtRan, newHoTestAck(e, 7, 5), nil)
	hoRequireSent(t, e.srcConn, "message sent to the released source", "UEContextReleaseCommand")
	e.smf.requireRequests(t, smfBefore, "SMF request for the late acknowledge")
	hoRequireSent(t, e.tgtConn, "message sent to the target for the late acknowledge",
		"HandoverRequest", "UEContextReleaseCommand")

	dispatchMain(e.tgtRan, newHoTestReleaseComplete(e.tgt, 7), nil)
	require.Nil(t, amf_context.GetSelf().RanUeFindByAmfUeNgapID(e.tgt.AmfUeNgapId), "target RanUe left behind")
	require.Nil(t, e.amfUe.RanUe[hoTestAnType])
}

// Control: once the HANDOVER COMMAND is sent, a UE CONTEXT RELEASE REQUEST from
// the source does not cancel the handover, and the target's HANDOVER NOTIFY
// still completes it.
func TestUEContextReleaseRequestAfterHandoverCommand(t *testing.T) {
	e := newHoTestEnv(t, true)
	dispatchMain(e.tgtRan, newHoTestAck(e, 7, 5), nil)
	hoRequireSent(t, e.srcConn, "no HANDOVER COMMAND", "HandoverCommand")
	smfBefore := len(e.smf.requests())

	dispatchMain(e.srcRan, newHoTestReleaseRequest(e.src), nil)

	e.smf.requireRequests(t, smfBefore, "handover canceled after the HANDOVER COMMAND", "DEACTIVATED")
	require.Equal(t, amf_context.OnGoingProcedureN2Handover, e.amfUe.OnGoing(hoTestAnType).Procedure)
	hoRequireSent(t, e.tgtConn, "target released after the HANDOVER COMMAND", "HandoverRequest")

	dispatchMain(e.srcRan, newHoTestReleaseComplete(e.src, e.src.RanUeNgapId), nil)
	dispatchMain(e.tgtRan, newHoTestNotify(e, 7), nil)
	require.Same(t, e.tgt, e.amfUe.RanUe[hoTestAnType])
}

// The source's SCTP association is lost while the target prepares; the
// target's acknowledge arrives late. The AMF must not send a HANDOVER COMMAND
// for the removed source; it cancels the handover at the SMF and releases the
// target (TS 23.502 4.11.1.2.3).
func TestHandoverRequestAcknowledgeAfterSourceLoss(t *testing.T) {
	e := newHoTestEnv(t, true)
	HandleSCTPConnError(e.srcConn)
	require.Nil(t, e.amfUe.RanUe[hoTestAnType])
	smfBefore := len(e.smf.requests())

	dispatchMain(e.tgtRan, newHoTestAck(e, 7, 5), nil)

	hoRequireSent(t, e.srcConn, "message sent to the removed source")
	e.smf.requireRequests(t, smfBefore, "SMF preparation not canceled", hoStateCanceled)
	require.Equal(t, amf_context.OnGoingProcedureNothing, e.amfUe.OnGoing(hoTestAnType).Procedure)
	requireHandoverCancelledRelease(t, e)

	require.NotPanics(t, func() {
		dispatchMain(e.tgtRan, newHoTestReleaseComplete(e.tgt, 7), nil)
	})
	require.Nil(t, amf_context.GetSelf().RanUeFindByAmfUeNgapID(e.tgt.AmfUeNgapId), "target RanUe left behind")
	require.Nil(t, e.amfUe.RanUe[hoTestAnType])
}

// Control: with the source still serving, the acknowledge is answered with a
// HANDOVER COMMAND and the notify completes the handover.
func TestHandoverRequestAcknowledgeWithServingSource(t *testing.T) {
	e := newHoTestEnv(t, true)
	dispatchMain(e.tgtRan, newHoTestAck(e, 7, 5), nil)
	hoRequireSent(t, e.srcConn, "no HANDOVER COMMAND", "HandoverCommand")
	e.smf.requireRequests(t, 0, "SMF not prepared", "PREPARING/HANDOVER_REQUIRED", "PREPARED/HANDOVER_REQ_ACK")

	dispatchMain(e.tgtRan, newHoTestNotify(e, 7), nil)
	require.Same(t, e.tgt, e.amfUe.RanUe[hoTestAnType])
}
