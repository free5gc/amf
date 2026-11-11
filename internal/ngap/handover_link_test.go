package ngap

import (
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/ngap/aper"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// hoLinkTargetNGReset: the target NG-RAN node resets its NG interface
// (TS 38.413 8.7.4, reset-all).
func hoLinkTargetNGReset(e *hoTestEnv) {
	dispatchMain(e.tgtRan, &ngapMessage.NGReset{
		Cause:     &ngapType.Cause{Choice: &ngapType.CauseRadioNetwork{Value: ngapType.CauseRadioNetworkPresentUnspecified}},
		ResetType: &ngapType.ResetType{Choice: &ngapType.ResetAll{}},
	}, nil)
}

// hoLinkReleaseSource: the source requests the release of the UE context and
// completes it (TS 38.413 8.3.2, 8.3.3).
func hoLinkReleaseSource(e *hoTestEnv, cause aper.Enumerated) {
	dispatchMain(e.srcRan, &ngapMessage.UEContextReleaseRequest{
		AMFUENGAPID: &ngapType.AMFUENGAPID{Value: e.src.AmfUeNgapId},
		RANUENGAPID: &ngapType.RANUENGAPID{Value: e.src.RanUeNgapId},
		Cause:       &ngapType.Cause{Choice: &ngapType.CauseRadioNetwork{Value: cause}},
	}, nil)
	dispatchMain(e.srcRan, &ngapMessage.UEContextReleaseComplete{
		AMFUENGAPID: &ngapType.AMFUENGAPID{Value: e.src.AmfUeNgapId},
		RANUENGAPID: &ngapType.RANUENGAPID{Value: e.src.RanUeNgapId},
	}, nil)
}

// The target NG-RAN node resets its NG interface (TS 38.413 8.7.4) after it
// acknowledged the handover. The target RanUe is removed; the source must not
// keep a link to it, or its next HANDOVER REQUIRED is dropped as a duplicate.
// (Whether the source stays the UE's N2 connection is decided by
// AmfUe.DetachRanUe in RanUe.Remove and is not asserted here.)
func TestTargetNGResetDuringHandoverClearsLink(t *testing.T) {
	e := newHoTestEnv(t, true)
	dispatchMain(e.tgtRan, newHoTestAck(e, 7, 5), nil)
	hoLinkTargetNGReset(e)
	require.Nil(t, amf_context.GetSelf().RanUeFindByAmfUeNgapID(e.tgt.AmfUeNgapId))

	dispatchMain(e.srcRan, newHoTestHandoverRequired(e.src), nil)
	hoRequireSent(t, e.tgtConn, "new HANDOVER REQUIRED dropped",
		"HandoverRequest", "NGResetAcknowledge", "HandoverRequest")
	require.NotSame(t, e.tgt, e.src.TargetUe)
}

// The target RanUe is removed after its acknowledge (NG RESET or loss of the
// target NG association) and the source cancels the handover (TS 23.502
// 4.11.1.2.3). The SMF preparation is canceled and the cancel acknowledged
// (steps 4b and 6); nothing is sent for the removed target. A new HANDOVER
// REQUIRED then reaches the target node.
func TestHandoverCancelAfterTargetRemoved(t *testing.T) {
	hoStateCanceled := string(models.Smf_PDUSess_HoState_CANCELLED) //nolint:misspell // OpenAPI enum value
	for _, tc := range []struct {
		name       string
		remove     func(e *hoTestEnv)
		tgtAfterRm []string
		retry      bool // the target node is still connected: prepare a new handover
	}{
		{"NG RESET", hoLinkTargetNGReset, []string{"HandoverRequest", "NGResetAcknowledge"}, true},
		{"association loss", func(e *hoTestEnv) { e.tgtRan.Remove() }, []string{"HandoverRequest"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newHoTestEnv(t, true)
			dispatchMain(e.tgtRan, newHoTestAck(e, 7, 5), nil)
			tc.remove(e)
			smfBefore := len(e.smf.requests())

			dispatchMain(e.srcRan, &ngapMessage.HandoverCancel{
				AMFUENGAPID: &ngapType.AMFUENGAPID{Value: e.src.AmfUeNgapId},
				RANUENGAPID: &ngapType.RANUENGAPID{Value: e.src.RanUeNgapId},
				Cause: &ngapType.Cause{Choice: &ngapType.CauseRadioNetwork{
					Value: ngapType.CauseRadioNetworkPresentHandoverCancelled,
				}},
			}, nil)

			hoRequireSent(t, e.srcConn, "HANDOVER CANCEL not acknowledged",
				"HandoverCommand", "HandoverCancelAcknowledge")
			e.smf.requireRequests(t, smfBefore, "SMF preparation not canceled", hoStateCanceled)
			require.Equal(t, amf_context.OnGoingProcedureNothing, e.amfUe.OnGoing(hoTestAnType).Procedure)
			hoRequireSent(t, e.tgtConn, "message sent for the removed target", tc.tgtAfterRm...)

			if tc.retry {
				dispatchMain(e.srcRan, newHoTestHandoverRequired(e.src), nil)
				hoRequireSent(t, e.tgtConn, "new HANDOVER REQUIRED dropped",
					append(tc.tgtAfterRm, "HandoverRequest")...)
			}
		})
	}
}

// The source releases the UE while the target prepares (TS 38.413 8.3.2), and
// the target then refuses the handover with HANDOVER FAILURE. The SMF
// preparation is canceled (TS 29.502 5.2.2.3.4.2), the ongoing N2 handover is
// ended and the target is released; nothing is sent for the removed source.
func TestHandoverFailureAfterSourceRelease(t *testing.T) {
	e := newHoTestEnv(t, true)
	hoLinkReleaseSource(e, ngapType.CauseRadioNetworkPresentUserInactivity)
	hoRequireSent(t, e.srcConn, "source not released", "UEContextReleaseCommand")
	smfBefore := len(e.smf.requests())

	dispatchMain(e.tgtRan, &ngapMessage.HandoverFailure{
		AMFUENGAPID: &ngapType.AMFUENGAPID{Value: e.tgt.AmfUeNgapId},
		Cause: &ngapType.Cause{Choice: &ngapType.CauseRadioNetwork{
			Value: ngapType.CauseRadioNetworkPresentNoRadioResourcesAvailableInTargetCell,
		}},
	}, nil)

	hoStateCanceled := string(models.Smf_PDUSess_HoState_CANCELLED) //nolint:misspell // OpenAPI enum value
	e.smf.requireRequests(t, smfBefore, "SMF preparation not canceled", hoStateCanceled)
	require.Equal(t, amf_context.OnGoingProcedureNothing, e.amfUe.OnGoing(hoTestAnType).Procedure,
		"N2 handover left ongoing")
	hoRequireSent(t, e.srcConn, "message sent for the removed source", "UEContextReleaseCommand")
	hoRequireSent(t, e.tgtConn, "target not released", "HandoverRequest", "UEContextReleaseCommand")
}

// The source NG association is lost after the HANDOVER COMMAND, and the UE
// still arrives at the target. The genuine HANDOVER NOTIFY (TS 38.413 8.4.3.2)
// completes the handover without addressing the removed source.
func TestHandoverNotifyAfterSourceAssociationLoss(t *testing.T) {
	e := newHoTestEnv(t, true)
	dispatchMain(e.tgtRan, newHoTestAck(e, 7, 5), nil)
	hoRequireSent(t, e.srcConn, "no HANDOVER COMMAND", "HandoverCommand")
	smfBefore := len(e.smf.requests())
	e.srcRan.Remove()

	dispatchMain(e.tgtRan, newHoTestNotify(e, 7), nil)

	require.Same(t, e.tgt, e.amfUe.RanUe[hoTestAnType], "handover not completed")
	e.smf.requireRequests(t, smfBefore, "handover completion not sent to the SMF", "COMPLETED")
	require.Equal(t, amf_context.OnGoingProcedureNothing, e.amfUe.OnGoing(hoTestAnType).Procedure)
	hoRequireSent(t, e.srcConn, "message sent for the removed source", "HandoverCommand")
	require.Nil(t, e.tgt.SourceUe)
}

// The source releases the UE after the HANDOVER COMMAND (TS 38.413 8.3.3.4,
// TNGRELOCoverall expiry) while the UE reaches the target.
func TestHandoverNotifyAfterSourceRelease(t *testing.T) {
	e := newHoTestEnv(t, true)
	dispatchMain(e.tgtRan, newHoTestAck(e, 7, 5), nil)
	hoLinkReleaseSource(e, ngapType.CauseRadioNetworkPresentTngrelocoverallExpiry)
	hoRequireSent(t, e.srcConn, "source not released", "HandoverCommand", "UEContextReleaseCommand")
	smfBefore := len(e.smf.requests())

	dispatchMain(e.tgtRan, newHoTestNotify(e, 7), nil)

	require.Same(t, e.tgt, e.amfUe.RanUe[hoTestAnType], "handover not completed")
	e.smf.requireRequests(t, smfBefore, "handover completion not sent to the SMF", "COMPLETED")
	hoRequireSent(t, e.srcConn, "released source addressed again", "HandoverCommand", "UEContextReleaseCommand")
}
