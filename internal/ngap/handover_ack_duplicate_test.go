package ngap

import (
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
)

// A repeated HANDOVER REQUEST ACKNOWLEDGE with the same AP IDs must not
// remove the prepared target or run the preparation again; the HANDOVER
// NOTIFY that follows completes the handover.
func TestHandoverRequestAcknowledgeExactDuplicateIgnored(t *testing.T) {
	e := newHoTestEnv(t, true)
	dispatchMain(e.tgtRan, newHoTestAck(e, 7, 5), nil)
	hoRequireSent(t, e.srcConn, "no HANDOVER COMMAND", "HandoverCommand")

	dispatchMain(e.tgtRan, newHoTestAck(e, 7, 5), nil)
	hoRequireSent(t, e.tgtConn, "duplicate answered on the target", "HandoverRequest")
	require.Same(t, e.tgt, amf_context.GetSelf().RanUeFindByAmfUeNgapID(e.tgt.AmfUeNgapId), "target removed")
	hoRequireSent(t, e.srcConn, "second HANDOVER COMMAND", "HandoverCommand")
	e.smf.requireRequests(t, 0, "preparation repeated at the SMF",
		"PREPARING/HANDOVER_REQUIRED", "PREPARED/HANDOVER_REQ_ACK")

	dispatchMain(e.tgtRan, newHoTestNotify(e, 7), nil)
	require.Same(t, e.tgt, e.amfUe.RanUe[hoTestAnType], "handover not completed")
}

// TS 38.413 10.6: a second acknowledge carrying a different RAN-UE-NGAP-ID is
// an inconsistent remote AP ID and is still answered with Error Indication.
func TestHandoverRequestAcknowledgeOtherRanUeNgapIDIsAPIDError(t *testing.T) {
	e := newHoTestEnv(t, true)
	dispatchMain(e.tgtRan, newHoTestAck(e, 7, 5), nil)
	dispatchMain(e.tgtRan, newHoTestAck(e, 8, 5), nil)

	hoRequireSent(t, e.tgtConn, "inconsistent RAN-UE-NGAP-ID not reported", "HandoverRequest", "ErrorIndication")
	m, err := ngapMessage.Parse(e.tgtConn.MsgList[1])
	require.NoError(t, err)
	ei, ok := m.(*ngapMessage.ErrorIndication)
	require.True(t, ok)
	require.Equal(t, &ngapType.Cause{Choice: &ngapType.CauseRadioNetwork{
		Value: ngapType.CauseRadioNetworkPresentInconsistentRemoteUENGAPID,
	}}, ei.Cause)
	require.Nil(t, amf_context.GetSelf().RanUeFindByAmfUeNgapID(e.tgt.AmfUeNgapId), "target not released locally")
}
