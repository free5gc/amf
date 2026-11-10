package ngap

import (
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
)

func requirePrematureNotifyErrorIndication(t *testing.T, raw []byte) {
	t.Helper()
	m, err := ngapMessage.Parse(raw)
	require.NoError(t, err)
	ei, ok := m.(*ngapMessage.ErrorIndication)
	require.True(t, ok, "not an Error Indication: %T", m)
	require.Equal(t, &ngapType.Cause{Choice: &ngapType.CauseProtocol{
		Value: ngapType.CauseProtocolPresentMessageNotCompatibleWithReceiverState,
	}}, ei.Cause)
	require.NotNil(t, ei.CriticalityDiagnostics)
	require.Equal(t, ngapMessage.ProcedureCodeHandoverNotification, ei.CriticalityDiagnostics.ProcedureCode.Value)
	require.Equal(t, ngapType.TriggeringMessagePresentInitiatingMessage,
		ei.CriticalityDiagnostics.TriggeringMessage.Value)
}

// A HANDOVER NOTIFY from a prepared target that has not acknowledged yet (it
// can only echo the AMF's placeholder RAN-UE-NGAP-ID) must not complete the
// handover.
func TestHandoverNotifyBeforeAcknowledge(t *testing.T) {
	e := newHoTestEnv(t, true)
	dispatchMain(e.tgtRan, newHoTestNotify(e, amf_context.RanUeNgapIdUnspecified), nil)

	require.Same(t, e.src, e.amfUe.RanUe[hoTestAnType], "UE moved to a target that never acknowledged")
	hoRequireSent(t, e.srcConn, "source released")
	e.smf.requireRequests(t, 0, "handover completed at the SMF", "PREPARING/HANDOVER_REQUIRED")
	hoRequireSent(t, e.tgtConn, "premature notify not answered", "HandoverRequest", "ErrorIndication")
	requirePrematureNotifyErrorIndication(t, e.tgtConn.MsgList[1])
}

// When the acknowledge ends in HANDOVER PREPARATION FAILURE (no PDU session
// could be handed over), no HANDOVER COMMAND was sent and a later notify is
// equally premature.
func TestHandoverNotifyAfterPreparationFailure(t *testing.T) {
	e := newHoTestEnv(t, true)
	dispatchMain(e.tgtRan, newHoTestAck(e, 7, 9), nil) // PDU session 9 does not exist
	hoRequireSent(t, e.srcConn, "no HANDOVER PREPARATION FAILURE", "HandoverPreparationFailure")
	smfBefore := len(e.smf.requests())

	dispatchMain(e.tgtRan, newHoTestNotify(e, 7), nil)
	require.Same(t, e.src, e.amfUe.RanUe[hoTestAnType], "handover completed after preparation failure")
	hoRequireSent(t, e.srcConn, "source released", "HandoverPreparationFailure")
	e.smf.requireRequests(t, smfBefore, "handover completed at the SMF")
	hoRequireSent(t, e.tgtConn, "premature notify not answered", "HandoverRequest", "ErrorIndication")
	requirePrematureNotifyErrorIndication(t, e.tgtConn.MsgList[1])
}

// Control: the notify that follows the HANDOVER COMMAND completes the handover.
func TestHandoverNotifyAfterHandoverCommand(t *testing.T) {
	e := newHoTestEnv(t, true)
	dispatchMain(e.tgtRan, newHoTestAck(e, 7, 5), nil)
	dispatchMain(e.tgtRan, newHoTestNotify(e, 7), nil)

	require.Same(t, e.tgt, e.amfUe.RanUe[hoTestAnType])
	hoRequireSent(t, e.srcConn, "source not released", "HandoverCommand", "UEContextReleaseCommand")
	e.smf.requireRequests(t, 0, "handover not completed at the SMF",
		"PREPARING/HANDOVER_REQUIRED", "PREPARED/HANDOVER_REQ_ACK", "COMPLETED")
	hoRequireSent(t, e.tgtConn, "notify answered", "HandoverRequest")
}
