package ngap

import (
	"testing"

	"github.com/stretchr/testify/require"

	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
)

func requireDuplicateNotifyErrorIndication(t *testing.T, raw []byte) {
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

// A HANDOVER NOTIFY repeated after the handover completed (before and after
// the source's UE CONTEXT RELEASE COMPLETE) must not release the source or
// complete the handover at the SMF again; it is answered with Error Indication.
func TestHandoverNotifyRepeatedAfterCompletion(t *testing.T) {
	e := newHoTestEnv(t, true)
	dispatchMain(e.tgtRan, newHoTestAck(e, 7, 5), nil)
	dispatchMain(e.tgtRan, newHoTestNotify(e, 7), nil)
	require.Same(t, e.tgt, e.amfUe.RanUe[hoTestAnType])
	hoRequireSent(t, e.srcConn, "source not released", "HandoverCommand", "UEContextReleaseCommand")
	smfAfterCompletion := len(e.smf.requests())

	dispatchMain(e.tgtRan, newHoTestNotify(e, 7), nil)
	dispatchMain(e.srcRan, &ngapMessage.UEContextReleaseComplete{
		AMFUENGAPID: &ngapType.AMFUENGAPID{Value: e.src.AmfUeNgapId},
		RANUENGAPID: &ngapType.RANUENGAPID{Value: e.src.RanUeNgapId},
	}, nil)
	dispatchMain(e.tgtRan, newHoTestNotify(e, 7), nil)

	hoRequireSent(t, e.srcConn, "source released again", "HandoverCommand", "UEContextReleaseCommand")
	e.smf.requireRequests(t, smfAfterCompletion, "handover completed again at the SMF")
	require.Same(t, e.tgt, e.amfUe.RanUe[hoTestAnType])
	hoRequireSent(t, e.tgtConn, "repeated notify not answered", "HandoverRequest", "ErrorIndication", "ErrorIndication")
	requireDuplicateNotifyErrorIndication(t, e.tgtConn.MsgList[1])
	requireDuplicateNotifyErrorIndication(t, e.tgtConn.MsgList[2])
}
