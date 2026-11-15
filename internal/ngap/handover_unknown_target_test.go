package ngap

import (
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/ngap/aper"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
)

// TS 38.413 8.4.1.3: a HANDOVER REQUIRED towards a gNB that the AMF does not
// know gets a HANDOVER PREPARATION FAILURE with cause "Unknown target ID", and
// the UE is no longer in an N2 handover.
func TestHandoverRequiredToUnknownTarget(t *testing.T) {
	e := newHoTestEnv(t, false)
	msg := newHoTestHandoverRequired(e.src)
	globalGNBID := msg.TargetID.Choice.(*ngapType.TargetRANNodeID).GlobalRANNodeID.Choice.(*ngapType.GlobalGNBID)
	globalGNBID.GNBID.Choice = &ngapType.GNBIDForGNBID{Value: aper.BitString{
		Bytes: []byte{0x00, 0x00, 0x03}, BitLength: 24,
	}}

	dispatchMain(e.srcRan, msg, nil)

	hoRequireSent(t, e.srcConn, "source not answered", "HandoverPreparationFailure")
	m, err := ngapMessage.Parse(e.srcConn.MsgList[0])
	require.NoError(t, err)
	failure, ok := m.(*ngapMessage.HandoverPreparationFailure)
	require.True(t, ok)
	require.Equal(t, &ngapType.Cause{Choice: &ngapType.CauseRadioNetwork{
		Value: ngapType.CauseRadioNetworkPresentUnknownTargetID,
	}}, failure.Cause)
	hoRequireSent(t, e.tgtConn, "other gNB contacted")
	e.smf.requireRequests(t, 0, "SMF asked to prepare a handover")
	require.Equal(t, amf_context.OnGoingProcedureNothing, e.amfUe.OnGoing(hoTestAnType).Procedure)
}
