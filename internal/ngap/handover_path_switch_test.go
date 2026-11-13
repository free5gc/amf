package ngap

import (
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	nastesting "github.com/free5gc/amf/internal/nas/testing"
	nasie "github.com/free5gc/nas/ie"
	"github.com/free5gc/ngap/aper"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
)

// sendXnPathSwitch delivers the target node's PATH SWITCH REQUEST for the UE
// served by e.src, with the target's new RAN-UE-NGAP-ID ranID.
func sendXnPathSwitch(e *hoTestEnv, ranID, pduSessionID int64) {
	transfer := aper.OctetString{0x00}
	dispatchMain(e.tgtRan, &ngapMessage.PathSwitchRequest{
		RANUENGAPID:       &ngapType.RANUENGAPID{Value: ranID},
		SourceAMFUENGAPID: &ngapType.AMFUENGAPID{Value: e.src.AmfUeNgapId},
		PDUSessionResourceToBeSwitchedDLList: &ngapType.PDUSessionResourceToBeSwitchedDLList{
			List: []ngapType.PDUSessionResourceToBeSwitchedDLItem{{
				PDUSessionID:              &ngapType.PDUSessionID{Value: pduSessionID},
				PathSwitchRequestTransfer: &transfer,
			}},
		},
	}, nil)
}

func ranUeNgapIDKeys(ran *amf_context.AmfRan) map[int64]*amf_context.RanUe {
	keys := map[int64]*amf_context.RanUe{}
	ran.RanUeList.Range(func(k, v any) bool {
		keys[k.(int64)] = v.(*amf_context.RanUe)
		return true
	})
	return keys
}

// TS 23.502 4.9.1.2.2: after the path switch the source NG-RAN node releases
// the UE over Xn, so the AMF must keep the UE only under the target node's
// RAN-UE-NGAP-ID.
func TestPathSwitchMovesRanUeNgapIDKey(t *testing.T) {
	e := newHoTestEnv(t, false)
	sendXnPathSwitch(e, 10, 5)

	hoRequireSent(t, e.tgtConn, "path switch not acknowledged", "PathSwitchRequestAcknowledge")
	e.smf.requireRequests(t, 0, "SMF not asked to switch the path", "PATH_SWITCH_REQ")
	require.Same(t, e.tgtRan, e.src.Ran)
	require.EqualValues(t, 10, e.src.RanUeNgapId)
	require.Empty(t, ranUeNgapIDKeys(e.srcRan), "stale RAN-UE-NGAP-ID key left on the source node")
	require.Equal(t, map[int64]*amf_context.RanUe{10: e.src}, ranUeNgapIDKeys(e.tgtRan))
}

// An NG RESET of the whole source NG interface after the UE left by Xn must
// not remove the moved UE (TS 38.413 8.7.4.2.2 resets only the associations
// of that interface).
func TestPathSwitchSourceNGResetKeepsMovedUe(t *testing.T) {
	e := newHoTestEnv(t, false)
	sendXnPathSwitch(e, 10, 5)

	dispatchMain(e.srcRan, &ngapMessage.NGReset{
		Cause:     &ngapType.Cause{Choice: &ngapType.CauseRadioNetwork{Value: ngapType.CauseRadioNetworkPresentUnspecified}},
		ResetType: &ngapType.ResetType{Choice: &ngapType.ResetAll{}},
	}, nil)

	hoRequireSent(t, e.srcConn, "NG RESET not acknowledged", "NGResetAcknowledge")
	require.Same(t, e.src, e.amfUe.RanUe[hoTestAnType], "moved UE lost its N2 connection")
	require.Same(t, e.src, amf_context.GetSelf().RanUeFindByAmfUeNgapID(e.src.AmfUeNgapId))
}

// The source node may give its freed RAN-UE-NGAP-ID to a new UE. The INITIAL
// UE MESSAGE that reuses it must not tear down the moved UE.
func TestPathSwitchSourceReusesRanUeNgapID(t *testing.T) {
	e := newHoTestEnv(t, false)
	sendXnPathSwitch(e, 10, 5)

	msg := BuildInitialUEMessage(t, 1, nastesting.GetServiceRequest(uint8(nasie.SvcType_Data)), "fe0000000001")
	encoded, err := msg.MarshalBinary()
	require.NoError(t, err)
	dispatchMain(e.srcRan, msg, encoded)

	require.Same(t, e.src, e.amfUe.RanUe[hoTestAnType], "moved UE lost its N2 connection")
	require.Same(t, e.src, amf_context.GetSelf().RanUeFindByAmfUeNgapID(e.src.AmfUeNgapId))
}

// A path switch that fails (no PDU session switched) leaves the UE on the
// source node, which keeps addressing it with its own RAN-UE-NGAP-ID.
func TestPathSwitchFailureKeepsRanUeNgapID(t *testing.T) {
	e := newHoTestEnv(t, false)
	sendXnPathSwitch(e, 10, 9) // PDU session 9 does not exist

	hoRequireSent(t, e.tgtConn, "failed path switch acknowledged")
	e.smf.requireRequests(t, 0, "SMF asked to switch an unknown PDU session")
	require.Same(t, e.srcRan, e.src.Ran)
	require.EqualValues(t, 1, e.src.RanUeNgapId)

	dispatchMain(e.srcRan, &ngapMessage.RRCInactiveTransitionReport{
		AMFUENGAPID: &ngapType.AMFUENGAPID{Value: e.src.AmfUeNgapId},
		RANUENGAPID: &ngapType.RANUENGAPID{Value: 1},
		RRCState:    &ngapType.RRCState{Value: ngapType.RRCStatePresentConnected},
	}, nil)
	hoRequireSent(t, e.srcConn, "source's own AP IDs rejected")
	require.Same(t, e.src, e.amfUe.RanUe[hoTestAnType])
}
