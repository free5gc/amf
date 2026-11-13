package ngap

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/ngap/aper"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// newPathSwitchTestRequest is a PATH SWITCH REQUEST from the target node that names the given PDU sessions.
func newPathSwitchTestRequest(sourceAmfUeNgapID int64, pduSessionIDs ...int64) *ngapMessage.PathSwitchRequest {
	list := &ngapType.PDUSessionResourceToBeSwitchedDLList{}
	for _, id := range pduSessionIDs {
		transfer := aper.OctetString{0x00}
		list.List = append(list.List, ngapType.PDUSessionResourceToBeSwitchedDLItem{
			PDUSessionID:              &ngapType.PDUSessionID{Value: id},
			PathSwitchRequestTransfer: &transfer,
		})
	}
	return &ngapMessage.PathSwitchRequest{
		RANUENGAPID:                          &ngapType.RANUENGAPID{Value: 7},
		SourceAMFUENGAPID:                    &ngapType.AMFUENGAPID{Value: sourceAmfUeNgapID},
		PDUSessionResourceToBeSwitchedDLList: list,
	}
}

// requirePathSwitchFailure checks that the last message on conn is a PATH SWITCH REQUEST FAILURE that releases one
// PDU session, with the cause given in its Path Switch Request Unsuccessful Transfer.
func requirePathSwitchFailure(t *testing.T, conn *ngaptesting.SctpConnStub, pduSessionID int64, cause *ngapType.Cause) {
	t.Helper()
	m, err := ngapMessage.Parse(conn.MsgList[len(conn.MsgList)-1])
	require.NoError(t, err)
	failure, ok := m.(*ngapMessage.PathSwitchRequestFailure)
	require.True(t, ok, "sent %T", m)
	require.Len(t, failure.PDUSessionResourceReleasedListPSFail.List, 1)
	item := failure.PDUSessionResourceReleasedListPSFail.List[0]
	require.Equal(t, pduSessionID, item.PDUSessionID.Value)
	var transfer ngapType.PathSwitchRequestUnsuccessfulTransfer
	require.NoError(t, ngapType.UnmarshalBinary(*item.PathSwitchRequestUnsuccessfulTransfer, &transfer))
	require.Equal(t, cause, transfer.Cause)
}

// TS 38.413 10.4: the target of a HANDOVER REQUEST that it never acknowledged names, as the source AMF UE NGAP ID,
// the AMF UE NGAP ID of that request, which is not the UE's NGAP association. The AMF refuses the request and asks
// no SMF to switch the session.
func TestPathSwitchFromUnacknowledgedHandoverTargetIsRefused(t *testing.T) {
	e := newHoTestEnv(t, true)
	smfBefore := len(e.smf.requests())

	dispatchMain(e.tgtRan, newPathSwitchTestRequest(e.tgt.AmfUeNgapId, 5), nil)

	hoRequireSent(t, e.tgtConn, "path switch not refused", "HandoverRequest", "PathSwitchRequestFailure")
	requirePathSwitchFailure(t, e.tgtConn, 5, &ngapType.Cause{Choice: &ngapType.CauseProtocol{
		Value: ngapType.CauseProtocolPresentMessageNotCompatibleWithReceiverState,
	}})
	e.smf.requireRequests(t, smfBefore, "session switched to the target")
}

// TS 38.413 8.4.4.4: a PATH SWITCH REQUEST that names PDU session 5 twice is refused before any SMF is asked.
func TestPathSwitchNamingSessionTwiceIsRefused(t *testing.T) {
	e := newHoTestEnv(t, false)

	dispatchMain(e.tgtRan, newPathSwitchTestRequest(e.src.AmfUeNgapId, 5, 5), nil)

	hoRequireSent(t, e.tgtConn, "path switch not refused", "PathSwitchRequestFailure")
	requirePathSwitchFailure(t, e.tgtConn, 5, &ngapType.Cause{Choice: &ngapType.CauseRadioNetwork{
		Value: ngapType.CauseRadioNetworkPresentMultiplePDUSessionIDInstances,
	}})
	e.smf.requireRequests(t, 0, "session switched")
}

// TS 38.413 8.4.4.3, 9.2.3.10: a PATH SWITCH REQUEST that names only a PDU session that the UE does not have gets a
// PATH SWITCH REQUEST FAILURE, whose PDU Session Resource Released List releases that session.
func TestPathSwitchOfUnknownSessionIsRefusedWithItsList(t *testing.T) {
	e := newHoTestEnv(t, false)

	dispatchMain(e.tgtRan, newPathSwitchTestRequest(e.src.AmfUeNgapId, 9), nil)

	hoRequireSent(t, e.tgtConn, "path switch not answered", "PathSwitchRequestFailure")
	requirePathSwitchFailure(t, e.tgtConn, 9, &ngapType.Cause{Choice: &ngapType.CauseRadioNetwork{
		Value: ngapType.CauseRadioNetworkPresentUnknownPDUSessionID,
	}})
}

// A PATH SWITCH REQUEST of the UE's NGAP association that names each of its PDU sessions once is still switched.
func TestPathSwitchIsAcknowledged(t *testing.T) {
	e := newHoTestEnv(t, false)

	dispatchMain(e.tgtRan, newPathSwitchTestRequest(e.src.AmfUeNgapId, 5), nil)

	hoRequireSent(t, e.tgtConn, "path switch not acknowledged", "PathSwitchRequestAcknowledge")
	e.smf.requireRequests(t, 0, "session not switched", "PATH_SWITCH_REQ")
}

// TS 23.502 4.9.1.2.2 step 7, TS 38.413 8.4.4.2: a PATH SWITCH REQUEST that names PDU session 5, the unknown PDU
// session 9 and PDU session 6, whose SMF answers without N2 SM information, is acknowledged for session 5, and the
// acknowledge lists sessions 9 and 6 as released in its PDU Session Resource Released List.
func TestPathSwitchAcknowledgeListsTheSessionsNotSwitched(t *testing.T) {
	e := newHoTestEnv(t, false)
	failingSmf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(failingSmf.Close)
	sm := amf_context.NewSmContext(6)
	sm.SetSmfUri(failingSmf.URL)
	sm.SetSmContextRef("sm-context-6")
	sm.SetSnssai(models.Snssai{Sst: 1, Sd: "010203"})
	sm.SetAccessType(hoTestAnType)
	e.amfUe.StoreSmContext(6, sm)

	dispatchMain(e.tgtRan, newPathSwitchTestRequest(e.src.AmfUeNgapId, 5, 9, 6), nil)

	hoRequireSent(t, e.tgtConn, "path switch not acknowledged", "PathSwitchRequestAcknowledge")
	m, err := ngapMessage.Parse(e.tgtConn.MsgList[0])
	require.NoError(t, err)
	ack := m.(*ngapMessage.PathSwitchRequestAcknowledge)
	require.Len(t, ack.PDUSessionResourceSwitchedList.List, 1)
	require.EqualValues(t, 5, ack.PDUSessionResourceSwitchedList.List[0].PDUSessionID.Value)
	require.NotNil(t, ack.PDUSessionResourceReleasedListPSAck, "no PDU Session Resource Released List")
	causes := map[int64]*ngapType.Cause{}
	for _, item := range ack.PDUSessionResourceReleasedListPSAck.List {
		var transfer ngapType.PathSwitchRequestUnsuccessfulTransfer
		require.NoError(t, ngapType.UnmarshalBinary(*item.PathSwitchRequestUnsuccessfulTransfer, &transfer))
		causes[item.PDUSessionID.Value] = transfer.Cause
	}
	require.Equal(t, map[int64]*ngapType.Cause{
		9: {Choice: &ngapType.CauseRadioNetwork{Value: ngapType.CauseRadioNetworkPresentUnknownPDUSessionID}},
		6: {Choice: &ngapType.CauseMisc{Value: ngapType.CauseMiscPresentUnspecified}},
	}, causes)
}
