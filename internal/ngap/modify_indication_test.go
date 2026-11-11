package ngap

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/pkg/app"
	"github.com/free5gc/ngap/aper"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
)

type modifyIndicationFixture struct {
	ran   *amf_context.AmfRan
	ranUe *amf_context.RanUe
	amfUe *amf_context.AmfUe
	conn  *ngaptesting.SctpConnStub
}

func newModifyIndicationUe(t *testing.T) modifyIndicationFixture {
	t.Helper()
	amfSelf := amf_context.GetSelf()
	NewAmfContext(amfSelf)
	f := modifyIndicationFixture{conn: &ngaptesting.SctpConnStub{}}
	f.ran = NewAmfRan(f.conn)
	var err error
	f.ranUe, err = f.ran.NewRanUe(1)
	require.NoError(t, err)
	f.amfUe = amfSelf.NewAmfUe("imsi-208930000000003")
	f.amfUe.AttachRanUe(f.ranUe)
	return f
}

func modifyIndicationList(pduSessionID int64) *ngapType.PDUSessionResourceModifyListModInd {
	transfer := aper.OctetString{0x00}
	return &ngapType.PDUSessionResourceModifyListModInd{List: []ngapType.PDUSessionResourceModifyItemModInd{{
		PDUSessionID: &ngapType.PDUSessionID{Value: pduSessionID},
		PDUSessionResourceModifyIndicationTransfer: &transfer,
	}}}
}

// failedToModifyCause decodes the single PDU SESSION RESOURCE MODIFY CONFIRM
// sent on conn and returns the cause reported for pduSessionID.
func failedToModifyCause(t *testing.T, conn *ngaptesting.SctpConnStub, pduSessionID int64) *ngapType.Cause {
	t.Helper()
	require.Len(t, conn.MsgList, 1)
	decoded, err := ngapMessage.Parse(conn.MsgList[0])
	require.NoError(t, err, "the PDU SESSION RESOURCE MODIFY CONFIRM must decode")
	confirm, ok := decoded.(*ngapMessage.PDUSessionResourceModifyConfirm)
	require.True(t, ok)
	require.Nil(t, confirm.PDUSessionResourceModifyListModCfm)
	require.NotNil(t, confirm.PDUSessionResourceFailedToModifyListModCfm)
	require.Len(t, confirm.PDUSessionResourceFailedToModifyListModCfm.List, 1)
	item := confirm.PDUSessionResourceFailedToModifyListModCfm.List[0]
	require.Equal(t, pduSessionID, item.PDUSessionID.Value)
	var transfer ngapType.PDUSessionResourceModifyIndicationUnsuccessfulTransfer
	require.NoError(t, ngapType.UnmarshalBinary(*item.PDUSessionResourceModifyIndicationUnsuccessfulTransfer, &transfer))
	require.NotNil(t, transfer.Cause)
	return transfer.Cause
}

func TestModifyIndicationUnknownPDUSessionReportedAsFailed(t *testing.T) {
	f := newModifyIndicationUe(t)

	handlePDUSessionResourceModifyIndicationMain(f.ran, f.ranUe, modifyIndicationList(5))

	cause := failedToModifyCause(t, f.conn, 5)
	radioNetwork, ok := cause.Choice.(*ngapType.CauseRadioNetwork)
	require.True(t, ok, "cause is %T", cause.Choice)
	require.Equal(t, ngapType.CauseRadioNetworkPresentUnknownPDUSessionID, radioNetwork.Value)
}

func TestModifyIndicationSmfFailureReportedAsFailed(t *testing.T) {
	f := newModifyIndicationUe(t)

	// The SMF answers the SmContext update with HTTP 500 and no N2 SM information.
	smf := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write([]byte(`{"status":500,"cause":"SYSTEM_FAILURE"}`)); err != nil {
			t.Errorf("SMF stub write: %v", err)
		}
	}))
	smf.Config.Protocols = new(http.Protocols)
	smf.Config.Protocols.SetUnencryptedHTTP2(true) // the SBI client uses h2c
	smf.Start()
	defer smf.Close()

	// The SmContext update does not call back into the AMF app.
	_, err := consumer.NewConsumer(struct{ app.App }{})
	require.NoError(t, err)
	smContext := amf_context.NewSmContext(5)
	smContext.SetSmfUri(smf.URL)
	smContext.SetSmContextRef("sm-context-5")
	f.amfUe.StoreSmContext(5, smContext)

	handlePDUSessionResourceModifyIndicationMain(f.ran, f.ranUe, modifyIndicationList(5))

	cause := failedToModifyCause(t, f.conn, 5)
	misc, ok := cause.Choice.(*ngapType.CauseMisc)
	require.True(t, ok, "cause is %T", cause.Choice)
	require.Equal(t, ngapType.CauseMiscPresentUnspecified, misc.Value)
}
