package gmm

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// newDuplicatedPduSessionIDTest returns a UE with PDU session 5 on 3GPP access, whose SMF answers
// the update of its SM context with status, and the initial request for session 5 that the UE
// sends again. The UE's NSSF is unreachable, so the selection of an SMF for a new session fails.
func newDuplicatedPduSessionIDTest(t *testing.T, status int) (
	*context.AmfUe, *ngaptesting.SctpConnStub, *nasMessage.ULNASTransport, chan []byte,
) {
	t.Helper()
	ue, conn := newNssaiTestUe(t)
	ue.SecurityContextAvailable = true // NEA0, NIA0

	updates := make(chan []byte, 1)
	smf := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		updates <- body
		w.WriteHeader(status)
	}))
	smf.Config.Protocols = new(http.Protocols)
	smf.Config.Protocols.SetUnencryptedHTTP2(true) // the SBI client speaks HTTP/2 with prior knowledge
	smf.Start()
	t.Cleanup(smf.Close)

	smContext := context.NewSmContext(5)
	smContext.SetAccessType(models.AccessType_3_GPP_ACCESS)
	smContext.SetSmfUri(smf.URL)
	smContext.SetSmContextRef("1")
	ue.StoreSmContext(5, smContext)

	request := &nasMessage.ULNASTransport{
		PayloadCntrType: &ie.PayloadCntrType{Value: ie.PayloadCntrType_N1SMInfo},
		PayloadCntr: &ie.PayloadCntr{
			Pct:      ie.PayloadCntrType_N1SMInfo,
			Contents: []byte{0x2e, 0x05, 0x02, 0xc1, 0xff, 0xff, 0x91}, // PDU SESSION ESTABLISHMENT REQUEST, PTI 2
		},
		PDUSessID: &ie.PDUSessId2{Value: 5},
		ReqType:   &ie.ReqType{Value: ie.ReqType_InitialReq},
		SNSSAI:    &ie.SNSSAI{SST: uint8(nssaiTestServed.Sst), SD: nssaiTestServed.Sd},
		DNN:       &ie.DNN{Value: "internet"},
	}
	return ue, conn, request, updates
}

// TS 24.501 5.4.5.2.5 a) 12): when the SMF cannot release the PDU session, the AMF still releases
// it locally and proceeds as specified in 5.4.5.2.3. Here the SMF selection then fails, so the UE
// gets its 5GSM message back with cause #90 (5.4.5.2.5 a) 1)).
func TestDuplicatedPduSessionIDProceedsWhenTheSmfUpdateFails(t *testing.T) {
	ue, conn, request, _ := newDuplicatedPduSessionIDTest(t, http.StatusInternalServerError)

	require.NoError(t, transport5GSMMessage(ue, models.AccessType_3_GPP_ACCESS, request))

	_, ok := ue.SmContextFindByPDUSessionID(5)
	require.False(t, ok, "the PDU session was not released locally")
	require.Len(t, conn.MsgList, 1, "the UE got no answer to its initial request")
	decoded, err := ngapMessage.Parse(conn.MsgList[0])
	require.NoError(t, err)
	downlink, ok := decoded.(*ngapMessage.DownlinkNASTransport)
	require.True(t, ok, "NGAP message is %T", decoded)
	// NEA0: the DL NAS TRANSPORT follows the 7 octets of the security header.
	nasMsg, err := nasMessage.ParseGMM(downlink.NASPDU.Value[7:])
	require.NoError(t, err)
	transport, ok := nasMsg.(*nasMessage.DLNASTransport)
	require.True(t, ok, "NAS message is %T", nasMsg)
	require.Equal(t, request.PayloadCntr.Contents, transport.PayloadCntr.Contents)
	require.Equal(t, uint8(5), transport.PDUSessID.Value)
	require.Equal(t, ie.Cause5GMM_PayloadWasNotForwarded, transport.Cause5GMM.Value)
}

// TS 29.502 5.2.2.3.11: once the SMF has accepted the release, the AMF proceeds with the initial
// request upon the SM context status notification that the SM context is deleted. Until then it
// keeps the PDU session and the request, with the access it came on.
func TestDuplicatedPduSessionIDWaitsForTheReleaseNotification(t *testing.T) {
	ue, conn, request, updates := newDuplicatedPduSessionIDTest(t, http.StatusNoContent)

	require.NoError(t, transport5GSMMessage(ue, models.AccessType_3_GPP_ACCESS, request))

	require.Len(t, updates, 1, "the SMF got no update of the SM context")
	require.Contains(t, string(<-updates), "/smContextStatus/"+ue.Supi+"/5\"",
		"the notification URI does not name the UE as the callback route does")
	smContext, ok := ue.SmContextFindByPDUSessionID(5)
	require.True(t, ok, "the PDU session was released before the SMF notified it")
	require.True(t, smContext.PduSessionIDDuplicated())
	kept, anType := smContext.ULNASTransport()
	require.Same(t, request, kept)
	require.Equal(t, models.AccessType_3_GPP_ACCESS, anType)
	require.Empty(t, conn.MsgList)
}
