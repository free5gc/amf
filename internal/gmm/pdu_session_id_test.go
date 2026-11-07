package gmm

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// TS 24.501 7.3.2 c): a UL NAS TRANSPORT with the unassigned PDU session ID 0 or a reserved one is answered with a
// DL NAS TRANSPORT with 5GMM cause #90, which carries the 5GSM message back with its PDU session ID (5.4.5.3.2,
// 8.2.11.2).
func TestUnassignedOrReservedPduSessionIDIsSentBack(t *testing.T) {
	const anType = models.AccessType_3_GPP_ACCESS
	amfSelf := context.GetSelf()
	savedGuamis := amfSelf.ServedGuamiList
	amfSelf.ServedGuamiList = []models.Guami{{PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"}, AmfId: "cafe00"}}
	t.Cleanup(func() { amfSelf.ServedGuamiList = savedGuamis })
	for _, pduSessionID := range []uint8{0, 16, 255} {
		ue := amfSelf.NewAmfUe("")
		ue.SecurityContextAvailable = true
		ue.NgKsi = models.Amf_Comm_NgKsi{Tsc: models.Amf_Comm_ScType_NATIVE, Ksi: 1}
		conn := new(ngaptesting.SctpConnStub)
		ran := &context.AmfRan{AnType: anType, Conn: conn, Log: logger.NgapLog}
		ue.AttachRanUe(&context.RanUe{Ran: ran, RanUeNgapId: 1, AmfUeNgapId: 1, Log: logger.NgapLog})
		// PDU SESSION ESTABLISHMENT REQUEST for that PDU session ID, PTI 1
		smMessage := []byte{0x2e, pduSessionID, 0x01, 0xc1, 0xff, 0xff}

		require.NoError(t, HandleULNASTransport(ue, anType, &nasMessage.ULNASTransport{
			PayloadCntrType: &ie.PayloadCntrType{Value: ie.PayloadCntrType_N1SMInfo},
			PayloadCntr:     &ie.PayloadCntr{Pct: ie.PayloadCntrType_N1SMInfo, Contents: smMessage},
			PDUSessID:       &ie.PDUSessId2{Value: pduSessionID},
			ReqType:         &ie.ReqType{Value: ie.ReqType_InitialReq},
		}))

		require.Len(t, conn.MsgList, 1, "PDU session ID %d", pduSessionID)
		decoded, err := ngapMessage.Parse(conn.MsgList[0])
		require.NoError(t, err)
		transport, ok := decoded.(*ngapMessage.DownlinkNASTransport)
		require.True(t, ok)
		// The test's security context has the null algorithms: after the security header, the plain message.
		msg, err := nasMessage.ParseGMM(transport.NASPDU.Value[7:])
		require.NoError(t, err)
		dlNasTransport, ok := msg.(*nasMessage.DLNASTransport)
		require.True(t, ok)
		require.NotNil(t, dlNasTransport.Cause5GMM)
		require.Equal(t, ie.Cause5GMM_PayloadWasNotForwarded, dlNasTransport.Cause5GMM.Value)
		require.NotNil(t, dlNasTransport.PDUSessID, "PDU session ID %d", pduSessionID)
		require.Equal(t, pduSessionID, dlNasTransport.PDUSessID.Value)
		require.Equal(t, smMessage, dlNasTransport.PayloadCntr.Contents)
		ue.Remove()
	}
}
