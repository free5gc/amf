package gmm

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

// TS 24.501 7.3.2 c): a UL NAS TRANSPORT with the unassigned PDU session ID 0 or a reserved one is answered with a
// DL NAS TRANSPORT with 5GMM cause #90, which carries the 5GSM message back with its PDU session ID (5.4.5.3.2,
// 8.2.11.2).
func TestUnassignedOrReservedPduSessionIDIsSentBack(t *testing.T) {
	const anType = models.AccessType_3_GPP_ACCESS
	for _, pduSessionID := range []uint8{0, 16, 255} {
		t.Run(fmt.Sprintf("PDU session ID %d", pduSessionID), func(t *testing.T) {
			ue := newGutiTestUe(t, false)
			conn := ue.GetRanUe(anType).Ran.Conn.(*ngaptesting.SctpConnStub)
			// PDU SESSION ESTABLISHMENT REQUEST for that PDU session ID, PTI 1
			smMessage := []byte{0x2e, pduSessionID, 0x01, 0xc1, 0xff, 0xff}

			require.NoError(t, HandleULNASTransport(ue, anType, &nasMessage.ULNASTransport{
				PayloadCntrType: &ie.PayloadCntrType{Value: ie.PayloadCntrType_N1SMInfo},
				PayloadCntr:     &ie.PayloadCntr{Pct: ie.PayloadCntrType_N1SMInfo, Contents: smMessage},
				PDUSessID:       &ie.PDUSessId2{Value: pduSessionID},
				ReqType:         &ie.ReqType{Value: ie.ReqType_InitialReq},
			}))

			sent := pagingTestNas(t, conn.MsgList)
			require.Len(t, sent, 1)
			dlNasTransport, ok := sent[0].(*nasMessage.DLNASTransport)
			require.True(t, ok, "NAS message is %T", sent[0])
			require.NotNil(t, dlNasTransport.Cause5GMM)
			require.Equal(t, ie.Cause5GMM_PayloadWasNotForwarded, dlNasTransport.Cause5GMM.Value)
			require.NotNil(t, dlNasTransport.PDUSessID)
			require.Equal(t, pduSessionID, dlNasTransport.PDUSessID.Value)
			require.Equal(t, smMessage, dlNasTransport.PayloadCntr.Contents)
		})
	}
}
