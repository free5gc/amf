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

// TS 24.501 5.5.1.2.8 i): an initial REGISTRATION REQUEST whose UE security capabilities have no 5GS
// encryption algorithm or no 5GS integrity algorithm (all bits zero) gets a REGISTRATION REJECT, before
// any authentication.
func TestRegistrationWithoutSecurityAlgorithmsIsRejected(t *testing.T) {
	tai := models.Tai{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, Tac: "000001"}
	amfSelf := context.GetSelf()
	amfSelf.ServedGuamiList = []models.Guami{{PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"}, AmfId: "cafe00"}}
	amfSelf.SupportTaiLists = []models.Tai{tai}

	testCases := []struct {
		name       string
		capability ie.UESecCapability
		rejected   bool
	}{
		{
			name:       "no encryption algorithm",
			capability: ie.UESecCapability{Length: 2, IA1_128_5G: true, IA2_128_5G: true},
			rejected:   true,
		},
		{
			name:       "no integrity algorithm",
			capability: ie.UESecCapability{Length: 2, EA05G: true, EA1_128_5G: true, EA2_128_5G: true},
			rejected:   true,
		},
		{
			name: "mandatory algorithms",
			capability: ie.UESecCapability{
				Length: 2, EA05G: true, EA1_128_5G: true, EA2_128_5G: true, IA1_128_5G: true, IA2_128_5G: true,
			},
			rejected: false,
		},
	}
	for i, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conn := new(ngaptesting.SctpConnStub)
			ran := &context.AmfRan{AnType: models.AccessType_3_GPP_ACCESS, Conn: conn, Log: logger.NgapLog}
			ue := amfSelf.NewAmfUe("")
			t.Cleanup(ue.Remove)
			ue.AttachRanUe(&context.RanUe{
				Ran: ran, RanUeNgapId: int64(i + 1), AmfUeNgapId: int64(i + 1), Log: logger.NgapLog, Tai: tai,
			})
			suci := &ie.MobileId5GS{}
			require.NoError(t, suci.UnmarshalBinary([]byte{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0, 0, 0, 0, 0, 0x47, 0x78}))
			capability := tc.capability

			err := HandleRegistrationRequest(ue, models.AccessType_3_GPP_ACCESS, 0, &nasMessage.RegReq{
				RegType5GS:      &ie.RegType5GS{FOR_Pending: true, Value: ie.RegType_InitialReg},
				Ngksi:           &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 7},
				MobileId5GS:     suci,
				UESecCapability: &capability,
			})

			if !tc.rejected {
				require.NoError(t, err)
				require.Empty(t, conn.MsgList)
				return
			}
			require.Error(t, err)
			require.Len(t, conn.MsgList, 1)
			decoded, err := ngapMessage.Parse(conn.MsgList[0])
			require.NoError(t, err)
			downlink, ok := decoded.(*ngapMessage.DownlinkNASTransport)
			require.True(t, ok, "NGAP message is %T", decoded)
			nasMsg, err := nasMessage.ParseGMM(downlink.NASPDU.Value)
			require.NoError(t, err)
			reject, ok := nasMsg.(*nasMessage.RegRej)
			require.True(t, ok, "NAS message is %T", nasMsg)
			require.Equal(t, ie.Cause5GMM_UESecCapabilitiesMismatch, reject.Cause5GMM.Value)
		})
	}
}
