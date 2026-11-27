package processor

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/mediatype/multipart"
	"github.com/free5gc/openapi/models"
)

// Paging must carry the PPI of the current N1N2 request, not the previously
// captured OnGoing value, for both Case A and Case C.
func TestN1N2MessageTransferPagingPriority(t *testing.T) {
	for _, access := range []struct {
		name   string
		anType models.AccessType
	}{
		{"3GPP", models.AccessType_3_GPP_ACCESS},
		{"non-3GPP", models.AccessType_NON_3_GPP_ACCESS},
	} {
		for _, tc := range []struct {
			name   string
			oldPpi int32
			newPpi int32
		}{
			{"first paging", 0, 3},
			{"higher priority replaces paging", 5, 2},
			{"no priority specified", 0, 0},
		} {
			t.Run(access.name+"/"+tc.name, func(t *testing.T) {
				amfSelf := context.GetSelf()
				prevGuami := amfSelf.ServedGuamiList
				prevT3513 := amfSelf.T3513Cfg
				amfSelf.ServedGuamiList = []models.Guami{{
					PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"},
					AmfId:  "cafe00",
				}}
				// Retransmissions are not under test.
				amfSelf.T3513Cfg.Enable = false
				t.Cleanup(func() {
					amfSelf.ServedGuamiList = prevGuami
					amfSelf.T3513Cfg = prevT3513
				})

				tai := models.Tai{
					PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"},
					Tac:    "000001",
				}
				snssai := models.Snssai{Sst: 1, Sd: "010203"}
				conn := new(ngaptesting.SctpConnStub)
				ran := &context.AmfRan{
					AnType: models.AccessType_3_GPP_ACCESS,
					Conn:   conn,
					Log:    logger.NgapLog,
					SupportedTAList: []context.SupportedTAI{{
						Tai:        tai,
						SNssaiList: []models.Snssai{snssai},
					}},
				}
				amfSelf.AmfRanPool.Store(conn, ran)
				t.Cleanup(func() { amfSelf.AmfRanPool.Delete(conn) })

				// The UE is registered but has no attached RanUe (CM-IDLE).
				ue := amfSelf.NewAmfUe("imsi-208930000007489")
				t.Cleanup(ue.Remove)
				ue.State[models.AccessType_3_GPP_ACCESS].Set(context.Registered)
				ue.State[access.anType].Set(context.Registered)
				ue.RegistrationArea[models.AccessType_3_GPP_ACCESS] = []models.Tai{tai}
				ue.RegistrationArea[access.anType] = []models.Tai{tai}

				const pduSessionID = 1
				smContext := context.NewSmContext(pduSessionID)
				smContext.SetAccessType(access.anType)
				smContext.SetSnssai(snssai)
				ue.StoreSmContext(pduSessionID, smContext)

				p := &Processor{}
				sendRequest := func(ppi int32) {
					t.Helper()
					request := models.N1N2MessageTransferRequestBody{
						JsonData: &models.Amf_Comm_N1N2MessageTransferReqData{
							PduSessionId: pduSessionID,
							Ppi:          ppi,
							N2InfoContainer: &models.Amf_Comm_N2InfoContainer{
								N2InformationClass: models.Amf_Comm_N2InformationClass_SM,
								SmInfo: &models.Amf_Comm_N2SmInformation{
									PduSessionId: pduSessionID,
									SNssai:       &snssai,
									N2InfoContent: &models.Amf_Comm_N2InfoContent{
										NgapIeType: models.Amf_Comm_NgapIeType_PDU_RES_SETUP_REQ,
									},
								},
							},
						},
						BinaryDataN2Information: &multipart.RelatedContent{Content: []byte{0x00}},
					}
					rsp, _, problemDetails, transferErr := p.N1N2MessageTransferProcedure(ue.Supi, "", request)
					require.Nil(t, problemDetails)
					require.Nil(t, transferErr)
					require.NotNil(t, rsp)
					require.Equal(t, models.Amf_Comm_N1N2MessageTransferCause_ATTEMPTING_TO_REACH_UE, rsp.Cause)
				}

				if tc.oldPpi != 0 {
					// Establish an ongoing paging procedure with the previous PPI.
					sendRequest(tc.oldPpi)
					require.Len(t, conn.MsgList, 1)
					conn.MsgList = nil
				}

				sendRequest(tc.newPpi)
				require.Len(t, conn.MsgList, 1)
				decoded, err := ngapMessage.Parse(conn.MsgList[0])
				require.NoError(t, err)
				paging, ok := decoded.(*ngapMessage.Paging)
				require.True(t, ok, "NGAP message is %T, not Paging", decoded)

				if tc.newPpi == 0 {
					require.Nil(t, paging.PagingPriority)
				} else {
					require.NotNil(t, paging.PagingPriority, "Paging Priority IE is missing for PPI %d", tc.newPpi)
					require.Equal(t, tc.newPpi, int32(paging.PagingPriority.Value), "Paging uses a stale PPI")
				}
			})
		}
	}
}
