package processor

import (
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/amf/pkg/factory"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/mediatype/multipart"
	"github.com/free5gc/openapi/models"
)

// A failed PAGING build must not leave a pending transfer or block the next request.
func TestN1N2MessageTransferPagingBuildFailure(t *testing.T) {
	const anType3GPP = models.AccessType_3_GPP_ACCESS
	for _, tc := range []struct {
		name    string
		anType  models.AccessType
		preempt bool
	}{
		{"3GPP", anType3GPP, false},
		{"non-3GPP", models.AccessType_NON_3_GPP_ACCESS, false},
		{"3GPP preemption", anType3GPP, true},
		{"non-3GPP preemption", models.AccessType_NON_3_GPP_ACCESS, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				amfSelf := context.GetSelf()
				prevGuami := amfSelf.ServedGuamiList
				prevT3513 := amfSelf.T3513Cfg
				defer func() {
					amfSelf.ServedGuamiList = prevGuami
					amfSelf.T3513Cfg = prevT3513
				}()
				amfSelf.ServedGuamiList = []models.Guami{{
					PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"},
					AmfId:  "cafe00",
				}}
				amfSelf.T3513Cfg = factory.TimerValue{
					Enable:        true,
					ExpireTime:    time.Hour,
					MaxRetryTimes: 1,
				}

				tai := models.Tai{
					PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"},
					Tac:    "000001",
				}
				snssai := models.Snssai{Sst: 1, Sd: "010203"}
				conn := new(ngaptesting.SctpConnStub)
				ran := &context.AmfRan{
					AnType: anType3GPP,
					Conn:   conn,
					Log:    logger.NgapLog,
					SupportedTAList: []context.SupportedTAI{{
						Tai:        tai,
						SNssaiList: []models.Snssai{snssai},
					}},
				}
				amfSelf.AmfRanPool.Store(conn, ran)
				defer amfSelf.AmfRanPool.Delete(conn)

				// Registered UE without an attached RanUe (CM-IDLE).
				ue := amfSelf.NewAmfUe("imsi-208930000007490")
				defer ue.Remove()
				ue.State[anType3GPP].Set(context.Registered)
				ue.State[tc.anType].Set(context.Registered)
				ue.RegistrationArea[anType3GPP] = []models.Tai{tai}
				ue.RegistrationArea[tc.anType] = []models.Tai{tai}

				// SMS uses 3GPP access without requiring a PDU session or slice check.
				request := models.N1N2MessageTransferRequestBody{
					JsonData: &models.Amf_Comm_N1N2MessageTransferReqData{
						N1MessageContainer: &models.Amf_Comm_N1MessageContainer{
							N1MessageClass: models.Amf_Comm_N1MessageClass_SMS,
							N1MessageContent: &models.RefToBinaryData{
								ContentId: "n1",
							},
						},
					},
					BinaryDataN1Message: &multipart.RelatedContent{Content: []byte{0x01}},
				}
				if tc.anType == models.AccessType_NON_3_GPP_ACCESS {
					// Select Case C through an SM context on non-3GPP access.
					// Keep its registration area valid so the slice check passes.
					const pduSessionID = 1
					smContext := context.NewSmContext(pduSessionID)
					smContext.SetAccessType(tc.anType)
					smContext.SetSnssai(snssai)
					ue.StoreSmContext(pduSessionID, smContext)
					request = models.N1N2MessageTransferRequestBody{
						JsonData: &models.Amf_Comm_N1N2MessageTransferReqData{
							PduSessionId: pduSessionID,
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
				}

				p := &Processor{}
				if tc.preempt {
					// Start an older, lower-priority paging procedure.
					request.JsonData.Ppi = 5
					rsp, _, pd, transferErr := p.N1N2MessageTransferProcedure(ue.Supi, "", request)
					require.Nil(t, pd)
					require.Nil(t, transferErr)
					require.NotNil(t, rsp)
					require.Equal(t, models.Amf_Comm_N1N2MessageTransferCause_ATTEMPTING_TO_REACH_UE, rsp.Cause)
					synctest.Wait()
					require.NotNil(t, ue.T3513)
					require.Equal(t, context.OnGoingProcedurePaging, ue.OnGoing(tc.anType).Procedure)
					require.Len(t, conn.MsgList, 1)
					conn.MsgList = nil
				}

				// BuildPaging always needs the 3GPP registration area, even in Case C.
				ue.RegistrationArea[anType3GPP] = nil
				request.JsonData.Ppi = 2
				rsp, location, pd, transferErr := p.N1N2MessageTransferProcedure(ue.Supi, "", request)
				synctest.Wait()

				// Use non-fatal checks so the subsequent request is exercised even before the fix.
				assert.Nil(t, rsp, "failed paging must not be accepted")
				assert.Empty(t, location)
				assert.Nil(t, transferErr)
				if assert.NotNil(t, pd, "expected a system failure response") {
					assert.Equal(t, int32(http.StatusInternalServerError), pd.Status)
					assert.Equal(t, "SYSTEM_FAILURE", pd.Cause)
				}
				assert.Nil(t, ue.N1N2Message, "failed transfer must not remain pending")
				onGoing := ue.OnGoing(tc.anType)
				assert.Equal(t, context.OnGoingProcedureNothing, onGoing.Procedure)
				assert.Zero(t, onGoing.Ppi)
				assert.Nil(t, ue.T3513, "failed build must not start a paging timer")
				assert.Empty(t, conn.MsgList)

				// Restore valid context and verify an ordinary request can page again.
				ue.RegistrationArea[anType3GPP] = []models.Tai{tai}
				request.JsonData.Ppi = 0
				rsp, location, pd, transferErr = p.N1N2MessageTransferProcedure(ue.Supi, "", request)
				if transferErr != nil && transferErr.Error != nil {
					t.Fatalf("next request rejected: status=%d cause=%s", transferErr.Error.Status, transferErr.Error.Cause)
				}
				require.Nil(t, transferErr)
				require.Nil(t, pd)
				require.NotNil(t, rsp)
				require.NotEmpty(t, location)
				require.Equal(t, models.Amf_Comm_N1N2MessageTransferCause_ATTEMPTING_TO_REACH_UE, rsp.Cause)
				synctest.Wait()
				require.NotNil(t, ue.T3513)
				require.Len(t, conn.MsgList, 1)
				decoded, err := ngapMessage.Parse(conn.MsgList[0])
				require.NoError(t, err)
				require.IsType(t, &ngapMessage.Paging{}, decoded)
			})
		})
	}
}
