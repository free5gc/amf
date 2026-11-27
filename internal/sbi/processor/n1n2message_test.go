package processor

import (
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/openapi/mediatype/multipart"
	"github.com/free5gc/openapi/models"
)

const testN1N2Supi = "imsi-208930000001155"

// newN1N2TestUe builds a CM-Connected AmfUe holding PDU Session 1 whose 3GPP RanUe has already completed
// the initial context setup, so that a PDU_RES_SETUP_REQ takes the PDU Session Resource Setup Request path.
func newN1N2TestUe(t *testing.T) (*context.AmfUe, *context.RanUe) {
	t.Helper()

	amfSelf := context.GetSelf()
	amfSelf.ServedGuamiList = []models.Guami{{
		PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"},
		AmfId:  "cafe00",
	}}

	ran := &context.AmfRan{
		AnType: models.AccessType_3_GPP_ACCESS,
		Log:    logger.NgapLog,
	}
	ranUe := &context.RanUe{
		Ran:                 ran,
		RanUeNgapId:         1,
		AmfUeNgapId:         1,
		InitialContextSetup: true,
		Log:                 logger.NgapLog,
	}

	ue := amfSelf.NewAmfUe(testN1N2Supi)
	t.Cleanup(func() { amfSelf.UePool.Delete(testN1N2Supi) })
	ue.AccessAndMobilitySubscriptionData = &models.Udm_SDM_AccessAndMobilitySubscriptionData{
		SubscribedUeAmbr: &models.AmbrRm{Uplink: "1 Gbps", Downlink: "1 Gbps"},
	}
	smContext := context.NewSmContext(1)
	smContext.SetAccessType(models.AccessType_3_GPP_ACCESS)
	ue.StoreSmContext(1, smContext)
	ue.RanUe[models.AccessType_3_GPP_ACCESS] = ranUe

	return ue, ranUe
}

func newPduResSetupReq() models.N1N2MessageTransferRequestBody {
	return models.N1N2MessageTransferRequestBody{
		JsonData: &models.Amf_Comm_N1N2MessageTransferReqData{
			PduSessionId: 1,
			N2InfoContainer: &models.Amf_Comm_N2InfoContainer{
				N2InformationClass: models.Amf_Comm_N2InformationClass_SM,
				SmInfo: &models.Amf_Comm_N2SmInformation{
					PduSessionId: 1,
					SNssai:       &models.Snssai{Sst: 1, Sd: "010203"},
					N2InfoContent: &models.Amf_Comm_N2InfoContent{
						NgapIeType: models.Amf_Comm_NgapIeType_PDU_RES_SETUP_REQ,
					},
				},
			},
		},
		BinaryDataN2Information: &multipart.RelatedContent{Content: []byte{0x00}},
	}
}

// A RanUe detached from the AmfUe (e.g. by ClearHoldingRanUe) may still be referenced by AmfUe.RanUe until
// it is released. N1N2MessageTransfer must reject the request instead of building NGAP message with it.
func TestN1N2MessageTransferProcedureRejectsDetachedRanUe(t *testing.T) {
	ue, ranUe := newN1N2TestUe(t)
	ranUe.DetachAmfUe()

	p := &Processor{}
	rsp, _, problemDetails, transferErr := p.N1N2MessageTransferProcedure(ue.Supi, "", newPduResSetupReq())

	require.Nil(t, rsp)
	require.Nil(t, problemDetails)
	require.NotNil(t, transferErr)
	require.Equal(t, int32(http.StatusConflict), transferErr.Error.Status)
	require.Equal(t, "TEMPORARY_REJECT_REGISTRATION_ONGOING", transferErr.Error.Cause)
}

func TestN1N2MessageTransferProcedureAttachedRanUe(t *testing.T) {
	ue, ranUe := newN1N2TestUe(t)
	ranUe.SetAmfUe(ue)

	p := &Processor{}
	rsp, _, problemDetails, transferErr := p.N1N2MessageTransferProcedure(ue.Supi, "", newPduResSetupReq())

	require.Nil(t, problemDetails)
	require.Nil(t, transferErr)
	require.NotNil(t, rsp)
	require.Equal(t, models.Amf_Comm_N1N2MessageTransferCause_N1_N2_TRANSFER_INITIATED, rsp.Cause)
}

func TestN1N2MessageTransferAfterPagingTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const anType = models.AccessType_3_GPP_ACCESS

		amfSelf := context.GetSelf()

		prevT3513 := amfSelf.T3513Cfg
		prevGuami := amfSelf.ServedGuamiList

		defer func() {
			amfSelf.T3513Cfg = prevT3513
			amfSelf.ServedGuamiList = prevGuami
		}()

		amfSelf.T3513Cfg = factory.TimerValue{
			Enable:        true,
			ExpireTime:    time.Second,
			MaxRetryTimes: 1,
		}

		amfSelf.ServedGuamiList = []models.Guami{{
			PlmnId: &models.PlmnIdNid{
				Mcc: "208",
				Mnc: "93",
			},
			AmfId: "cafe00",
		}}

		// Create a registered UE in CM-IDLE.
		ue := amfSelf.NewAmfUe("imsi-208930000007488")
		defer amfSelf.UePool.Delete(ue.Supi)
		defer ue.StopT3513()

		ue.State[anType].Set(context.Registered)

		ue.RegistrationArea[anType] = []models.Tai{{
			PlmnId: &models.PlmnId{
				Mcc: "208",
				Mnc: "93",
			},
			Tac: "000001",
		}}

		request := models.N1N2MessageTransferRequestBody{
			JsonData: &models.Amf_Comm_N1N2MessageTransferReqData{
				N1MessageContainer: &models.Amf_Comm_N1MessageContainer{
					N1MessageClass: models.Amf_Comm_N1MessageClass_SMS,
					N1MessageContent: &models.RefToBinaryData{
						ContentId: "n1",
					},
				},
			},
			BinaryDataN1Message: &multipart.RelatedContent{
				Content: []byte{0x01},
			},
		}

		p := &Processor{}

		// First request starts paging.
		rsp, _, problemDetails, transferErr := p.N1N2MessageTransferProcedure(ue.Supi, "", request)

		require.Nil(t, problemDetails)
		require.Nil(t, transferErr)
		require.NotNil(t, rsp)
		require.Equal(t,
			models.Amf_Comm_N1N2MessageTransferCause_ATTEMPTING_TO_REACH_UE,
			rsp.Cause,
		)

		synctest.Wait()

		require.NotNil(t, ue.T3513)
		require.Equal(t,
			context.OnGoingProcedurePaging,
			ue.OnGoing(anType).Procedure,
		)

		// Wait until T3513 exhausts all retries.
		time.Sleep(3 * time.Second)
		synctest.Wait()

		require.Nil(t, ue.T3513)

		// A new request should be accepted after paging has ended.
		rsp, _, problemDetails, transferErr = p.N1N2MessageTransferProcedure(ue.Supi, "", request)

		require.Nil(t, problemDetails)

		if transferErr != nil {
			t.Fatalf("second N1N2 request rejected: status=%d cause=%s",
				transferErr.Error.Status,
				transferErr.Error.Cause,
			)
		}

		require.NotNil(t, rsp)
		require.Equal(t,
			models.Amf_Comm_N1N2MessageTransferCause_ATTEMPTING_TO_REACH_UE,
			rsp.Cause,
		)
	})
}
