package processor

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/nas/ie"
	nas_message "github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

const testSmContextStatusSupi = "imsi-208930000001156"

type keptRequest struct {
	ulNasTransport *nas_message.ULNASTransport
	anType         models.AccessType
	pduSessionID   int32
	smMessage      []uint8
}

// stubCreatePDUSession records the requests that the procedure forwards, in place of an SMF.
func stubCreatePDUSession(t *testing.T) chan keptRequest {
	t.Helper()
	created := make(chan keptRequest, 1)
	saved := createPDUSession
	createPDUSession = func(ulNasTransport *nas_message.ULNASTransport, _ *context.AmfUe, anType models.AccessType,
		pduSessionID int32, smMessage []uint8,
	) (bool, error) {
		created <- keptRequest{ulNasTransport, anType, pduSessionID, smMessage}
		return true, nil
	}
	t.Cleanup(func() { createPDUSession = saved })
	return created
}

func newSmContextStatusTestUe(t *testing.T, duplicated bool) (*context.AmfUe, *nas_message.ULNASTransport) {
	t.Helper()
	amfSelf := context.GetSelf()
	amfSelf.ServedGuamiList = []models.Guami{{
		PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"},
		AmfId:  "cafe00",
	}}
	ue := amfSelf.NewAmfUe(testSmContextStatusSupi)
	t.Cleanup(func() { amfSelf.UePool.Delete(testSmContextStatusSupi) })

	smContext := context.NewSmContext(5)
	smContext.SetAccessType(models.AccessType_3_GPP_ACCESS)
	ue.StoreSmContext(5, smContext)
	// The second initial request for session 5, PTI 2, which transport5GSMMessage keeps. It came
	// on the other access.
	request := &nas_message.ULNASTransport{
		PayloadCntrType: &ie.PayloadCntrType{Value: ie.PayloadCntrType_N1SMInfo},
		PayloadCntr: &ie.PayloadCntr{
			Pct:      ie.PayloadCntrType_N1SMInfo,
			Contents: []byte{0x2e, 0x05, 0x02, 0xc1, 0xff, 0xff, 0x91},
		},
		PDUSessID: &ie.PDUSessId2{Value: 5},
		ReqType:   &ie.ReqType{Value: ie.ReqType_InitialReq},
	}
	if duplicated {
		smContext.StoreULNASTransport(request, models.AccessType_NON_3_GPP_ACCESS)
		smContext.SetDuplicatedPduSessionID(true)
	}
	return ue, request
}

func releasedNotification() models.Smf_PDUSess_SmContextStatusNotification {
	return models.Smf_PDUSess_SmContextStatusNotification{
		StatusInfo: &models.Smf_PDUSess_StatusInfo{ResourceStatus: models.Smf_PDUSess_ResourceStatus_RELEASED},
	}
}

// TS 29.502 5.2.2.3.11: an initial request for a PDU session ID in use releases the old session,
// then proceeds, on the access it came on, upon the notification that the SM context is deleted.
func TestSmContextStatusNotifyForwardsKeptInitialRequest(t *testing.T) {
	created := stubCreatePDUSession(t)
	ue, request := newSmContextStatusTestUe(t, true)

	p := &Processor{}
	require.Nil(t, p.SmContextStatusNotifyProcedure(testSmContextStatusSupi, 5, releasedNotification()))

	select {
	case got := <-created:
		require.Same(t, request, got.ulNasTransport)
		require.Equal(t, models.AccessType_NON_3_GPP_ACCESS, got.anType)
		require.Equal(t, int32(5), got.pduSessionID)
		require.Equal(t, request.PayloadCntr.Contents, got.smMessage)
	case <-time.After(time.Second):
		t.Fatal("the kept initial request was not forwarded")
	}
	_, ok := ue.SmContextFindByPDUSessionID(5)
	require.False(t, ok, "the released SM context is still stored")
}

func TestSmContextStatusNotifyReleaseCreatesNothing(t *testing.T) {
	created := stubCreatePDUSession(t)
	ue, _ := newSmContextStatusTestUe(t, false)

	p := &Processor{}
	require.Nil(t, p.SmContextStatusNotifyProcedure(testSmContextStatusSupi, 5, releasedNotification()))

	select {
	case <-created:
		t.Fatal("a release that ends a session created another")
	case <-time.After(100 * time.Millisecond):
	}
	_, ok := ue.SmContextFindByPDUSessionID(5)
	require.False(t, ok)
}
