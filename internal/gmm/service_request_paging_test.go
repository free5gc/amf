package gmm

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

var pagingTestTai = models.Tai{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, Tac: "000001"}

// newPagedTestUe returns a registered UE with a 5G NAS security context (NIA0,
// NEA0) that is being paged (T3513 running, OnGoing paging).
func newPagedTestUe(t *testing.T) *context.AmfUe {
	t.Helper()
	amfSelf := context.GetSelf()
	amfSelf.ServedGuamiList = []models.Guami{{PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"}, AmfId: "cafe00"}}
	amfSelf.SupportTaiLists = []models.Tai{pagingTestTai}
	if factory.AmfConfig == nil {
		factory.AmfConfig = &factory.Config{Configuration: &factory.Configuration{}}
	} else if factory.AmfConfig.Configuration == nil {
		factory.AmfConfig.Configuration = &factory.Configuration{}
	}

	ue := amfSelf.NewAmfUe("imsi-208930000007487")
	ue.SecurityContextAvailable = true
	ue.NgKsi = models.Amf_Comm_NgKsi{Tsc: models.Amf_Comm_ScType_NATIVE, Ksi: 1}
	ue.State[models.AccessType_3_GPP_ACCESS].Set(context.Registered)
	ue.SetOnGoing(models.AccessType_3_GPP_ACCESS, &context.OnGoing{Procedure: context.OnGoingProcedurePaging})
	ue.T3513 = context.NewTimer(time.Hour, 4, func(int32) {}, func() {})
	t.Cleanup(ue.Remove)
	return ue
}

// pagingTestConnect attaches a new N2 connection, as an INITIAL UE MESSAGE that
// names the UE's 5G-S-TMSI does for a CM-IDLE UE.
func pagingTestConnect(ue *context.AmfUe, id int64) *ngaptesting.SctpConnStub {
	conn := new(ngaptesting.SctpConnStub)
	ran := &context.AmfRan{AnType: models.AccessType_3_GPP_ACCESS, Conn: conn, Log: logger.NgapLog}
	ue.AttachRanUe(&context.RanUe{Ran: ran, RanUeNgapId: id, AmfUeNgapId: id, Log: logger.NgapLog, Tai: pagingTestTai})
	return conn
}

func pagingTestServiceRequest() *nasMessage.SvcReq {
	return &nasMessage.SvcReq{
		Ngksi:   &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 1},
		SvcType: &ie.SvcType{Value: ie.SvcType_MobileTermSvc},
	}
}

// TS 24.501 5.6.2.2.1: T3513 is stopped by a response to paging that passed the
// integrity check, and kept running otherwise. TS 24.501 4.4.4.3: a SERVICE
// REQUEST that fails the integrity check is answered with SERVICE REJECT #9.
func TestServiceRequestFailingIntegrityKeepsPaging(t *testing.T) {
	ue := newPagedTestUe(t)

	conn := pagingTestConnect(ue, 1)
	ue.MacFailed = true
	require.NoError(t, HandleServiceRequest(ue, models.AccessType_3_GPP_ACCESS, pagingTestServiceRequest()))

	require.Len(t, conn.MsgList, 2, "expected SERVICE REJECT and UE CONTEXT RELEASE COMMAND")
	decoded, err := ngapMessage.Parse(conn.MsgList[0])
	require.NoError(t, err)
	downlink, ok := decoded.(*ngapMessage.DownlinkNASTransport)
	require.True(t, ok, "first NGAP message is %T", decoded)
	nasMsg, err := nasMessage.Parse(downlink.NASPDU.Value, nil) // NIA0/NEA0: readable without keys
	reject, ok := nasMsg.(*nasMessage.SvcRej)
	require.True(t, ok, "NAS message is %T (%v)", nasMsg, err)
	require.Equal(t, ie.Cause5GMM_UEIdCannotBeDerivedByTheNw, reject.Cause5GMM.Value)
	decoded, err = ngapMessage.Parse(conn.MsgList[1])
	require.NoError(t, err)
	_, ok = decoded.(*ngapMessage.UEContextReleaseCommand)
	require.True(t, ok, "second NGAP message is %T", decoded)

	require.NotNil(t, ue.T3513, "a SERVICE REQUEST that failed the integrity check stopped T3513")
	require.Equal(t, context.OnGoingProcedurePaging, ue.OnGoing(models.AccessType_3_GPP_ACCESS).Procedure)

	// The gNB releases the rejected connection; the paged UE answers with an
	// integrity-checked SERVICE REQUEST on a new one.
	require.NoError(t, ue.RanUe[models.AccessType_3_GPP_ACCESS].Remove())
	pagingTestConnect(ue, 2)
	ue.MacFailed = false
	require.NoError(t, HandleServiceRequest(ue, models.AccessType_3_GPP_ACCESS, pagingTestServiceRequest()))

	require.Nil(t, ue.T3513, "the integrity-checked SERVICE REQUEST did not stop T3513")
	require.Equal(t, context.OnGoingProcedureNothing, ue.OnGoing(models.AccessType_3_GPP_ACCESS).Procedure)
}
