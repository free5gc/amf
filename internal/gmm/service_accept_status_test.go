package gmm

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// newServiceStatusTestUe returns a registered UE with PDU session 5 of 3GPP access and PDU session 6 of non-3GPP
// access, and the paths of the release requests that their SMF receives.
func newServiceStatusTestUe(t *testing.T) (*context.AmfUe, *ngaptesting.SctpConnStub, chan string) {
	t.Helper()
	tai := models.Tai{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, Tac: "000001"}
	amfSelf := context.GetSelf()
	savedGuamis, savedTais := amfSelf.ServedGuamiList, amfSelf.SupportTaiLists
	amfSelf.ServedGuamiList = []models.Guami{{PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"}, AmfId: "cafe00"}}
	amfSelf.SupportTaiLists = []models.Tai{tai}
	t.Cleanup(func() { amfSelf.ServedGuamiList, amfSelf.SupportTaiLists = savedGuamis, savedTais })
	if factory.AmfConfig == nil {
		factory.AmfConfig = &factory.Config{Configuration: &factory.Configuration{}}
	} else if factory.AmfConfig.Configuration == nil {
		factory.AmfConfig.Configuration = &factory.Configuration{}
	}
	_, err := consumer.NewConsumer(nssaiTestApp{})
	require.NoError(t, err)

	released := make(chan string, 2)
	smf := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		released <- r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	smf.Config.Protocols = new(http.Protocols)
	smf.Config.Protocols.SetUnencryptedHTTP2(true) // the SBI client speaks HTTP/2 with prior knowledge
	smf.Start()
	t.Cleanup(smf.Close)

	ue := amfSelf.NewAmfUe("imsi-208930000000732")
	t.Cleanup(ue.Remove)
	ue.SecurityContextAvailable = true // with the null algorithms, the container is in clear
	ue.NgKsi = models.Amf_Comm_NgKsi{Tsc: models.Amf_Comm_ScType_NATIVE, Ksi: 1}
	ue.State[models.AccessType_3_GPP_ACCESS].Set(context.Registered)
	conn := new(ngaptesting.SctpConnStub)
	ran := &context.AmfRan{AnType: models.AccessType_3_GPP_ACCESS, Conn: conn, Log: logger.NgapLog}
	ue.AttachRanUe(&context.RanUe{Ran: ran, RanUeNgapId: 1, AmfUeNgapId: 1, Tai: tai, Log: logger.NgapLog})
	for pduSessionID, accessType := range map[int32]models.AccessType{
		5: models.AccessType_3_GPP_ACCESS,
		6: models.AccessType_NON_3_GPP_ACCESS,
	} {
		smContext := context.NewSmContext(pduSessionID)
		smContext.SetAccessType(accessType)
		smContext.SetSmfUri(smf.URL)
		smContext.SetSmContextRef(string(accessType))
		ue.StoreSmContext(pduSessionID, smContext)
	}
	return ue, conn, released
}

// serviceStatusTestRequest returns a SERVICE REQUEST whose PDU session status, not a cleartext IE, is in its NAS
// message container (TS 24.501 4.4.6) and says that no PDU session is active.
func serviceStatusTestRequest(t *testing.T, serviceType ie.ConstSvcType) *nasMessage.SvcReq {
	t.Helper()
	inner := &nasMessage.SvcReq{
		Ngksi:         &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 1},
		SvcType:       &ie.SvcType{Value: serviceType},
		TMSI5GS:       &ie.MobileId5GS{TypeOfId: ie.IdType_5GS_TMSI, TMSI5G: [4]byte{0, 0, 0, 1}},
		PDUSessStatus: &ie.PDUSessStatus{},
	}
	contents, err := nasMessage.Marshal(inner, nil, nasMessage.SecHdrTypePlainNas)
	require.NoError(t, err)
	outer := *inner
	outer.PDUSessStatus = nil
	outer.NASMsgCntr = &ie.NASMsgCntr{Contents: contents}
	return &outer
}

// serviceStatusTestSent returns the first NAS message that the AMF sent.
func serviceStatusTestSent(t *testing.T, conn *ngaptesting.SctpConnStub) nasMessage.Message {
	t.Helper()
	require.NotEmpty(t, conn.MsgList)
	decoded, err := ngapMessage.Parse(conn.MsgList[0])
	require.NoError(t, err)
	transport, ok := decoded.(*ngapMessage.DownlinkNASTransport)
	require.True(t, ok, "sent %T", decoded)
	// The test's security context has the null algorithms: after the security header, the plain message.
	msg, err := nasMessage.ParseGMM(transport.NASPDU.Value[7:])
	require.NoError(t, err)
	return msg
}

// TS 24.501 5.6.1.4.1: for a SERVICE REQUEST for signaling too, the AMF releases the PDU sessions of the access type
// the request is sent over that the UE says are inactive, here session 5 but not session 6 of non-3GPP access, and the
// SERVICE ACCEPT has a PDU session status of the sessions that stay active, none.
func TestSignalingServiceRequestReleasesInactivePDUSession(t *testing.T) {
	ue, conn, released := newServiceStatusTestUe(t)

	// This spelling is the name exported by the NAS API.
	request := serviceStatusTestRequest(t, ie.SvcType_Signalling) //nolint:misspell
	require.NoError(t, HandleServiceRequest(ue, models.AccessType_3_GPP_ACCESS, request))

	require.Len(t, released, 1, "the number of release requests")
	require.Equal(t, "/nsmf-pdusession/v1/sm-contexts/3GPP_ACCESS/release", <-released)
	_, ok := ue.SmContextFindByPDUSessionID(5)
	require.False(t, ok, "session 5 is kept")
	_, ok = ue.SmContextFindByPDUSessionID(6)
	require.True(t, ok, "session 6 is released")
	accept, ok := serviceStatusTestSent(t, conn).(*nasMessage.SvcAccept)
	require.True(t, ok, "the request is not accepted")
	require.NotNil(t, accept.PDUSessStatus, "the accept has no PDU session status")
	require.Equal(t, [16]bool{}, accept.PDUSessStatus.PSI)
}

// TS 24.501 5.6.1.5: the SERVICE REJECT of a request with a PDU session status has a PDU session status of the
// sessions of the access type it is sent over that are active in the AMF, here session 5.
func TestEmergencyServiceRejectPDUSessionStatusFromContainer(t *testing.T) {
	ue, conn, released := newServiceStatusTestUe(t)

	request := serviceStatusTestRequest(t, ie.SvcType_EmergSvc)
	require.NoError(t, HandleServiceRequest(ue, models.AccessType_3_GPP_ACCESS, request))

	require.Empty(t, released)
	reject, ok := serviceStatusTestSent(t, conn).(*nasMessage.SvcRej)
	require.True(t, ok, "the request is not rejected")
	require.NotNil(t, reject.PDUSessStatus, "the reject has no PDU session status")
	require.Equal(t, [16]bool{5: true}, reject.PDUSessStatus.PSI)
}
