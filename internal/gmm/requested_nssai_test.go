package gmm

import (
	"encoding/json"
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

type nssaiTestApp struct{}

func (nssaiTestApp) SetLogEnable(bool)            {}
func (nssaiTestApp) SetLogLevel(string)           {}
func (nssaiTestApp) SetReportCaller(bool)         {}
func (nssaiTestApp) Start()                       {}
func (nssaiTestApp) Terminate()                   {}
func (nssaiTestApp) Context() *context.AMFContext { return context.GetSelf() }
func (nssaiTestApp) Config() *factory.Config      { return factory.AmfConfig }

var (
	nssaiTestServed       = models.Snssai{Sst: 1, Sd: "010203"} // subscribed (default), served in the TA
	nssaiTestUnsubscribed = models.Snssai{Sst: 1, Sd: "112233"} // served in the TA, not subscribed
	nssaiTestOtherTa      = models.Snssai{Sst: 2, Sd: "000001"} // subscribed, not served in the TA
	nssaiTestNotInAmf     = models.Snssai{Sst: 3, Sd: "000003"} // subscribed, served in the TA, not supported by the AMF
	nssaiTestTai          = models.Tai{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, Tac: "000001"}
)

// newNssaiTestUe returns a UE whose NSSF query fails because the NSSF is
// unreachable, and which requests the given S-NSSAIs.
func newNssaiTestUe(t *testing.T, requested ...models.Snssai) (*context.AmfUe, *ngaptesting.SctpConnStub) {
	t.Helper()
	amfSelf := context.GetSelf()
	amfSelf.ServedGuamiList = []models.Guami{{PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"}, AmfId: "cafe00"}}
	amfSelf.SupportTaiLists = []models.Tai{nssaiTestTai}
	amfSelf.PlmnSupportList = []factory.PlmnSupportItem{{
		PlmnId:     &models.PlmnId{Mcc: "208", Mnc: "93"},
		SNssaiList: []models.Snssai{nssaiTestServed, nssaiTestUnsubscribed, nssaiTestOtherTa},
	}}
	amfSelf.NrfUri = "http://127.0.0.1:1"
	if factory.AmfConfig == nil {
		factory.AmfConfig = &factory.Config{Configuration: &factory.Configuration{}}
	}
	_, err := consumer.NewConsumer(nssaiTestApp{})
	require.NoError(t, err)

	conn := new(ngaptesting.SctpConnStub)
	ran := &context.AmfRan{
		AnType: models.AccessType_3_GPP_ACCESS, Conn: conn, Log: logger.NgapLog,
		SupportedTAList: []context.SupportedTAI{{
			Tai:        nssaiTestTai,
			SNssaiList: []models.Snssai{nssaiTestServed, nssaiTestUnsubscribed, nssaiTestNotInAmf},
		}},
	}
	ue := amfSelf.NewAmfUe("imsi-208930000007487")
	t.Cleanup(ue.Remove)
	ue.NssfUri = "http://127.0.0.1:1" // NSSelectionGet fails with a transport error
	ue.Tai = nssaiTestTai
	ue.SubscribedNssai = []models.Nssf_NSSel_SubscribedSnssai{
		{SubscribedSnssai: &nssaiTestServed, DefaultIndication: true},
		{SubscribedSnssai: &nssaiTestOtherTa},
		{SubscribedSnssai: &nssaiTestNotInAmf},
	}
	ue.AttachRanUe(&context.RanUe{Ran: ran, RanUeNgapId: 1, AmfUeNgapId: 1, Log: logger.NgapLog, Tai: nssaiTestTai})
	nssai := &ie.NSSAI{}
	for _, s := range requested {
		nssai.SNSSAIs = append(nssai.SNSSAIs, ie.SNSSAI{SST: uint8(s.Sst), SD: s.Sd})
	}
	ue.RegistrationRequest = &nasMessage.RegReq{ReqNSSAI: nssai}
	return ue, conn
}

func nssaiTestAllowed(ue *context.AmfUe) []models.Snssai {
	var allowed []models.Snssai
	for _, a := range ue.AllowedNssai[models.AccessType_3_GPP_ACCESS] {
		allowed = append(allowed, *a.AllowedSnssai)
	}
	return allowed
}

// TS 23.501 5.15.5.2.1: when the NSSF cannot be used, the S-NSSAIs the AMF can
// serve are allowed whatever their position in the Requested NSSAI, and the
// others are reported as rejected instead of rejecting the registration.
func TestRequestedNssaiWithoutNssfIsOrderIndependent(t *testing.T) {
	for _, requested := range [][]models.Snssai{
		{nssaiTestServed, nssaiTestUnsubscribed},
		{nssaiTestUnsubscribed, nssaiTestServed},
	} {
		ue, conn := newNssaiTestUe(t, requested...)

		require.NoError(t, handleRequestedNssai(ue, models.AccessType_3_GPP_ACCESS))

		require.Empty(t, conn.MsgList, "the registration was rejected")
		require.Equal(t, []models.Snssai{nssaiTestServed}, nssaiTestAllowed(ue))
		require.Equal(t, []models.Snssai{nssaiTestUnsubscribed}, ue.NetworkSliceInfo.RejectedNssaiInPlmn)
		require.Empty(t, ue.NetworkSliceInfo.RejectedNssaiInTa)
	}
}

// TS 23.501 5.15.4.1: an S-NSSAI rejected for the entire PLMN is not requested
// again anywhere in the PLMN. A subscribed S-NSSAI that is only unavailable in
// the current TA is rejected for the registration area.
func TestRequestedNssaiWithoutNssfRejectsTaUnavailableSliceInTa(t *testing.T) {
	ue, _ := newNssaiTestUe(t, nssaiTestServed, nssaiTestOtherTa)

	require.NoError(t, handleRequestedNssai(ue, models.AccessType_3_GPP_ACCESS))

	require.Equal(t, []models.Snssai{nssaiTestServed}, nssaiTestAllowed(ue))
	require.Equal(t, []models.Snssai{nssaiTestOtherTa}, ue.NetworkSliceInfo.RejectedNssaiInTa)
	require.Empty(t, ue.NetworkSliceInfo.RejectedNssaiInPlmn)
}

// An S-NSSAI the UE may use but this AMF does not support might be served by
// another AMF of the PLMN; without the NSSF it is neither allowed nor rejected,
// so the UE may request it again (TS 23.501 5.15.4.1).
func TestRequestedNssaiWithoutNssfDoesNotRejectSliceUnsupportedByAmf(t *testing.T) {
	ue, _ := newNssaiTestUe(t, nssaiTestServed, nssaiTestNotInAmf)

	require.NoError(t, handleRequestedNssai(ue, models.AccessType_3_GPP_ACCESS))

	require.Equal(t, []models.Snssai{nssaiTestServed}, nssaiTestAllowed(ue))
	require.Empty(t, ue.NetworkSliceInfo.RejectedNssaiInPlmn)
	require.Empty(t, ue.NetworkSliceInfo.RejectedNssaiInTa)
}

// TS 23.501 5.15.5.2.1 (C): the Allowed NSSAI only holds S-NSSAIs available in
// the registration area. The Allowed NSSAI of the previous registration is not
// reused; with no requested S-NSSAI allowed, the default S-NSSAI is used.
func TestRequestedNssaiWithoutNssfReplacesPreviousAllowedNssai(t *testing.T) {
	ue, _ := newNssaiTestUe(t, nssaiTestOtherTa)
	ue.AllowedNssai[models.AccessType_3_GPP_ACCESS] = []models.Nssf_NSSel_AllowedSnssai{
		{AllowedSnssai: &nssaiTestOtherTa},
	}

	require.NoError(t, handleRequestedNssai(ue, models.AccessType_3_GPP_ACCESS))

	require.Equal(t, []models.Snssai{nssaiTestServed}, nssaiTestAllowed(ue))
	require.Equal(t, []models.Snssai{nssaiTestOtherTa}, ue.NetworkSliceInfo.RejectedNssaiInTa)
}

// TS 23.501 5.15.5.2.1 and TS 24.501 5.5.1.2.5: when no S-NSSAI can be allowed
// and there is no default S-NSSAI, the registration is rejected with #62 and the
// rejected S-NSSAIs.
func TestRequestedNssaiWithoutNssfRejectsWhenNothingIsAllowed(t *testing.T) {
	ue, conn := newNssaiTestUe(t, nssaiTestUnsubscribed)
	ue.SubscribedNssai = []models.Nssf_NSSel_SubscribedSnssai{{SubscribedSnssai: &nssaiTestOtherTa}}

	require.Error(t, handleRequestedNssai(ue, models.AccessType_3_GPP_ACCESS))

	require.Len(t, conn.MsgList, 1)
	decoded, err := ngapMessage.Parse(conn.MsgList[0])
	require.NoError(t, err)
	downlink, ok := decoded.(*ngapMessage.DownlinkNASTransport)
	require.True(t, ok, "NGAP message is %T", decoded)
	nasMsg, err := nasMessage.ParseGMM(downlink.NASPDU.Value)
	require.NoError(t, err)
	reject, ok := nasMsg.(*nasMessage.RegRej)
	require.True(t, ok, "NAS message is %T", nasMsg)
	require.Equal(t, ie.Cause5GMM_NoNwSlicesAvailable, reject.Cause5GMM.Value)
	rejected := &ie.RejectedNSSAI{}
	rejected.Append(ie.SNSSAIRej_NotAvailInCurrPLMN, uint8(nssaiTestUnsubscribed.Sst), nssaiTestUnsubscribed.Sd)
	require.Equal(t, rejected, reject.RejectedNSSAI)
}

// The free5gc NSSF answers 403 SNSSAI_NOT_SUPPORTED as soon as one requested
// S-NSSAI is not in its PLMN list. That answer carries no per-S-NSSAI result, so
// it is handled like an unavailable NSSF instead of rejecting the registration.
func TestRequestedNssaiWithNssfForbiddenAllowsServedSlices(t *testing.T) {
	nssf := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusForbidden)
		if err := json.NewEncoder(w).Encode(models.ProblemDetails{
			Title: "Unsupported request resources", Status: http.StatusForbidden,
			Detail: "S-NSSAI in Requested NSSAI is not supported in PLMN", Cause: "SNSSAI_NOT_SUPPORTED",
		}); err != nil {
			t.Error(err)
		}
	}))
	nssf.Config.Protocols = new(http.Protocols)
	nssf.Config.Protocols.SetUnencryptedHTTP2(true) // the SBI client speaks HTTP/2 with prior knowledge
	nssf.Start()
	t.Cleanup(nssf.Close)

	unknown := models.Snssai{Sst: 9}
	ue, conn := newNssaiTestUe(t, nssaiTestServed, unknown)
	ue.NssfUri = nssf.URL

	require.NoError(t, handleRequestedNssai(ue, models.AccessType_3_GPP_ACCESS))

	require.Empty(t, conn.MsgList, "the registration was rejected")
	require.Equal(t, []models.Snssai{nssaiTestServed}, nssaiTestAllowed(ue))
	require.Equal(t, []models.Snssai{unknown}, ue.NetworkSliceInfo.RejectedNssaiInPlmn)
}
