package ngap

// Shared fixture for the N2 and Xn handover handler tests. It provides a
// registered UE with PDU session 5 served by a source NG-RAN node, a second
// NG-RAN node as handover target, stub SCTP connections that record what the
// AMF sends, and an SMF stub that records every Nsmf_PDUSession_UpdateSMContext
// request as "<hoState>/<n2SmInfoType>/<upCnxState>" (empty parts omitted).

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/ngap/aper"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/mediatype/multipart"
	"github.com/free5gc/openapi/models"
)

const hoTestAnType = models.AccessType_3_GPP_ACCESS

var hoSmfFields = []*regexp.Regexp{
	regexp.MustCompile(`"hoState":"([A-Z_]+)"`),
	regexp.MustCompile(`"n2SmInfoType":"([A-Z_]+)"`),
	regexp.MustCompile(`"upCnxState":"([A-Z_]+)"`),
}

type hoSmfStub struct {
	mu   sync.Mutex
	reqs []string
}

func (s *hoSmfStub) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	reqs := make([]string, len(s.reqs))
	copy(reqs, s.reqs)
	return reqs
}

func newHoSmfStub(t *testing.T) (*hoSmfStub, string) {
	s := &hoSmfStub{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var fields []string
		for _, re := range hoSmfFields {
			if m := re.FindSubmatch(body); m != nil {
				fields = append(fields, string(m[1]))
			}
		}
		s.mu.Lock()
		s.reqs = append(s.reqs, strings.Join(fields, "/"))
		s.mu.Unlock()
		ct, payload, err := openapi.Serialize(models.UpdateSmContextResponse200{
			JsonData: &models.Smf_PDUSess_SmContextUpdatedData{
				N2SmInfo: &models.RefToBinaryData{ContentId: "N2SmInfo"},
			},
			BinaryDataN2SmInformation: &multipart.RelatedContent{ContentID: "N2SmInfo", Content: []byte{0x00}},
		}, "multipart/related")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(http.StatusOK)
		if _, err = w.Write(payload); err != nil {
			t.Logf("SMF stub write: %v", err)
		}
	}))
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	srv.Config.Protocols = protocols
	srv.Start()
	t.Cleanup(srv.Close)
	return s, srv.URL
}

type hoTestEnv struct {
	amfUe            *amf_context.AmfUe
	srcRan, tgtRan   *amf_context.AmfRan
	srcConn, tgtConn *ngaptesting.SctpConnStub
	src, tgt         *amf_context.RanUe
	smf              *hoSmfStub
}

func newHoTestRan(gnbID string) (*amf_context.AmfRan, *ngaptesting.SctpConnStub) {
	conn := &ngaptesting.SctpConnStub{}
	ran := NewAmfRan(conn)
	ran.Name = "gnb-" + gnbID
	ran.RanId.GNbId.GNBValue = gnbID
	amf_context.GetSelf().AmfRanPool.Store(conn, ran)
	return ran, conn
}

// newHoTestEnv registers a UE with PDU session 5 on the source node
// (RAN-UE-NGAP-ID 1). With prepareTarget, the source sends HANDOVER REQUIRED
// towards the target node and the AMF prepares the target RanUe and sends the
// HANDOVER REQUEST (TS 23.502 4.9.1.3.2).
func newHoTestEnv(t *testing.T, prepareTarget bool) *hoTestEnv {
	amfSelf := amf_context.GetSelf()
	NewAmfContext(amfSelf)
	_, err := consumer.NewConsumer(nil)
	require.NoError(t, err)
	prevCfg := factory.AmfConfig
	factory.AmfConfig = &factory.Config{}
	t.Cleanup(func() { factory.AmfConfig = prevCfg })

	e := &hoTestEnv{}
	var smfURI string
	e.smf, smfURI = newHoSmfStub(t)
	e.srcRan, e.srcConn = newHoTestRan("000001")
	e.tgtRan, e.tgtConn = newHoTestRan("000002")

	e.amfUe = amfSelf.NewAmfUe("imsi-208930000000001")
	e.amfUe.SecurityContextAvailable = true
	e.amfUe.NgKsi.Ksi = 1
	e.amfUe.Kamf = strings.Repeat("11", 32)
	e.amfUe.NH = []byte(strings.Repeat("\x22", 32))
	e.amfUe.AccessAndMobilitySubscriptionData = &models.Udm_SDM_AccessAndMobilitySubscriptionData{
		SubscribedUeAmbr: &models.AmbrRm{Uplink: "1 Gbps", Downlink: "2 Gbps"},
	}
	e.amfUe.State[hoTestAnType].Set(amf_context.Registered)

	sm := amf_context.NewSmContext(5)
	sm.SetSmfUri(smfURI)
	sm.SetSmContextRef("sm-context-5")
	sm.SetSnssai(models.Snssai{Sst: 1, Sd: "010203"})
	sm.SetAccessType(hoTestAnType)
	e.amfUe.StoreSmContext(5, sm)

	e.src, err = e.srcRan.NewRanUe(1)
	require.NoError(t, err)
	e.amfUe.AttachRanUe(e.src)

	if prepareTarget {
		dispatchMain(e.srcRan, newHoTestHandoverRequired(e.src), nil)
		hoRequireSent(t, e.tgtConn, "target not prepared", "HandoverRequest")
		e.tgt = e.src.TargetUe
		require.NotNil(t, e.tgt)
	}
	return e
}

// newHoTestHandoverRequired is the source's HANDOVER REQUIRED for PDU session 5
// towards the target node (gNB ID 000002, TAC 000001).
func newHoTestHandoverRequired(src *amf_context.RanUe) *ngapMessage.HandoverRequired {
	transfer := aper.OctetString{0x00}
	return &ngapMessage.HandoverRequired{
		AMFUENGAPID:  &ngapType.AMFUENGAPID{Value: src.AmfUeNgapId},
		RANUENGAPID:  &ngapType.RANUENGAPID{Value: src.RanUeNgapId},
		HandoverType: &ngapType.HandoverType{Value: ngapType.HandoverTypePresentIntra5gs},
		Cause: &ngapType.Cause{Choice: &ngapType.CauseRadioNetwork{
			Value: ngapType.CauseRadioNetworkPresentHandoverDesirableForRadioReason,
		}},
		TargetID: &ngapType.TargetID{Choice: &ngapType.TargetRANNodeID{
			GlobalRANNodeID: &ngapType.GlobalRANNodeID{Choice: &ngapType.GlobalGNBID{
				PLMNIdentity: &ngapType.PLMNIdentity{Value: aper.OctetString{0x02, 0xf8, 0x39}},
				GNBID: &ngapType.GNBID{Choice: &ngapType.GNBIDForGNBID{Value: aper.BitString{
					Bytes: []byte{0x00, 0x00, 0x02}, BitLength: 24,
				}}},
			}},
			SelectedTAI: &ngapType.TAI{
				PLMNIdentity: &ngapType.PLMNIdentity{Value: aper.OctetString{0x02, 0xf8, 0x39}},
				TAC:          &ngapType.TAC{Value: aper.OctetString{0x00, 0x00, 0x01}},
			},
		}},
		PDUSessionResourceListHORqd: &ngapType.PDUSessionResourceListHORqd{
			List: []ngapType.PDUSessionResourceItemHORqd{{
				PDUSessionID:             &ngapType.PDUSessionID{Value: 5},
				HandoverRequiredTransfer: &transfer,
			}},
		},
		SourceToTargetTransparentContainer: &ngapType.SourceToTargetTransparentContainer{
			Value: aper.OctetString{0x00},
		},
	}
}

// hoSentNames decodes what the AMF sent on a stub connection.
func hoSentNames(conn *ngaptesting.SctpConnStub) []string {
	names := make([]string, 0, len(conn.MsgList))
	for _, b := range conn.MsgList {
		m, err := ngapMessage.Parse(b)
		if err != nil || m == nil {
			names = append(names, "UNDECODABLE")
			continue
		}
		names = append(names, messageName(m))
	}
	return names
}

// hoRequireSent checks the complete sequence of messages the AMF sent on conn.
func hoRequireSent(t *testing.T, conn *ngaptesting.SctpConnStub, why string, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	require.Equal(t, want, hoSentNames(conn), why)
}

// requireRequests checks the SMF requests received from index from onwards.
func (s *hoSmfStub) requireRequests(t *testing.T, from int, why string, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	require.Equal(t, want, s.requests()[from:], why)
}
