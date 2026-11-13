package ngap

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	ngap_message "github.com/free5gc/amf/internal/ngap/message"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	"github.com/free5gc/ngap/aper"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// icsSmfStub is an h2c SMF that records the SM context of every
// Nsmf_PDUSession_UpdateSMContext request it receives.
type icsSmfStub struct {
	mu      sync.Mutex
	updates []string
}

func (s *icsSmfStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.updates = append(s.updates, strings.TrimSuffix(strings.TrimPrefix(r.URL.Path,
		"/nsmf-pdusession/v1/sm-contexts/"), "/modify"))
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *icsSmfStub) smContextUpdates() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.updates...)
}

// TS 38.413 8.3.1 / 10.4: INITIAL CONTEXT SETUP RESPONSE and FAILURE answer an
// INITIAL CONTEXT SETUP REQUEST. The AMF applies each answer to one
// outstanding request and ignores an answer for which no request is
// outstanding.
func TestInitialContextSetupAnswerRequiresOutstandingRequest(t *testing.T) {
	const anType = models.AccessType_3_GPP_ACCESS
	const icsRequest = "InitialContextSetupRequest"
	prevConfig := factory.AmfConfig
	factory.AmfConfig = &factory.Config{Configuration: &factory.Configuration{}}
	t.Cleanup(func() { factory.AmfConfig = prevConfig })
	_, err := consumer.NewConsumer(nil)
	require.NoError(t, err)

	smf := &icsSmfStub{}
	server := httptest.NewUnstartedServer(smf)
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetUnencryptedHTTP2(true)
	server.Start()
	t.Cleanup(server.Close)

	setup := func(t *testing.T) (*ngaptesting.SctpConnStub, *amf_context.AmfRan, *amf_context.RanUe,
		*amf_context.AmfUe,
	) {
		t.Helper()
		amfSelf := amf_context.GetSelf()
		NewAmfContext(amfSelf)
		conn := new(ngaptesting.SctpConnStub)
		ran := NewAmfRan(conn)
		ranUe, newErr := ran.NewRanUe(1)
		require.NoError(t, newErr)
		ranUe.UeContextRequest = true
		amfUe := amfSelf.NewAmfUe("imsi-208930000000075")
		amfUe.AttachRanUe(ranUe)
		amfUe.Kgnb = make([]byte, 32)
		amfUe.UESecurityCapability = ie.UESecCapability{Length: 2}
		amfUe.AllowedNssai[anType] = []models.Nssf_NSSel_AllowedSnssai{
			{AllowedSnssai: &models.Snssai{Sst: 1, Sd: "010203"}},
		}
		for _, psi := range []int32{5, 6} {
			smContext := amf_context.NewSmContext(psi)
			smContext.SetSmContextRef(fmt.Sprintf("psi-%d", psi))
			smContext.SetSmfUri(server.URL)
			amfUe.StoreSmContext(psi, smContext)
		}
		return conn, ran, ranUe, amfUe
	}
	response := func(ranUe *amf_context.RanUe, psi int64) *ngapMessage.InitialContextSetupResponse {
		return &ngapMessage.InitialContextSetupResponse{
			AMFUENGAPID: &ngapType.AMFUENGAPID{Value: ranUe.AmfUeNgapId},
			RANUENGAPID: &ngapType.RANUENGAPID{Value: ranUe.RanUeNgapId},
			PDUSessionResourceSetupListCxtRes: &ngapType.PDUSessionResourceSetupListCxtRes{
				List: []ngapType.PDUSessionResourceSetupItemCxtRes{{
					PDUSessionID:                            &ngapType.PDUSessionID{Value: psi},
					PDUSessionResourceSetupResponseTransfer: &aper.OctetString{0x00},
				}},
			},
		}
	}
	sentNames := func(t *testing.T, conn *ngaptesting.SctpConnStub) []string {
		t.Helper()
		var names []string
		for _, msg := range conn.MsgList {
			decoded, parseErr := ngapMessage.Parse(msg)
			require.NoError(t, parseErr)
			names = append(names, messageName(decoded))
		}
		return names
	}

	t.Run("response before any request is ignored", func(t *testing.T) {
		conn, ran, ranUe, amfUe := setup(t)
		before := len(smf.smContextUpdates())

		dispatchMain(ran, response(ranUe, 5), nil)
		require.False(t, ranUe.InitialContextSetup)
		require.Len(t, smf.smContextUpdates(), before, "nothing forwarded to the SMF")

		// The REGISTRATION ACCEPT still goes in an INITIAL CONTEXT SETUP REQUEST.
		ngap_message.SendN2Message(amfUe, anType, []byte{0x7e, 0x00, 0x42}, nil, nil, nil, nil, nil)
		require.Equal(t, []string{icsRequest}, sentNames(t, conn))
	})

	t.Run("failure before any request is ignored", func(t *testing.T) {
		_, ran, ranUe, _ := setup(t)
		before := len(smf.smContextUpdates())

		dispatchMain(ran, &ngapMessage.InitialContextSetupFailure{
			AMFUENGAPID: &ngapType.AMFUENGAPID{Value: ranUe.AmfUeNgapId},
			RANUENGAPID: &ngapType.RANUENGAPID{Value: ranUe.RanUeNgapId},
			PDUSessionResourceFailedToSetupListCxtFail: &ngapType.PDUSessionResourceFailedToSetupListCxtFail{
				List: []ngapType.PDUSessionResourceFailedToSetupItemCxtFail{{
					PDUSessionID: &ngapType.PDUSessionID{Value: 5},
					PDUSessionResourceSetupUnsuccessfulTransfer: &aper.OctetString{0x00},
				}},
			},
			Cause: &ngapType.Cause{Choice: &ngapType.CauseRadioNetwork{
				Value: ngapType.CauseRadioNetworkPresentUnspecified,
			}},
		}, nil)
		require.Len(t, smf.smContextUpdates(), before, "nothing forwarded to the SMF")
	})

	t.Run("each of two outstanding requests gets its response", func(t *testing.T) {
		conn, ran, ranUe, amfUe := setup(t)
		before := len(smf.smContextUpdates())

		// E.g. a SERVICE ACCEPT in a first request, then an N1N2 message
		// transfer for another PDU session before the first response.
		ngap_message.SendInitialContextSetupRequest(amfUe, anType, nil, nil, nil, nil, nil)
		ngap_message.SendInitialContextSetupRequest(amfUe, anType, nil, nil, nil, nil, nil)
		require.Equal(t, []string{icsRequest, icsRequest}, sentNames(t, conn))

		dispatchMain(ran, response(ranUe, 5), nil)
		dispatchMain(ran, response(ranUe, 6), nil)
		require.True(t, ranUe.InitialContextSetup)
		require.Equal(t, []string{"psi-5", "psi-6"}, smf.smContextUpdates()[before:])

		dispatchMain(ran, response(ranUe, 5), nil)
		require.Len(t, smf.smContextUpdates(), before+2, "a third response has no request left")
	})

	t.Run("response crossing a UE CONTEXT RELEASE COMMAND is ignored", func(t *testing.T) {
		_, ran, ranUe, amfUe := setup(t)
		before := len(smf.smContextUpdates())

		ngap_message.SendInitialContextSetupRequest(amfUe, anType, nil, nil, nil, nil, nil)
		ngap_message.SendUEContextReleaseCommand(ranUe, amf_context.UeContextN2NormalRelease,
			ngap_message.CauseChoiceRadioNetwork, ngapType.CauseRadioNetworkPresentUnspecified)
		dispatchMain(ran, response(ranUe, 5), nil)
		require.False(t, ranUe.InitialContextSetup)
		require.Len(t, smf.smContextUpdates(), before, "nothing forwarded to the SMF")
	})
}
