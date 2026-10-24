package ngap

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	gmm_message "github.com/free5gc/amf/internal/gmm/message"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// retransmissionConn records what the AMF sends to the gNB. The 5GMM timers
// write from their own goroutines, so it is guarded by a mutex.
type retransmissionConn struct {
	mu   sync.Mutex
	msgs [][]byte
}

func (c *retransmissionConn) Read(b []byte) (int, error) { return 0, nil }
func (c *retransmissionConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = append(c.msgs, append([]byte(nil), b...))
	return len(b), nil
}
func (c *retransmissionConn) Close() error                     { return nil }
func (c *retransmissionConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *retransmissionConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *retransmissionConn) SetDeadline(time.Time) error      { return nil }
func (c *retransmissionConn) SetReadDeadline(time.Time) error  { return nil }
func (c *retransmissionConn) SetWriteDeadline(time.Time) error { return nil }

// names returns the NGAP message names sent from index from on.
func (c *retransmissionConn) names(t *testing.T, from int) []string {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var names []string
	for _, msg := range c.msgs[from:] {
		decoded, err := ngapMessage.Parse(msg)
		require.NoError(t, err)
		names = append(names, messageName(decoded))
	}
	return names
}

func (c *retransmissionConn) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.msgs)
}

func countName(names []string, name string) int {
	n := 0
	for _, got := range names {
		if got == name {
			n++
		}
	}
	return n
}

// A 5GMM retransmission timer holds the RanUe it was started on. Once that
// UE-associated logical NG-connection is released by NG Reset or by the loss
// of the SCTP association, the AMF must not send the NAS message again with
// the released AP IDs. The timer must keep running all the same: its last
// expiry is what aborts the procedure, so the UE is not left in the procedure's
// state.
func TestNasRetransmissionStopsWhenN2ConnectionIsReleased(t *testing.T) {
	amfSelf := amf_context.GetSelf()
	NewAmfContext(amfSelf)
	timer := factory.TimerValue{Enable: true, ExpireTime: 50 * time.Millisecond, MaxRetryTimes: 3}
	amfSelf.T3522Cfg = timer
	amfSelf.T3560Cfg = timer
	amfSelf.T3565Cfg = timer
	amfSelf.T3570Cfg = timer
	// T3565's last expiry sends the N1N2 transfer failure notification; the
	// SMF stub records the callback path of each notification it receives.
	var failureNotified sync.Map
	smf := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		failureNotified.Store(r.URL.Path, true)
		w.WriteHeader(http.StatusNoContent)
	}))
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	smf.Config.Protocols = protocols
	smf.Start()
	t.Cleanup(smf.Close)
	// Let the last expiry return before another test resets the AMF context.
	t.Cleanup(func() { time.Sleep(5 * timer.ExpireTime) })

	const anType = models.AccessType_3_GPP_ACCESS
	removed := func(amfUe *amf_context.AmfUe) bool {
		_, ok := amfSelf.AmfUeFindBySupi(amfUe.Supi)
		return !ok
	}
	procedures := []struct {
		name    string
		start   func(ranUe *amf_context.RanUe, amfUe *amf_context.AmfUe)
		aborted func(amfUe *amf_context.AmfUe) bool
		// timerSendsAll: start sends nothing, every message is sent by the timer
		timerSendsAll bool
	}{
		{
			name: "T3560 authentication",
			start: func(ranUe *amf_context.RanUe, amfUe *amf_context.AmfUe) {
				amfUe.State[anType].Set(amf_context.Authentication)
				amfUe.ABBA = []uint8{0x00, 0x00}
				amfUe.AuthenticationCtx = &models.Ausf_UEAU_UEAuthenticationCtx{
					AuthType: models.Ausf_UEAU_AuthType_5_G_AKA,
					Var5gAuthData: map[string]interface{}{
						"rand": "00112233445566778899aabbccddeeff",
						"autn": "ffeeddccbbaa99887766554433221100",
					},
				}
				gmm_message.SendAuthenticationRequest(ranUe)
			},
			aborted: removed,
		},
		{
			name: "T3560 security mode control",
			start: func(ranUe *amf_context.RanUe, amfUe *amf_context.AmfUe) {
				amfUe.State[anType].Set(amf_context.SecurityMode)
				amfUe.IntegrityAlg = 2 // 128-5G-IA2
				amfUe.UESecurityCapability = ie.UESecCapability{Length: 2, EA05G: true, IA2_128_5G: true}
				gmm_message.SendSecurityModeCommand(ranUe, anType, false, "")
			},
			aborted: removed,
		},
		{
			name: "T3570 identification",
			start: func(ranUe *amf_context.RanUe, amfUe *amf_context.AmfUe) {
				gmm_message.SendIdentityRequest(ranUe, anType, ie.IdType_5GS_SUCI)
			},
			aborted: removed,
		},
		{
			// SendNotification only starts T3565, which sends each NOTIFICATION.
			name:          "T3565 notification",
			timerSendsAll: true,
			start: func(ranUe *amf_context.RanUe, amfUe *amf_context.AmfUe) {
				amfUe.N1N2Message = &amf_context.N1N2Message{
					Request: models.N1N2MessageTransferRequestBody{JsonData: &models.Amf_Comm_N1N2MessageTransferReqData{
						N1n2FailureTxfNotifURI: smf.URL + "/" + amfUe.Supi,
					}},
					Status: models.Amf_Comm_N1N2MessageTransferCause_ATTEMPTING_TO_REACH_UE,
				}
				gmm_message.SendNotification(ranUe, []byte{0x7e, 0x00, 0x65, 0x01, 0x02})
			},
			aborted: func(amfUe *amf_context.AmfUe) bool {
				_, ok := failureNotified.Load("/" + amfUe.Supi)
				return ok
			},
		},
		{
			name: "T3522 network-initiated de-registration",
			start: func(ranUe *amf_context.RanUe, amfUe *amf_context.AmfUe) {
				amfUe.State[anType].Set(amf_context.Registered)
				amfUe.SecurityContextAvailable = true
				amfUe.IntegrityAlg = 2 // 128-5G-IA2
				gmm_message.SendDeregistrationRequest(ranUe, ie.AccessType_3gpp, false, 0)
			},
			aborted: func(amfUe *amf_context.AmfUe) bool {
				return amfUe.State[anType].Is(amf_context.Deregistered)
			},
		},
	}
	releases := []struct {
		name    string
		release func(ran *amf_context.AmfRan, ranUe *amf_context.RanUe)
	}{
		{name: "connection kept"},
		{
			name: "NG Reset part of NG interface",
			release: func(ran *amf_context.AmfRan, ranUe *amf_context.RanUe) {
				handleNGResetMain(ran, nil, &ngapType.ResetType{Choice: &ngapType.UEAssociatedLogicalNGConnectionList{
					List: []ngapType.UEAssociatedLogicalNGConnectionItem{{
						AMFUENGAPID: &ngapType.AMFUENGAPID{Value: ranUe.AmfUeNgapId},
						RANUENGAPID: &ngapType.RANUENGAPID{Value: ranUe.RanUeNgapId},
					}},
				}})
			},
		},
		{
			name: "NG Reset all",
			release: func(ran *amf_context.AmfRan, _ *amf_context.RanUe) {
				handleNGResetMain(ran, nil, &ngapType.ResetType{Choice: &ngapType.ResetAll{}})
			},
		},
		{
			name: "SCTP association lost",
			release: func(ran *amf_context.AmfRan, _ *amf_context.RanUe) {
				ran.Remove()
			},
		},
	}

	var ranUeNgapID int64
	for _, procedure := range procedures {
		for _, release := range releases {
			t.Run(procedure.name+"/"+release.name, func(t *testing.T) {
				ranUeNgapID++
				conn := &retransmissionConn{}
				ran := NewAmfRan(conn)
				ranUe, err := ran.NewRanUe(ranUeNgapID)
				require.NoError(t, err)
				amfUe := amfSelf.NewAmfUe(fmt.Sprintf("imsi-2089300000%05d", ranUeNgapID))
				amfUe.AttachRanUe(ranUe)

				procedure.start(ranUe, amfUe)
				if procedure.timerSendsAll {
					require.Empty(t, conn.names(t, 0))
				} else {
					require.Equal(t, []string{"DownlinkNASTransport"}, conn.names(t, 0))
				}

				if release.release != nil {
					release.release(ran, ranUe)
				}
				afterRelease := conn.count()

				require.Eventually(t, func() bool { return procedure.aborted(amfUe) },
					2*time.Second, timer.ExpireTime/4, "the last expiry must still abort the procedure")

				sent := conn.names(t, afterRelease)
				if release.release == nil {
					require.Equal(t, timer.MaxRetryTimes, countName(sent, "DownlinkNASTransport"),
						"the timer retransmits on a live connection")
				} else {
					require.Zero(t, countName(sent, "DownlinkNASTransport"),
						"no retransmission on the released connection, got %v", sent)
				}
			})
		}
	}
}
