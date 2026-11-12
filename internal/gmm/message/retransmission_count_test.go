package message

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	nas_message "github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// sentConn hands each NGAP message that the AMF sends over a channel, so that a test can wait for a
// retransmission that a timer sends from its own goroutine.
type sentConn struct {
	*ngaptesting.SctpConnStub
	sent chan []byte
}

func (c sentConn) Write(b []byte) (int, error) {
	c.sent <- append([]byte(nil), b...)
	return len(b), nil
}

// nextNasPdu returns the NAS PDU of the next DOWNLINK NAS TRANSPORT that the AMF sends.
func (c sentConn) nextNasPdu(t *testing.T) []byte {
	t.Helper()
	select {
	case b := <-c.sent:
		decoded, err := ngapMessage.Parse(b)
		require.NoError(t, err)
		downlink, ok := decoded.(*ngapMessage.DownlinkNASTransport)
		require.True(t, ok, "NGAP message is %T", decoded)
		return downlink.NASPDU.Value
	case <-time.After(2 * time.Second):
		t.Fatal("no NGAP message sent")
		return nil
	}
}

func newRetransmissionTestUe(t *testing.T, securityContext bool) (*context.AmfUe, sentConn) {
	t.Helper()
	tai := models.Tai{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, Tac: "000001"}
	amfSelf := context.GetSelf()
	amfSelf.ServedGuamiList = []models.Guami{{PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"}, AmfId: "cafe00"}}
	amfSelf.SupportTaiLists = []models.Tai{tai}
	if factory.AmfConfig == nil {
		factory.AmfConfig = &factory.Config{Configuration: &factory.Configuration{}}
	} else if factory.AmfConfig.Configuration == nil {
		factory.AmfConfig.Configuration = &factory.Configuration{}
	}

	ue := amfSelf.NewAmfUe("imsi-208930000000126")
	t.Cleanup(func() {
		ue.StopT3550()
		ue.StopT3555()
		ue.StopT3560()
		ue.StopT3570()
		ue.StopT3522()
		ue.Remove()
	})
	ue.SecurityContextAvailable = securityContext
	ue.CipheringAlg = uint8(nas_message.AlgCiphering128NEA2)
	ue.IntegrityAlg = uint8(nas_message.AlgIntegrity128NIA2)
	ue.KnasEnc = [16]uint8{1, 2, 3, 4}
	ue.KnasInt = [16]uint8{5, 6, 7, 8}
	ue.NgKsi = models.Amf_Comm_NgKsi{Tsc: models.Amf_Comm_ScType_NATIVE, Ksi: 1}
	ue.ABBA = []uint8{0x00, 0x00}
	ue.AuthenticationCtx = &models.Ausf_UEAU_UEAuthenticationCtx{
		AuthType: models.Ausf_UEAU_AuthType_5_G_AKA,
		Var5gAuthData: models.Ausf_UEAU_Av5gAka{
			Rand: "000102030405060708090a0b0c0d0e0f",
			Autn: "101112131415161718191a1b1c1d1e1f",
		},
	}
	conn := sentConn{SctpConnStub: new(ngaptesting.SctpConnStub), sent: make(chan []byte, 8)}
	ran := &context.AmfRan{AnType: models.AccessType_3_GPP_ACCESS, Conn: conn, Log: logger.NgapLog}
	// A RanUe of the AMF's pool: a timer does not retransmit on a released N2 connection.
	ranUe, err := ran.NewRanUe(1)
	require.NoError(t, err)
	t.Cleanup(func() { amfSelf.RanUePool.Delete(ranUe.AmfUeNgapId) })
	ranUe.Tai = tai
	ue.AttachRanUe(ranUe)
	return ue, conn
}

// TS 24.501 4.4.3.1: "After each new or retransmitted outbound SECURITY PROTECTED 5GS NAS MESSAGE
// message, the sender shall increase the NAS COUNT number by one". A UE accepts a NAS COUNT at most
// once (4.4.3.2), so it discards a retransmission that repeats the octets of the first sending.
func TestRetransmissionUsesNextNasCount(t *testing.T) {
	amfSelf := context.GetSelf()
	accessType := models.AccessType_3_GPP_ACCESS
	tests := []struct {
		name      string
		timer     *factory.TimerValue
		protected bool
		send      func(*context.AmfUe)
	}{
		{"T3550 registration accept", &amfSelf.T3550Cfg, true, func(ue *context.AmfUe) {
			SendRegistrationAccept(ue, accessType, nil, nil, nil, nil, nil)
		}},
		{"T3555 configuration update command", &amfSelf.T3555Cfg, true, func(ue *context.AmfUe) {
			SendConfigurationUpdateCommand(ue, accessType, &context.ConfigurationUpdateCommandFlags{NeedGUTI: true})
		}},
		{"T3570 identity request", &amfSelf.T3570Cfg, true, func(ue *context.AmfUe) {
			SendIdentityRequest(ue.GetRanUe(accessType), accessType, ie.IdType_5GS_IMEI)
		}},
		{"T3560 authentication request", &amfSelf.T3560Cfg, true, func(ue *context.AmfUe) {
			SendAuthenticationRequest(ue.GetRanUe(accessType))
		}},
		{"T3522 deregistration request", &amfSelf.T3522Cfg, true, func(ue *context.AmfUe) {
			SendDeregistrationRequest(ue.GetRanUe(accessType), ie.AccessType_3gpp, false, 0)
		}},
		// The initial SECURITY MODE COMMAND resets the downlink NAS COUNT (5.4.2.2); its
		// retransmission does not.
		{"T3560 security mode command", &amfSelf.T3560Cfg, true, func(ue *context.AmfUe) {
			ue.UESecurityCapability = ie.UESecCapability{Length: 2}
			ue.DLCount.Set(0, 5)
			SendSecurityModeCommand(ue.GetRanUe(accessType), accessType, false, "")
		}},
		// Without a security context, the message is plain and sent again as it is.
		{"T3560 plain authentication request", &amfSelf.T3560Cfg, false, func(ue *context.AmfUe) {
			SendAuthenticationRequest(ue.GetRanUe(accessType))
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			saved := *test.timer
			*test.timer = factory.TimerValue{Enable: true, ExpireTime: 50 * time.Millisecond, MaxRetryTimes: 4}
			t.Cleanup(func() { *test.timer = saved })
			ue, conn := newRetransmissionTestUe(t, test.protected)

			test.send(ue)
			first, retransmission := conn.nextNasPdu(t), conn.nextNasPdu(t)

			if !test.protected {
				require.Equal(t, first, retransmission)
				return
			}
			// The UE's view: the same message, under NAS sequence numbers 0 and 1.
			ueSecurity := nas_message.NewSecCtx(nas_message.UESide, nas_message.Bearer3GPP,
				ie.AlgCiphering(ue.CipheringAlg), ie.AlgIntegrity(ue.IntegrityAlg), ue.KnasEnc[:], ue.KnasInt[:])
			var messages []nas_message.Message
			for sequenceNumber, pdu := range [][]byte{first, retransmission} {
				header := new(nas_message.SecProtectedHdr)
				require.NoError(t, header.UnmarshalBinary(pdu))
				require.Equal(t, uint8(sequenceNumber), header.SequenceNumber, "NAS sequence number")
				msg, err := nas_message.Parse(pdu, ueSecurity)
				require.NoError(t, err)
				messages = append(messages, msg)
			}
			require.Equal(t, messages[0], messages[1])
		})
	}
}
