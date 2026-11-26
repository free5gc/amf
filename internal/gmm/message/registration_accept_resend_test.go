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

func TestRegistrationAcceptResentAfterAuthenticationUsesNewSecurityContext(t *testing.T) {
	const access = models.AccessType_3_GPP_ACCESS
	self := context.GetSelf()
	previousGuami, previousTimer := self.ServedGuamiList, self.T3550Cfg
	self.ServedGuamiList = []models.Guami{{PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"}, AmfId: "cafe00"}}
	self.T3550Cfg = factory.TimerValue{Enable: true, ExpireTime: time.Hour, MaxRetryTimes: 4}
	t.Cleanup(func() { self.ServedGuamiList, self.T3550Cfg = previousGuami, previousTimer })
	previousConfig := factory.AmfConfig
	factory.AmfConfig = &factory.Config{Configuration: &factory.Configuration{}}
	t.Cleanup(func() { factory.AmfConfig = previousConfig })
	ue := self.NewAmfUe("imsi-208930000000129")
	t.Cleanup(ue.Remove)
	conn := new(ngaptesting.SctpConnStub)
	ran := &context.AmfRan{AnType: access, Conn: conn, Log: logger.NgapLog}
	ue.AttachRanUe(&context.RanUe{Ran: ran, RanUeNgapId: 1, AmfUeNgapId: 1, Log: logger.NgapLog})
	ue.State[access].Set(context.ContextSetup)
	ue.SecurityContextAvailable = true
	ue.IntegrityAlg = 2 // 128-5G-IA2
	ue.KnasInt = [16]byte{1, 2, 3, 4}
	ue.NgKsi = models.Amf_Comm_NgKsi{Tsc: models.Amf_Comm_ScType_NATIVE, Ksi: 1}
	SendRegistrationAccept(ue, access, nil, nil, nil, nil, nil)
	guti := ue.GetGuti()
	// Model an accept whose retransmission counter was already three when the
	// authenticated connection replaced it. Re-sending must not reset or increment it.
	ue.StartT3550(self.T3550Cfg, func(int32, func() bool) {}, func() {}, 3)
	resend, retries := ue.RegistrationAcceptResend()
	require.NotNil(t, resend)
	require.EqualValues(t, 3, retries)
	ue.StopAll5GSMMTimers()
	ue.KnasInt = [16]byte{5, 6, 7, 8}
	ue.DLCount.Set(0, 5)
	resend(retries)
	require.Equal(t, guti, ue.GetGuti())
	require.EqualValues(t, 3, ue.T3550.ExpireTimes())
	require.Len(t, conn.MsgList, 2)
	decoded, err := ngapMessage.Parse(conn.MsgList[1])
	require.NoError(t, err)
	downlink, ok := decoded.(*ngapMessage.DownlinkNASTransport)
	require.True(t, ok)
	require.EqualValues(t, 5, downlink.NASPDU.Value[nas_message.SecHdrLen-1])
	security := nas_message.NewSecCtx(nas_message.UESide, nas_message.Bearer3GPP,
		ie.AlgCiphering(ue.CipheringAlg), ie.AlgIntegrity(ue.IntegrityAlg), ue.KnasEnc[:], ue.KnasInt[:])
	accept, err := nas_message.Parse(downlink.NASPDU.Value, security)
	require.NoError(t, err)
	require.IsType(t, &nas_message.RegAccept{}, accept)
	ue.ClearRegistrationRequestData(access)
	resend, _ = ue.RegistrationAcceptResend()
	require.Nil(t, resend, "completed registration must not retain an accept")
}
