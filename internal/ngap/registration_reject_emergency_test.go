package ngap

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

type emergencyTestApp struct{}

func (emergencyTestApp) SetLogEnable(bool)                {}
func (emergencyTestApp) SetLogLevel(string)               {}
func (emergencyTestApp) SetReportCaller(bool)             {}
func (emergencyTestApp) Start()                           {}
func (emergencyTestApp) Terminate()                       {}
func (emergencyTestApp) Context() *amf_context.AMFContext { return amf_context.GetSelf() }
func (emergencyTestApp) Config() *factory.Config          { return factory.AmfConfig }

// newEmergencyTestUe returns a registered, CM-IDLE UE with a 5G NAS security
// context (NIA2, NEA0) and a stub gNB connection.
func newEmergencyTestUe(t *testing.T) (*ngaptesting.SctpConnStub, *amf_context.AmfRan, *amf_context.AmfUe) {
	t.Helper()
	amfSelf := amf_context.GetSelf()
	NewAmfContext(amfSelf)
	amfSelf.NrfUri = "http://127.0.0.1:1" // SBI requests fail immediately
	long := factory.TimerValue{Enable: true, ExpireTime: time.Hour, MaxRetryTimes: 4}
	amfSelf.T3550Cfg, amfSelf.T3560Cfg, amfSelf.T3570Cfg = long, long, long
	if factory.AmfConfig == nil {
		factory.AmfConfig = &factory.Config{Configuration: &factory.Configuration{}}
	} else if factory.AmfConfig.Configuration == nil {
		factory.AmfConfig.Configuration = &factory.Configuration{}
	}
	_, err := consumer.NewConsumer(emergencyTestApp{})
	require.NoError(t, err)

	ue := amfSelf.NewAmfUe("imsi-208930000007487")
	ue.SecurityContextAvailable = true
	ue.NgKsi = models.Amf_Comm_NgKsi{Tsc: models.Amf_Comm_ScType_NATIVE, Ksi: 1}
	ue.IntegrityAlg = uint8(nasMessage.AlgIntegrity128NIA2)
	ue.CipheringAlg = uint8(nasMessage.AlgCiphering128NEA0)
	for i := range ue.KnasInt {
		ue.KnasInt[i] = byte(i + 1)
	}
	ue.UESecurityCapability = ie.UESecCapability{Length: 2, EA05G: true, IA2_128_5G: true}
	ue.State[models.AccessType_3_GPP_ACCESS].Set(amf_context.Registered)
	t.Cleanup(ue.Remove)

	conn := new(ngaptesting.SctpConnStub)
	return conn, NewAmfRan(conn), ue
}

// emergencyTestSecCtx is the UE side of the NAS security context.
func emergencyTestSecCtx(ue *amf_context.AmfUe, ul, dl *nasMessage.Count) *nasMessage.SecCtx {
	return &nasMessage.SecCtx{
		Side: nasMessage.UESide, Bearer: nasMessage.Bearer3GPP,
		UplinkCount: ul, DownlinkCount: dl,
		CipheringAlg: ie.AlgCiphering(ue.CipheringAlg), IntegrityAlg: ie.AlgIntegrity(ue.IntegrityAlg),
		KnasEnc: ue.KnasEnc, KnasInt: ue.KnasInt,
	}
}

// emergencyTestSendRegistration sends an integrity-protected REGISTRATION REQUEST
// from the UE, naming its 5G-GUTI in the NAS and its 5G-S-TMSI in NGAP.
func emergencyTestSendRegistration(t *testing.T, ran *amf_context.AmfRan, ue *amf_context.AmfUe,
	ranUeNgapID int64, regType uint8,
) {
	t.Helper()
	guti := &ie.MobileId5GS{}
	require.NoError(t, guti.FromGUTIStr(ue.Guti))
	regReq := &nasMessage.RegReq{
		RegType5GS:      &ie.RegType5GS{FOR_Pending: true, Value: regType},
		Ngksi:           &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 1},
		MobileId5GS:     guti,
		UESecCapability: &ie.UESecCapability{Length: 2, EA05G: true, IA2_128_5G: true},
	}
	ul, dl := ue.ULCount, ue.DLCount
	nasPdu, err := nasMessage.Marshal(regReq, emergencyTestSecCtx(ue, &ul, &dl),
		nasMessage.SecHdrTypeIntegrityProtected)
	require.NoError(t, err)

	msg := BuildInitialUEMessage(t, ranUeNgapID, nasPdu, fmt.Sprintf("fe00%08x", uint32(ue.Tmsi)))
	encoded, err := msg.MarshalBinary()
	require.NoError(t, err)
	handleInitialUEMessageMain(ran, encoded, msg.RANUENGAPID, msg.NASPDU, msg.UserLocationInformation,
		msg.RRCEstablishmentCause, msg.FiveGSTMSI, msg.UEContextRequest)
}

// TS 24.501 5.5.1.2.5: an emergency registration the AMF cannot serve is answered
// with REGISTRATION REJECT, and the rejected request must not start the
// registration procedure (authentication, security mode, context setup).
func TestEmergencyRegistrationIsRejected(t *testing.T) {
	conn, ran, ue := newEmergencyTestUe(t)
	ul, dl := ue.ULCount, ue.DLCount // the UE's view of the NAS COUNTs

	emergencyTestSendRegistration(t, ran, ue, 1, ie.RegType_EmergReg)

	require.Len(t, conn.MsgList, 2, "expected REGISTRATION REJECT and UE CONTEXT RELEASE COMMAND")
	decoded, err := ngapMessage.Parse(conn.MsgList[0])
	require.NoError(t, err)
	downlink, ok := decoded.(*ngapMessage.DownlinkNASTransport)
	require.True(t, ok, "first NGAP message is %T", decoded)
	nasMsg, err := nasMessage.Parse(downlink.NASPDU.Value, emergencyTestSecCtx(ue, &ul, &dl))
	require.NoError(t, err)
	reject, ok := nasMsg.(*nasMessage.RegRej)
	require.True(t, ok, "NAS message is %T", nasMsg)
	require.Equal(t, ie.Cause5GMM_ProtError, reject.Cause5GMM.Value)

	decoded, err = ngapMessage.Parse(conn.MsgList[1])
	require.NoError(t, err)
	_, ok = decoded.(*ngapMessage.UEContextReleaseCommand)
	require.True(t, ok, "second NGAP message is %T", decoded)

	// The rejected request must leave the UE in its 5GMM state: if the
	// registration went on to authentication, the FSM would reach
	// ContextSetup, which has no handling for an emergency registration, and
	// the UE's later registrations would not be answered.
	require.True(t, ue.State[models.AccessType_3_GPP_ACCESS].Is(amf_context.Registered),
		"GMM state after the reject: %s", ue.State[models.AccessType_3_GPP_ACCESS].Current())
	// The reject ended the registration procedure: no registration may stay
	// ongoing (it would make the AMF refuse N1N2 message transfers with
	// TEMPORARY_REJECT_REGISTRATION_ONGOING and handovers), and the rejected
	// request must not be kept as the UE's registration request.
	require.Equal(t, amf_context.OnGoingProcedureNothing, ue.OnGoing(models.AccessType_3_GPP_ACCESS).Procedure)
	require.Nil(t, ue.RegistrationRequest)
}
