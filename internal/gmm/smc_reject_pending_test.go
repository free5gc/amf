package gmm

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/amf/internal/nas/nas_security"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/fsm"
)

// This is a GMM/NAS component test, not a full Registration-over-SCTP test.
// It exercises a real SHT=2 NAS decode and the SecurityMode -> Deregistered
// FSM transition without starting the rest of free5GC.
func newSMCRejectTestUE(t *testing.T) (*context.AmfUe, *ngaptesting.SctpConnStub) {
	t.Helper()
	const accessType = models.AccessType_3_GPP_ACCESS
	amfSelf := context.GetSelf()
	tai := models.Tai{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, Tac: "000001"}
	oldTAIs := amfSelf.SupportTaiLists
	amfSelf.SupportTaiLists = []models.Tai{tai}
	t.Cleanup(func() { amfSelf.SupportTaiLists = oldTAIs })

	// NewAmfUe allocates a GUTI using ServedGuamiList[0].
	// Supply a test GUAMI and restore the previous global AMF configuration afterwards.
	oldGuamis := amfSelf.ServedGuamiList
	amfSelf.ServedGuamiList = []models.Guami{{
		PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"},
		AmfId:  "cafe00",
	}}
	t.Cleanup(func() { amfSelf.ServedGuamiList = oldGuamis })

	// The SecurityMode -> Deregistered transition calls
	// ClearRegistrationRequestData(), which reads AmfConfig.Configuration.
	// Preserve any existing configuration and supply an empty one only for tests
	// that do not start the AMF through its normal configuration loader.
	oldConfig := factory.AmfConfig

	if oldConfig == nil || oldConfig.Configuration == nil {
		factory.AmfConfig = &factory.Config{
			Configuration: &factory.Configuration{},
		}
	}

	t.Cleanup(func() {
		factory.AmfConfig = oldConfig
	})

	ue := amfSelf.NewAmfUe("")
	t.Cleanup(ue.Remove)
	ue.NgKsi = models.Amf_Comm_NgKsi{Tsc: models.Amf_Comm_ScType_NATIVE, Ksi: 1}
	// NEA0 keeps the inner NAS visible for checking the stub gNB's output;
	// NIA2 still exercises a real NAS integrity check.
	ue.CipheringAlg = uint8(nasMessage.AlgCiphering128NEA0)
	ue.IntegrityAlg = uint8(nasMessage.AlgIntegrity128NIA2)
	ue.KnasEnc = [16]byte{1, 2, 3, 4}
	ue.KnasInt = [16]byte{5, 6, 7, 8}
	ue.SecurityContextAvailable = true // New keys have been derived for SMC.
	ue.BeginSMC()
	ue.GmmStateEnterTime = time.Now()
	ue.State[accessType].Set(context.SecurityMode)

	conn := new(ngaptesting.SctpConnStub)
	ran := &context.AmfRan{AnType: accessType, Conn: conn, Log: logger.NgapLog}
	ue.AttachRanUe(&context.RanUe{
		Ran: ran, RanUeNgapId: 1, AmfUeNgapId: 1, Log: logger.NgapLog, Tai: tai,
	})
	return ue, conn
}

// smcRejectTestUplink builds a UE-side NAS context using exactly the pending
// keys installed in the AMF. One SecCtx is reused so the UL COUNT advances
// from the Reject to the subsequent ServiceRequest.
func smcRejectTestUplink(ue *context.AmfUe) *nasMessage.SecCtx {
	return nasMessage.NewSecCtx(
		nasMessage.UESide,
		nasMessage.Bearer3GPP,
		ie.AlgCiphering(ue.CipheringAlg),
		ie.AlgIntegrity(ue.IntegrityAlg),
		ue.KnasEnc[:], ue.KnasInt[:],
	)
}

// This is the exact core #1151 failure path at the NAS decoder/GMM FSM level:
// pending NAS keys -> SHT=2 SecurityModeReject -> Deregistered -> SHT=2
// ServiceRequest. The new keys must not authorize the ServiceRequest.
func TestSMCRejectBlocksServiceRequest(t *testing.T) {
	const accessType = models.AccessType_3_GPP_ACCESS
	ue, conn := newSMCRejectTestUE(t)
	uplink := smcRejectTestUplink(ue)

	rejectPayload, err := nasMessage.Marshal(
		&nasMessage.SecModeRej{Cause5GMM: &ie.Cause5GMM{Value: ie.Cause5GMM_SecModeRejected}},
		uplink, nasMessage.SecHdrTypeIntegrityProtectedAndCiphered,
	)
	require.NoError(t, err)
	require.Equal(t, nasMessage.SecHdrTypeIntegrityProtectedAndCiphered,
		nasMessage.GetSecHdrType(rejectPayload))

	decoded, integrityProtected, err := nas_security.Decode(ue, accessType, rejectPayload, false)
	require.NoError(t, err, "the test needs Reject to reach the SecurityMode handler")
	require.True(t, integrityProtected)
	require.IsType(t, &nasMessage.SecModeRej{}, decoded)
	ue.MacFailed = !integrityProtected

	require.NoError(t, GmmFSM.SendEvent(ue.State[accessType], GmmMessageEvent, fsm.ArgsType{
		ArgAmfUe: ue, ArgAccessType: accessType, ArgProcedureCode: int64(0),
		ArgNASMessage: decoded,
	}, logger.GmmLog))
	require.True(t, ue.State[accessType].Is(context.Deregistered))
	require.False(t, ue.IsSMCPending(), "failed SMC must end pending status")
	require.False(t, ue.SecurityContextAvailable, "failed SMC must revoke its new keys")
	require.False(t, ue.SecurityContextIsValid())

	serviceRequest := &nasMessage.SvcReq{
		Ngksi:   &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 1},
		SvcType: &ie.SvcType{Value: ie.SvcType_Signalling}, //nolint:misspell
		TMSI5GS: &ie.MobileId5GS{TypeOfId: ie.IdType_5GS_TMSI, TMSI5G: [4]byte{0, 0, 0, 1}},
	}
	servicePayload, err := nasMessage.Marshal(
		serviceRequest, uplink, nasMessage.SecHdrTypeIntegrityProtectedAndCiphered,
	)
	require.NoError(t, err)
	require.Equal(t, nasMessage.SecHdrTypeIntegrityProtectedAndCiphered,
		nasMessage.GetSecHdrType(servicePayload))

	// In the real NAS handler, a Decode error prevents dispatch into GMM.
	_, integrityProtected, err = nas_security.Decode(ue, accessType, servicePayload, false)
	require.Error(t, err, "SHT=2 ServiceRequest using rejected keys must not pass NAS decode")
	require.False(t, integrityProtected)
	require.Empty(t, conn.MsgList, "NAS decoding must not send a ServiceAccept")
}

// Defense in depth: even if a ServiceRequest somehow reaches the GMM handler,
// the pending context must not be considered an established security context.
func TestSMCPendingServiceRequestRejectedByGMM(t *testing.T) {
	const accessType = models.AccessType_3_GPP_ACCESS
	ue, conn := newSMCRejectTestUE(t)
	require.False(t, ue.SecurityContextIsValid())

	// Directly exercise the handler's security check. This deliberately bypasses
	// the NAS decoder; the previous test covers real NAS decoding.
	err := HandleServiceRequest(ue, accessType, &nasMessage.SvcReq{
		Ngksi:   &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 1},
		SvcType: &ie.SvcType{Value: ie.SvcType_Signalling}, //nolint:misspell
		TMSI5GS: &ie.MobileId5GS{TypeOfId: ie.IdType_5GS_TMSI, TMSI5G: [4]byte{0, 0, 0, 1}},
	})
	require.NoError(t, err)
	require.NotEmpty(t, conn.MsgList, "GMM should send a ServiceReject or release")

	// NEA0 makes the enclosed NAS message parseable even with a protected header.
	// A UE Context Release command has no NAS PDU and is ignored.
	foundReject := false
	for _, packet := range conn.MsgList {
		ngap, parseErr := ngapMessage.Parse(packet)
		require.NoError(t, parseErr)
		var nasPayload []byte
		switch p := ngap.(type) {
		case *ngapMessage.DownlinkNASTransport:
			if p.NASPDU != nil {
				nasPayload = p.NASPDU.Value
			}
		case *ngapMessage.InitialContextSetupRequest:
			if p.NASPDU != nil {
				nasPayload = p.NASPDU.Value
			}
		}
		if len(nasPayload) == 0 {
			continue
		}
		require.GreaterOrEqual(t, len(nasPayload), 2)
		if nasMessage.GetSecHdrType(nasPayload) != nasMessage.SecHdrTypePlainNas {
			require.GreaterOrEqual(t, len(nasPayload), 7)
			nasPayload = nasPayload[7:]
		}
		msg, parseErr := nasMessage.ParseGMM(nasPayload)
		require.NoError(t, parseErr)
		require.NotEqual(t, nasMessage.MsgTypeSvcAccept, msg.MsgType(),
			"SMC pending keys must never lead to ServiceAccept")
		if msg.MsgType() == nasMessage.MsgTypeSvcRej {
			foundReject = true
		}
	}
	require.True(t, foundReject, "GMM must send ServiceReject while SMC is pending")
}
