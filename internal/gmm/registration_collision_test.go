package gmm

import (
	"encoding/hex"
	"fmt"
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
	"github.com/free5gc/util/fsm"
)

// Plain REGISTRATION REQUESTs for an initial registration by a 5G-GUTI of PLMN 208 93 and AMF ID cafe00, with the
// 5G-TMSIs fffffffe and fffffffd, and the follow-on request pending. The last one is for a mobility registration
// update, without a follow-on request.
const (
	registrationRequestByGuti         = "7e004179000bf202f839cafe00fffffffe2e02f0f0"
	otherRegistrationRequestByGuti    = "7e004179000bf202f839cafe00fffffffd2e02f0f0"
	mobilityRegistrationRequestByGuti = "7e004172000bf202f839cafe00fffffffe2e02f0f0"
)

// notSwitchOff is a DEREGISTRATION REQUEST not for switch off.
func notSwitchOff() *nasMessage.DeregReqUEOrig {
	return &nasMessage.DeregReqUEOrig{
		DeregType: &ie.DeregType{AccessType: ie.AccessType_3gpp},
		Ngksi:     &ie.NASKeySetId{Ksi: ie.NASKeyNA},
	}
}

// sentNames returns the type of each NGAP message that the AMF has sent to the gNB, or of its NAS message for a
// DOWNLINK NAS TRANSPORT.
func sentNames(t *testing.T, conn *ngaptesting.SctpConnStub) []string {
	t.Helper()
	var names []string
	for i := range conn.MsgList {
		decoded := sent(t, conn, i)
		if transport, ok := decoded.(*ngapMessage.DownlinkNASTransport); ok {
			msg, err := nasMessage.ParseGMM(transport.NASPDU.Value)
			require.NoError(t, err)
			names = append(names, fmt.Sprintf("%T", msg))
		} else {
			names = append(names, fmt.Sprintf("%T", decoded))
		}
	}
	return names
}

// sent returns the i-th NGAP message that the AMF has sent to the gNB.
func sent(t *testing.T, conn *ngaptesting.SctpConnStub, i int) ngapMessage.Message {
	t.Helper()
	decoded, err := ngapMessage.Parse(conn.MsgList[i])
	require.NoError(t, err)
	return decoded
}

// nas returns the NAS message of a DOWNLINK NAS TRANSPORT.
func nas(t *testing.T, decoded ngapMessage.Message) nasMessage.Message {
	t.Helper()
	transport, ok := decoded.(*ngapMessage.DownlinkNASTransport)
	require.True(t, ok, "sent %T, not a Downlink NAS Transport", decoded)
	msg, err := nasMessage.ParseGMM(transport.NASPDU.Value)
	require.NoError(t, err)
	return msg
}

func registrationRequest(t *testing.T, value string) *nasMessage.RegReq {
	t.Helper()
	b, err := hex.DecodeString(value)
	require.NoError(t, err)
	msg, err := nasMessage.ParseGMM(b)
	require.NoError(t, err)
	registrationRequest, ok := msg.(*nasMessage.RegReq)
	require.True(t, ok)
	return registrationRequest
}

// registeringUe returns a UE in the given state of a registration by registrationRequestByGuti, without a security
// context, on a gNB whose NGAP messages the test reads.
func registeringUe(t *testing.T, state fsm.StateType) (*context.AmfUe, *ngaptesting.SctpConnStub) {
	t.Helper()
	amfSelf := context.GetSelf()
	tai := models.Tai{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, Tac: "000001"}
	savedGuamis, savedTais, savedT3570 := amfSelf.ServedGuamiList, amfSelf.SupportTaiLists, amfSelf.T3570Cfg
	amfSelf.ServedGuamiList = []models.Guami{{PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"}, AmfId: "cafe00"}}
	amfSelf.SupportTaiLists = []models.Tai{tai}
	amfSelf.T3570Cfg = factory.TimerValue{Enable: false}
	t.Cleanup(func() {
		amfSelf.ServedGuamiList, amfSelf.SupportTaiLists, amfSelf.T3570Cfg = savedGuamis, savedTais, savedT3570
	})
	if factory.AmfConfig == nil {
		factory.AmfConfig = &factory.Config{Configuration: &factory.Configuration{}}
	} else if factory.AmfConfig.Configuration == nil {
		factory.AmfConfig.Configuration = &factory.Configuration{}
	}

	ue := amfSelf.NewAmfUe("")
	conn := new(ngaptesting.SctpConnStub)
	ran := &context.AmfRan{AnType: models.AccessType_3_GPP_ACCESS, Conn: conn, Log: logger.NgapLog}
	ranUe := &context.RanUe{Ran: ran, RanUeNgapId: 1, AmfUeNgapId: 1, Tai: tai, Log: logger.NgapLog}
	ue.AttachRanUe(ranUe)
	ue.RegistrationRequest = registrationRequest(t, registrationRequestByGuti)
	ue.RegistrationType5GS = ie.RegType_InitialReg
	ue.State[models.AccessType_3_GPP_ACCESS].Set(state)
	return ue, conn
}

// runningTimer returns a timer that does not expire during a test and hands each call of its expiredFunc over a
// channel.
func runningTimer(t *testing.T) (*context.Timer, chan int32) {
	t.Helper()
	expired := make(chan int32, 4)
	timer := context.NewTimer(time.Hour, 4, func(expireTimes int32) { expired <- expireTimes }, func() {})
	return timer, expired
}

func sendGmmMessage(t *testing.T, ue *context.AmfUe, msg nasMessage.Message) {
	t.Helper()
	require.NoError(t, GmmFSM.SendEvent(ue.State[models.AccessType_3_GPP_ACCESS], GmmMessageEvent, fsm.ArgsType{
		ArgAmfUe:         ue,
		ArgAccessType:    models.AccessType_3_GPP_ACCESS,
		ArgNASMessage:    msg,
		ArgProcedureCode: int64(0),
	}, logger.GmmLog))
}

// TS 24.501 5.5.1.2.8 d) 2): a REGISTRATION REQUEST that does not differ, after the REGISTRATION ACCEPT, has the
// accept resent and T3550 restarted, its retransmission counter not incremented. TS 24.501 4.4.6: when the UE sends
// the request in a NAS message container, the request compared is the one of the container.
func TestRegistrationRequestAgainAfterAcceptResendsAccept(t *testing.T) {
	inContainer := registrationRequest(t, registrationRequestByGuti)
	contents, err := hex.DecodeString(registrationRequestByGuti)
	require.NoError(t, err)
	inContainer.NASMsgCntr = &ie.NASMsgCntr{Contents: contents} // ciphered by 5G-EA0

	for name, request := range map[string]*nasMessage.RegReq{
		"plain":                    registrationRequest(t, registrationRequestByGuti),
		"in NAS message container": inContainer,
	} {
		t.Run(name, func(t *testing.T) {
			ue, conn := registeringUe(t, context.ContextSetup)
			t3550, resent := runningTimer(t)
			ue.T3550 = t3550
			t.Cleanup(func() { ue.StopT3550() })

			sendGmmMessage(t, ue, request)

			select {
			case expireTimes := <-resent:
				require.EqualValues(t, 0, expireTimes)
			case <-time.After(2 * time.Second):
				t.Fatal("the registration accept is not resent")
			}
			require.Same(t, t3550, ue.T3550)
			require.EqualValues(t, 0, ue.T3550.ExpireTimes())
			require.True(t, ue.State[models.AccessType_3_GPP_ACCESS].Is(context.ContextSetup))
			require.Empty(t, conn.MsgList)
		})
	}
}

// TS 24.501 5.5.1.2.8 h): a DEREGISTRATION REQUEST before the REGISTRATION COMPLETE aborts the registration for
// initial registration and the de-registration is progressed.
func TestDeregistrationRequestBeforeRegistrationCompleteIsProgressed(t *testing.T) {
	ue, conn := registeringUe(t, context.ContextSetup)
	t3550, resent := runningTimer(t)
	ue.T3550 = t3550

	sendGmmMessage(t, ue, &nasMessage.DeregReqUEOrig{
		DeregType: &ie.DeregType{AccessType: ie.AccessType_3gpp},
		Ngksi:     &ie.NASKeySetId{Ksi: ie.NASKeyNA},
	})

	require.Len(t, conn.MsgList, 2)
	_, ok := nas(t, sent(t, conn, 0)).(*nasMessage.DeregAcceptUEOrig)
	require.True(t, ok, "the deregistration request is not accepted")
	_, ok = sent(t, conn, 1).(*ngapMessage.UEContextReleaseCommand)
	require.True(t, ok)
	require.Nil(t, ue.T3550)
	require.True(t, ue.State[models.AccessType_3_GPP_ACCESS].Is(context.Deregistered))
	require.Empty(t, resent)
}

// TS 24.501 5.5.1.3.8 g): a DEREGISTRATION REQUEST before the REGISTRATION COMPLETE of a mobility registration aborts
// it for switch off only; otherwise the registration goes on.
func TestDeregistrationRequestBeforeMobilityRegistrationComplete(t *testing.T) {
	t.Run("switch off", func(t *testing.T) {
		ue, conn := registeringUe(t, context.ContextSetup)
		ue.RegistrationType5GS = ie.RegType_MobilityRegUpdating
		t3550, _ := runningTimer(t)
		ue.T3550 = t3550

		sendGmmMessage(t, ue, &nasMessage.DeregReqUEOrig{
			DeregType: &ie.DeregType{Switchoff: true, AccessType: ie.AccessType_3gpp},
			Ngksi:     &ie.NASKeySetId{Ksi: ie.NASKeyNA},
		})

		require.Len(t, conn.MsgList, 1)
		_, ok := sent(t, conn, 0).(*ngapMessage.UEContextReleaseCommand)
		require.True(t, ok, "a switch-off deregistration is answered")
		require.Nil(t, ue.T3550)
		require.True(t, ue.State[models.AccessType_3_GPP_ACCESS].Is(context.Deregistered))
	})

	t.Run("not switch off", func(t *testing.T) {
		ue, conn := registeringUe(t, context.ContextSetup)
		// Without a follow-on request, the completion alone would release the connection
		ue.RegistrationRequest = registrationRequest(t, mobilityRegistrationRequestByGuti)
		ue.RegistrationType5GS = ie.RegType_MobilityRegUpdating
		t3550, _ := runningTimer(t)
		ue.T3550 = t3550
		t.Cleanup(func() { ue.StopT3550() })

		sendGmmMessage(t, ue, &nasMessage.DeregReqUEOrig{
			DeregType: &ie.DeregType{AccessType: ie.AccessType_3gpp},
			Ngksi:     &ie.NASKeySetId{Ksi: ie.NASKeyNA},
		})

		require.Empty(t, conn.MsgList)
		require.Same(t, t3550, ue.T3550)
		require.True(t, ue.State[models.AccessType_3_GPP_ACCESS].Is(context.ContextSetup))

		// The registration completes, and the de-registration is progressed then
		sendGmmMessage(t, ue, &nasMessage.RegComplete{})

		// The UE has no security context here, so no CONFIGURATION UPDATE COMMAND is sent, and the de-registration
		// releases the connection, not the completion
		require.Equal(t, []string{"*message.DeregAcceptUEOrig", "*message.UEContextReleaseCommand"},
			sentNames(t, conn))
		require.Nil(t, ue.DeferredDeregistrationRequest)
		require.True(t, ue.State[models.AccessType_3_GPP_ACCESS].Is(context.Deregistered))
	})
}

// TS 24.501 5.4.3.6 f): a DEREGISTRATION REQUEST not for switch off during an identification lets the identification
// complete, and the de-registration is progressed then.
func TestDeregistrationRequestDuringIdentificationIsProgressedAfterIt(t *testing.T) {
	ue, conn := registeringUe(t, context.Authentication)
	t3570, _ := runningTimer(t)
	ue.T3570 = t3570
	ue.RequestIdentityType = ie.IdType_5GS_SUCI
	t.Cleanup(ue.StopT3570)

	sendGmmMessage(t, ue, &nasMessage.DeregReqUEOrig{
		DeregType: &ie.DeregType{AccessType: ie.AccessType_3gpp},
		Ngksi:     &ie.NASKeySetId{Ksi: ie.NASKeyNA},
	})

	require.Empty(t, conn.MsgList)
	require.Same(t, t3570, ue.T3570)
	require.True(t, ue.State[models.AccessType_3_GPP_ACCESS].Is(context.Authentication))

	// An IDENTITY RESPONSE with a SUCI of the null scheme, of PLMN 208 93.
	b, err := hex.DecodeString("7e005c000c0102f839f0ff000000004778")
	require.NoError(t, err)
	identityResponse, err := nasMessage.ParseGMM(b)
	require.NoError(t, err)
	sendGmmMessage(t, ue, identityResponse)

	require.Len(t, conn.MsgList, 2)
	_, ok := nas(t, sent(t, conn, 0)).(*nasMessage.DeregAcceptUEOrig)
	require.True(t, ok, "the deregistration request is not accepted")
	_, ok = sent(t, conn, 1).(*ngapMessage.UEContextReleaseCommand)
	require.True(t, ok)
	require.Nil(t, ue.T3570)
	require.True(t, ue.State[models.AccessType_3_GPP_ACCESS].Is(context.Deregistered))
}

// TS 24.501 5.4.3.6 f): the same holds for the identification of the IMEI that a registration starts after the
// security mode control.
func TestDeregistrationRequestDuringIMEIIdentificationIsProgressedAfterIt(t *testing.T) {
	ue, conn := registeringUe(t, context.ContextSetup)
	t3570, _ := runningTimer(t)
	ue.T3570 = t3570
	ue.RequestIdentityType = ie.IdType_5GS_IMEI
	t.Cleanup(ue.StopT3570)

	sendGmmMessage(t, ue, notSwitchOff())

	require.Empty(t, conn.MsgList)
	require.NotNil(t, ue.DeferredDeregistrationRequest, "the de-registration is neither deferred nor answered")
	require.Same(t, t3570, ue.T3570)
	require.True(t, ue.State[models.AccessType_3_GPP_ACCESS].Is(context.ContextSetup))

	// An IDENTITY RESPONSE with the IMEI 356938035643809.
	b, err := hex.DecodeString("7e005c00083b65390853468390")
	require.NoError(t, err)
	identityResponse, err := nasMessage.ParseGMM(b)
	require.NoError(t, err)
	sendGmmMessage(t, ue, identityResponse)

	require.Equal(t, "imei-356938035643809", ue.Pei)
	require.Equal(t, []string{"*message.DeregAcceptUEOrig", "*message.UEContextReleaseCommand"}, sentNames(t, conn))
	require.Nil(t, ue.T3570)
	require.Nil(t, ue.DeferredDeregistrationRequest)
	require.True(t, ue.State[models.AccessType_3_GPP_ACCESS].Is(context.Deregistered))
}

// A REGISTRATION REQUEST that differs, during an identification, starts a new registration, which does not progress
// the DEREGISTRATION REQUEST that came during the first one.
func TestNewRegistrationRequestForgetsDeferredDeregistration(t *testing.T) {
	ue, _ := registeringUe(t, context.Authentication)
	t3570, _ := runningTimer(t)
	ue.T3570 = t3570
	ue.RequestIdentityType = ie.IdType_5GS_SUCI

	sendGmmMessage(t, ue, notSwitchOff())
	require.NotNil(t, ue.DeferredDeregistrationRequest)

	sendGmmMessage(t, ue, registrationRequest(t, otherRegistrationRequestByGuti))

	require.Nil(t, ue.DeferredDeregistrationRequest)
	require.True(t, ue.State[models.AccessType_3_GPP_ACCESS].Is(context.Authentication))
}

// The DEREGISTRATION REQUEST that waits for a procedure of the registration is cleared with the other registration
// data, as entering 5GMM-REGISTERED or 5GMM-DEREGISTERED does.
func TestRegistrationRequestDataIncludesDeferredDeregistration(t *testing.T) {
	ue, _ := registeringUe(t, context.ContextSetup)
	ue.DeferredDeregistrationRequest = notSwitchOff()

	ue.ClearRegistrationRequestData(models.AccessType_3_GPP_ACCESS)

	require.Nil(t, ue.DeferredDeregistrationRequest)
}

// TS 24.501 5.4.2.7 c): a DEREGISTRATION REQUEST not for switch off during the security mode control aborts it and
// the de-registration is progressed.
func TestDeregistrationRequestDuringSecurityModeControlIsProgressed(t *testing.T) {
	ue, conn := registeringUe(t, context.SecurityMode)
	t3560, retransmitted := runningTimer(t)
	ue.T3560 = t3560

	sendGmmMessage(t, ue, &nasMessage.DeregReqUEOrig{
		DeregType: &ie.DeregType{AccessType: ie.AccessType_3gpp},
		Ngksi:     &ie.NASKeySetId{Ksi: ie.NASKeyNA},
	})

	require.Len(t, conn.MsgList, 2)
	_, ok := nas(t, sent(t, conn, 0)).(*nasMessage.DeregAcceptUEOrig)
	require.True(t, ok, "the deregistration request is not accepted")
	_, ok = sent(t, conn, 1).(*ngapMessage.UEContextReleaseCommand)
	require.True(t, ok)
	require.Nil(t, ue.T3560)
	require.True(t, ue.State[models.AccessType_3_GPP_ACCESS].Is(context.Deregistered))
	require.Empty(t, retransmitted)
}

// TS 24.501 5.4.3.6 f): a DEREGISTRATION REQUEST for switch off during an identification aborts it and the
// de-registration is progressed, with no DEREGISTRATION ACCEPT.
func TestSwitchOffDeregistrationAbortsIdentification(t *testing.T) {
	ue, conn := registeringUe(t, context.Authentication)
	t3570, retransmitted := runningTimer(t)
	ue.T3570 = t3570

	sendGmmMessage(t, ue, &nasMessage.DeregReqUEOrig{
		DeregType: &ie.DeregType{Switchoff: true, AccessType: ie.AccessType_3gpp},
		Ngksi:     &ie.NASKeySetId{Ksi: ie.NASKeyNA},
	})

	require.Len(t, conn.MsgList, 1)
	_, ok := sent(t, conn, 0).(*ngapMessage.UEContextReleaseCommand)
	require.True(t, ok, "a switch-off deregistration is answered")
	require.Nil(t, ue.T3570)
	require.True(t, ue.State[models.AccessType_3_GPP_ACCESS].Is(context.Deregistered))
	require.Empty(t, retransmitted)
}

// TS 24.501 5.4.3.6 d): a REGISTRATION REQUEST that does not differ, during the identification that a registration
// started, is not treated any further.
func TestRegistrationRequestAgainDuringIdentificationIsIgnored(t *testing.T) {
	ue, conn := registeringUe(t, context.Authentication)
	t3570, _ := runningTimer(t)
	ue.T3570 = t3570
	t.Cleanup(ue.StopT3570)

	sendGmmMessage(t, ue, registrationRequest(t, registrationRequestByGuti))

	require.Empty(t, conn.MsgList)
	require.Same(t, t3570, ue.T3570)
	require.True(t, ue.State[models.AccessType_3_GPP_ACCESS].Is(context.Authentication))
}

// TS 24.501 5.4.3.6 d): a REGISTRATION REQUEST that differs, during the identification that a registration started,
// aborts it and the new registration is progressed: here its own identification.
func TestNewRegistrationRequestDuringIdentificationIsProgressed(t *testing.T) {
	ue, conn := registeringUe(t, context.Authentication)
	t3570, retransmitted := runningTimer(t)
	ue.T3570 = t3570
	newRequest := registrationRequest(t, otherRegistrationRequestByGuti)

	sendGmmMessage(t, ue, newRequest)

	require.Len(t, conn.MsgList, 1)
	identityRequest, ok := nas(t, sent(t, conn, 0)).(*nasMessage.IdReq)
	require.True(t, ok, "the new registration is not progressed")
	require.Equal(t, ie.IdType_5GS_SUCI, identityRequest.IdType.IdType)
	require.Nil(t, ue.T3570, "the first identification goes on")
	require.Same(t, newRequest, ue.RegistrationRequest)
	require.True(t, ue.State[models.AccessType_3_GPP_ACCESS].Is(context.Authentication))
	require.Empty(t, retransmitted)
}

// TS 24.501 5.4.2.7 c), 5.5.1.2.8 d) 1): a REGISTRATION REQUEST that differs, during the security mode control or
// after the REGISTRATION ACCEPT, aborts the ongoing procedure and the new registration is progressed: here its
// identification.
func TestNewRegistrationRequestDuringRegistrationIsProgressed(t *testing.T) {
	for name, state := range map[string]fsm.StateType{
		"during the security mode control": context.SecurityMode,
		"after the registration accept":    context.ContextSetup,
	} {
		t.Run(name, func(t *testing.T) {
			ue, conn := registeringUe(t, state)
			timer, retransmitted := runningTimer(t)
			if state == context.SecurityMode {
				ue.T3560 = timer
			} else {
				ue.T3550 = timer
			}
			newRequest := registrationRequest(t, otherRegistrationRequestByGuti)

			sendGmmMessage(t, ue, newRequest)

			require.Len(t, conn.MsgList, 1)
			identityRequest, ok := nas(t, sent(t, conn, 0)).(*nasMessage.IdReq)
			require.True(t, ok, "the new registration is not progressed")
			require.Equal(t, ie.IdType_5GS_SUCI, identityRequest.IdType.IdType)
			require.Nil(t, ue.T3560, "the security mode control goes on")
			require.Nil(t, ue.T3550, "the registration accept is still retransmitted")
			require.Same(t, newRequest, ue.RegistrationRequest)
			require.True(t, ue.State[models.AccessType_3_GPP_ACCESS].Is(context.Authentication))
			require.Empty(t, retransmitted)
		})
	}
}

// TS 24.501 5.4.2.7 c): a REGISTRATION REQUEST that does not differ, during the security mode control of the
// registration that it started, does not abort it.
func TestRegistrationRequestAgainDuringSecurityModeControlIsIgnored(t *testing.T) {
	ue, conn := registeringUe(t, context.SecurityMode)
	t3560, _ := runningTimer(t)
	ue.T3560 = t3560
	t.Cleanup(ue.StopT3560)

	sendGmmMessage(t, ue, registrationRequest(t, registrationRequestByGuti))

	require.Empty(t, conn.MsgList)
	require.Same(t, t3560, ue.T3560)
	require.True(t, ue.State[models.AccessType_3_GPP_ACCESS].Is(context.SecurityMode))
}
