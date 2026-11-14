package gmm

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	gmm_message "github.com/free5gc/amf/internal/gmm/message"
	"github.com/free5gc/amf/internal/logger"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

var gutiTestTai = models.Tai{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, Tac: "000001"}

// newGutiTestUe returns a UE with a 5G NAS security context (NIA0, NEA0) and an
// N2 connection over a stub gNB. A registered UE has already received its
// 5G-GUTI in the REGISTRATION ACCEPT of its initial registration.
func newGutiTestUe(t *testing.T, registered bool) *context.AmfUe {
	t.Helper()
	amfSelf := context.GetSelf()
	amfSelf.ServedGuamiList = []models.Guami{{PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"}, AmfId: "cafe00"}}
	amfSelf.SupportTaiLists = []models.Tai{gutiTestTai}
	amfSelf.T3550Cfg = factory.TimerValue{Enable: true, ExpireTime: time.Hour, MaxRetryTimes: 4}
	if factory.AmfConfig == nil {
		factory.AmfConfig = &factory.Config{Configuration: &factory.Configuration{}}
	} else if factory.AmfConfig.Configuration == nil {
		factory.AmfConfig.Configuration = &factory.Configuration{}
	}

	ue := amfSelf.NewAmfUe("imsi-208930000007487")
	ue.SecurityContextAvailable = true
	ue.NgKsi = models.Amf_Comm_NgKsi{Tsc: models.Amf_Comm_ScType_NATIVE, Ksi: 1}
	t.Cleanup(ue.Remove)
	gutiTestConnect(ue, 1)
	if registered {
		suci := &ie.MobileId5GS{}
		require.NoError(t, suci.UnmarshalBinary([]byte{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0, 0, 0, 0, 0x47, 0x78}))
		ue.RegistrationType5GS = ie.RegType_InitialReg
		ue.RegistrationRequest = &nasMessage.RegReq{
			RegType5GS:  &ie.RegType5GS{FOR_Pending: true, Value: ie.RegType_InitialReg},
			Ngksi:       &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 1},
			MobileId5GS: suci,
		}
		sendGutiTestAccept(ue)
		ue.State[models.AccessType_3_GPP_ACCESS].Set(context.Registered)
	}
	return ue
}

func gutiTestConnect(ue *context.AmfUe, id int64) {
	ran := &context.AmfRan{
		AnType: models.AccessType_3_GPP_ACCESS, Conn: new(ngaptesting.SctpConnStub), Log: logger.NgapLog,
	}
	ue.AttachRanUe(&context.RanUe{Ran: ran, RanUeNgapId: id, AmfUeNgapId: id, Log: logger.NgapLog, Tai: gutiTestTai})
}

func gutiTestRegistrationRequest(t *testing.T, regType uint8, guti string) *nasMessage.RegReq {
	t.Helper()
	identity := &ie.MobileId5GS{}
	require.NoError(t, identity.FromGUTIStr(guti))
	return &nasMessage.RegReq{
		RegType5GS:  &ie.RegType5GS{FOR_Pending: true, Value: regType},
		Ngksi:       &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 1},
		MobileId5GS: identity,
	}
}

// gutiTestAccept runs the accept of a mobility registration in which the UE
// named guti.
func gutiTestAccept(t *testing.T, ue *context.AmfUe, guti string) {
	t.Helper()
	ue.RegistrationType5GS = ie.RegType_MobilityRegUpdating
	ue.RegistrationRequest = gutiTestRegistrationRequest(t, ie.RegType_MobilityRegUpdating, guti)
	sendGutiTestAccept(ue)
}

func sendGutiTestAccept(ue *context.AmfUe) {
	gmm_message.SendRegistrationAccept(ue, models.AccessType_3_GPP_ACCESS, nil, nil, nil, nil, nil)
	ue.StopT3550() // T3550 is not under test
}

func gutiResolves(guti string) bool {
	_, ok := context.GetSelf().AmfUeFindByGuti(guti)
	return ok
}

// TS 24.501 5.3.3: the UE's 5G-GUTI stays valid when its registration request is
// rejected. Before the change the AMF replaced the 5G-GUTI while it parsed the
// request, so the UE's retry with its own 5G-GUTI was rejected with #10.
func TestRejectedRegistrationKeepsGuti(t *testing.T) {
	ue := newGutiTestUe(t, true)
	guti := ue.Guti

	// The request lacks the mandatory UE security capability: REGISTRATION REJECT #111.
	err := HandleRegistrationRequest(ue, models.AccessType_3_GPP_ACCESS, 0,
		gutiTestRegistrationRequest(t, ie.RegType_MobilityRegUpdating, guti))

	require.Error(t, err)
	require.Equal(t, guti, ue.Guti)
	found, ok := context.GetSelf().AmfUeFindByGuti(guti)
	require.True(t, ok, "the UE's 5G-GUTI no longer resolves to its context")
	require.Same(t, ue, found)
}

// TS 24.501 5.5.1.3.8 a): after a REGISTRATION ACCEPT with a new 5G-GUTI, both
// the old and the new 5G-GUTI are valid until REGISTRATION COMPLETE.
func TestRegistrationAcceptKeepsOldGutiUntilComplete(t *testing.T) {
	ue := newGutiTestUe(t, true)
	guti1 := ue.Guti

	gutiTestAccept(t, ue, guti1)
	guti2 := ue.Guti
	require.NotEqual(t, guti1, guti2, "the REGISTRATION ACCEPT carries a new 5G-GUTI")
	require.True(t, gutiResolves(guti1))
	require.True(t, gutiResolves(guti2))

	ue.T3550 = context.NewTimer(time.Hour, 4, func(int32) {}, func() {})
	ue.State[models.AccessType_3_GPP_ACCESS].Set(context.ContextSetup)
	require.NoError(t, HandleRegistrationComplete(ue, models.AccessType_3_GPP_ACCESS, &nasMessage.RegComplete{}))
	require.False(t, gutiResolves(guti1), "the old 5G-GUTI is still valid after REGISTRATION COMPLETE")
	require.True(t, gutiResolves(guti2))
}

// TS 24.501 5.5.1.3.8 a): the UE received the new 5G-GUTI but its REGISTRATION
// COMPLETE was lost. Its next registration uses the new 5G-GUTI, so the old one
// becomes invalid, and the 5G-GUTI the UE holds stays valid until the next
// REGISTRATION COMPLETE even if that ACCEPT is lost too.
func TestUnacknowledgedGutiUsedByUeStaysValid(t *testing.T) {
	ue := newGutiTestUe(t, true)
	guti1 := ue.Guti
	gutiTestAccept(t, ue, guti1)
	guti2 := ue.Guti

	gutiTestAccept(t, ue, guti2)
	guti3 := ue.Guti

	require.NotEqual(t, guti2, guti3)
	require.True(t, gutiResolves(guti2), "the 5G-GUTI the UE holds no longer resolves")
	require.True(t, gutiResolves(guti3))
	require.False(t, gutiResolves(guti1), "the 5G-GUTI the UE replaced is still valid")
}

// The UE never received the new 5G-GUTI and registers again with the old one:
// the old 5G-GUTI stays valid and the unacknowledged one is released.
func TestUnacknowledgedGutiNotReceivedByUeIsReleased(t *testing.T) {
	ue := newGutiTestUe(t, true)
	guti1 := ue.Guti
	gutiTestAccept(t, ue, guti1)
	guti2 := ue.Guti

	gutiTestAccept(t, ue, guti1)
	guti3 := ue.Guti

	require.True(t, gutiResolves(guti1), "the 5G-GUTI the UE holds no longer resolves")
	require.True(t, gutiResolves(guti3))
	require.False(t, gutiResolves(guti2), "the 5G-GUTI the UE never received is still allocated")
}

// TS 24.501 5.5.1.3.8 a): once the UE uses the new 5G-GUTI in a subsequent
// message, the old 5G-GUTI is invalid.
func TestServiceRequestWithNewGutiReleasesOldGuti(t *testing.T) {
	ue := newGutiTestUe(t, true)
	guti1 := ue.Guti
	gutiTestAccept(t, ue, guti1)
	guti2 := ue.Guti

	sTmsi := &ie.MobileId5GS{}
	require.NoError(t, sTmsi.UnmarshalBinary(append([]byte{0xf4, 0xfe, 0x00},
		byte(ue.Tmsi>>24), byte(ue.Tmsi>>16), byte(ue.Tmsi>>8), byte(ue.Tmsi))))
	require.NoError(t, HandleServiceRequest(ue, models.AccessType_3_GPP_ACCESS, &nasMessage.SvcReq{
		Ngksi:   &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 1},
		SvcType: &ie.SvcType{Value: ie.SvcType_Signalling}, //nolint:misspell // NAS API name
		TMSI5GS: sTmsi,
	}))

	require.False(t, gutiResolves(guti1), "the old 5G-GUTI is still valid after the UE used the new one")
	require.True(t, gutiResolves(guti2))
}

// TS 24.501 5.3.3 a): a successful initial registration assigns a new 5G-GUTI,
// also when the UE was found by its 5G-GUTI on an existing context; the old one
// stays valid until REGISTRATION COMPLETE.
func TestInitialRegistrationOnExistingContextGetsNewGuti(t *testing.T) {
	ue := newGutiTestUe(t, true)
	guti1 := ue.Guti

	ue.RegistrationType5GS = ie.RegType_InitialReg
	ue.RegistrationRequest = gutiTestRegistrationRequest(t, ie.RegType_InitialReg, guti1)
	sendGutiTestAccept(ue)

	require.NotEqual(t, guti1, ue.Guti)
	require.True(t, gutiResolves(guti1))
	require.True(t, gutiResolves(ue.Guti))
}

// A context created for this registration already holds a 5G-GUTI that was never
// sent; the REGISTRATION ACCEPT assigns it instead of allocating another one.
func TestNewContextGutiIsAssigned(t *testing.T) {
	ue := newGutiTestUe(t, false)
	guti := ue.Guti

	ue.RegistrationType5GS = ie.RegType_InitialReg
	ue.RegistrationRequest = gutiTestRegistrationRequest(t, ie.RegType_InitialReg, "20893cafe00ffffffff")
	sendGutiTestAccept(ue)

	require.Equal(t, guti, ue.Guti)
}
