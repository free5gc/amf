//go:build go1.18

package nas_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	amf_nas "github.com/free5gc/amf/internal/nas"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/pkg/service"
	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

var fuzzMobileIdentity = []byte{
	0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
}

func mustMobileIdentity(tb testing.TB) ie.MobileId5GS {
	tb.Helper()
	var identity ie.MobileId5GS
	require.NoError(tb, identity.UnmarshalBinary(fuzzMobileIdentity))
	return identity
}

func mustMarshal(tb testing.TB, msg message.Message) []byte {
	tb.Helper()
	data, err := msg.MarshalBinary()
	require.NoError(tb, err)
	return data
}

func registrationRequest(tb testing.TB) []byte {
	tb.Helper()
	identity := mustMobileIdentity(tb)
	return mustMarshal(tb, &message.RegReq{
		RegType5GS:      &ie.RegType5GS{FOR_Pending: true, Value: ie.RegType_InitialReg},
		Ngksi:           &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: ie.NASKeyNA},
		MobileId5GS:     &identity,
		UESecCapability: &ie.UESecCapability{Length: 2, EA05G: true, IA2_128_5G: true},
	})
}

func setupFuzzAMF() (*amf_context.AMFContext, models.Tai) {
	amfSelf := amf_context.GetSelf()
	amfSelf.ServedGuamiList = []models.Guami{{
		PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"},
		AmfId:  "cafe00",
	}}
	tai := models.Tai{
		PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"},
		Tac:    "1",
	}
	amfSelf.SupportTaiLists = []models.Tai{tai}
	return amfSelf, tai
}

func newFuzzRanUe(amfSelf *amf_context.AMFContext, tai models.Tai) *amf_context.RanUe {
	ue := &amf_context.RanUe{
		Ran: &amf_context.AmfRan{
			AnType: models.AccessType_3_GPP_ACCESS,
			Log:    logger.NgapLog,
		},
		Log: logger.NgapLog,
		Tai: tai,
	}
	ue.SetAmfUe(amfSelf.NewAmfUe(""))
	return ue
}

func FuzzHandleNAS(f *testing.F) {
	amfSelf, tai := setupFuzzAMF()
	f.Add(registrationRequest(f))

	identity := mustMobileIdentity(f)
	f.Add(mustMarshal(f, &message.DeregReqUEOrig{
		DeregType:   &ie.DeregType{AccessType: ie.AccessType_3gpp},
		Ngksi:       &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: ie.NASKeyNA},
		MobileId5GS: &identity,
	}))

	serviceRequest := mustMarshal(f, &message.SvcReq{
		Ngksi: &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative},
		// This spelling is the name exported by the NAS API.
		SvcType: &ie.SvcType{Value: ie.SvcType_Signalling}, //nolint:misspell
		TMSI5GS: &ie.MobileId5GS{TypeOfId: ie.IdType_5GS_TMSI},
	})
	f.Add(append([]byte{
		byte(message.Epd5GSMobilityMgmtMsg),
		byte(message.SecHdrTypeIntegrityProtected),
		0, 0, 0, 0, 0,
	}, serviceRequest...))

	f.Fuzz(func(t *testing.T, data []byte) {
		ue := newFuzzRanUe(amfSelf, tai)
		amf_nas.HandleNAS(ue, ngapMessage.ProcedureCodeInitialUEMessage, data, true)
	})
}

func FuzzHandleNAS2(f *testing.F) {
	amfSelf, tai := setupFuzzAMF()
	amfSelf.NrfUri = "test"
	registrationPacket := registrationRequest(f)

	identity := mustMobileIdentity(f)
	f.Add(mustMarshal(f, &message.IdRsp{MobileId: &identity}))
	f.Add(mustMarshal(f, &message.AuthRsp{
		AuthRspParam: &ie.AuthRspParam{Res: make([]byte, 16)},
	}))
	f.Add(mustMarshal(f, &message.AuthFailure{
		Cause5GMM:        &ie.Cause5GMM{Value: ie.Cause5GMM_SynchFailure},
		AuthFailureParam: &ie.AuthFailureParam{Value: make([]byte, 14)},
	}))
	f.Add(mustMarshal(f, &message.Status5GMM{
		Cause5GMM: &ie.Cause5GMM{Value: ie.Cause5GMM_ProtError},
	}))

	f.Fuzz(func(t *testing.T, data []byte) {
		ctrl := gomock.NewController(t)
		app := service.NewMockAmfAppInterface(ctrl)
		c, err := consumer.NewConsumer(app)
		service.AMF = app
		require.NoError(t, err)
		app.EXPECT().Consumer().AnyTimes().Return(c)

		ue := newFuzzRanUe(amfSelf, tai)
		amf_nas.HandleNAS(ue, ngapMessage.ProcedureCodeInitialUEMessage, registrationPacket, true)
		amfUe := ue.GetAmfUe()
		amfUe.State[models.AccessType_3_GPP_ACCESS].Set(amf_context.Authentication)
		amfUe.RequestIdentityType = ie.IdType_5GS_SUCI
		amfUe.AuthenticationCtx = &models.Ausf_UEAU_UEAuthenticationCtx{
			AuthType: models.Ausf_UEAU_AuthType_5_G_AKA,
		}
		amf_nas.HandleNAS(ue, ngapMessage.ProcedureCodeUplinkNASTransport, data, false)
	})
}
