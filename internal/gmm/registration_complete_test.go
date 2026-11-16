package gmm

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

// Without T3550, nothing supervises the REGISTRATION ACCEPT, and its REGISTRATION COMPLETE completes the registration.
func TestRegistrationCompleteWithoutT3550(t *testing.T) {
	amfSelf := context.GetSelf()
	saved := amfSelf.T3550Cfg
	amfSelf.T3550Cfg = factory.TimerValue{Enable: false}
	t.Cleanup(func() { amfSelf.T3550Cfg = saved })
	amfSelf.ServedGuamiList = []models.Guami{{PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"}, AmfId: "cafe00"}}
	if factory.AmfConfig == nil {
		factory.AmfConfig = &factory.Config{Configuration: &factory.Configuration{}}
	} else if factory.AmfConfig.Configuration == nil {
		factory.AmfConfig.Configuration = &factory.Configuration{}
	}
	ue := amfSelf.NewAmfUe("imsi-208930000007488")
	t.Cleanup(ue.Remove)
	ran := &context.AmfRan{
		AnType: models.AccessType_3_GPP_ACCESS, Conn: new(ngaptesting.SctpConnStub), Log: logger.NgapLog,
	}
	ue.AttachRanUe(&context.RanUe{Ran: ran, RanUeNgapId: 1, AmfUeNgapId: 1, Log: logger.NgapLog})
	ue.RegistrationType5GS = ie.RegType_MobilityRegUpdating
	ue.RegistrationRequest = &nasMessage.RegReq{
		RegType5GS: &ie.RegType5GS{FOR_Pending: true, Value: ie.RegType_MobilityRegUpdating},
	}
	ue.State[models.AccessType_3_GPP_ACCESS].Set(context.ContextSetup)

	require.NoError(t, HandleRegistrationComplete(ue, models.AccessType_3_GPP_ACCESS, &nasMessage.RegComplete{}))
	require.True(t, ue.State[models.AccessType_3_GPP_ACCESS].Is(context.Registered))
}
