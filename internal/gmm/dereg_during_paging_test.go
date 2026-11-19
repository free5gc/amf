package gmm

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

// TS 24.501 5.6.2.2.1: a DEREGISTRATION REQUEST that answers a paging and passed the integrity check stops T3513;
// one that failed the integrity check keeps T3513 running.
func TestDeregistrationOfPagedUeStopsPaging(t *testing.T) {
	const anType = models.AccessType_3_GPP_ACCESS
	amfSelf := context.GetSelf()
	savedGuamis, savedConfig := amfSelf.ServedGuamiList, factory.AmfConfig
	t.Cleanup(func() { amfSelf.ServedGuamiList, factory.AmfConfig = savedGuamis, savedConfig })
	amfSelf.ServedGuamiList = []models.Guami{{PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"}, AmfId: "cafe00"}}
	factory.AmfConfig = &factory.Config{Configuration: &factory.Configuration{}}

	for _, tc := range []struct {
		name      string
		macFailed bool
	}{
		{name: "integrity check passed", macFailed: false},
		{name: "integrity check failed", macFailed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ue := amfSelf.NewAmfUe("")
			t.Cleanup(ue.Remove)
			ran := &context.AmfRan{AnType: anType, Conn: new(ngaptesting.SctpConnStub), Log: logger.NgapLog}
			ue.AttachRanUe(&context.RanUe{Ran: ran, RanUeNgapId: 1, AmfUeNgapId: 1, Log: logger.NgapLog})
			ue.State[anType].Set(context.DeregistrationInitiated)
			ue.SetOnGoing(anType, &context.OnGoing{Procedure: context.OnGoingProcedurePaging})
			ue.T3513 = context.NewTimer(time.Hour, 4, func(int32) {}, func() {})
			ue.MacFailed = tc.macFailed

			require.NoError(t, HandleDeregistrationRequest(ue, anType, &nasMessage.DeregReqUEOrig{
				DeregType: &ie.DeregType{Switchoff: true, AccessType: ie.AccessType_3gpp},
			}))

			if tc.macFailed {
				require.NotNil(t, ue.T3513, "a request that failed the integrity check stopped T3513")
			} else {
				require.Nil(t, ue.T3513, "T3513 is still running")
			}
		})
	}
}
