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
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// TS 24.501 5.6.1.4, 5.6.1.5: a SERVICE REQUEST of a registered UE with a valid security context gets an answer,
// for mobile terminated services when nothing is pending for the UE, and for elevated signaling.
func TestServiceRequestIsAnswered(t *testing.T) {
	const anType = models.AccessType_3_GPP_ACCESS
	tai := models.Tai{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, Tac: "000001"}
	amfSelf := context.GetSelf()
	savedGuamis, savedTais, savedConfig := amfSelf.ServedGuamiList, amfSelf.SupportTaiLists, factory.AmfConfig
	amfSelf.ServedGuamiList = []models.Guami{{PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"}, AmfId: "cafe00"}}
	amfSelf.SupportTaiLists = []models.Tai{tai}
	factory.AmfConfig = &factory.Config{Configuration: &factory.Configuration{}}
	t.Cleanup(func() {
		amfSelf.ServedGuamiList, amfSelf.SupportTaiLists, factory.AmfConfig = savedGuamis, savedTais, savedConfig
	})

	for name, tc := range map[string]struct {
		serviceType ie.ConstSvcType
		cucPending  bool
	}{
		"mobile terminated services":                               {ie.SvcType_MobileTermSvc, false},
		"mobile terminated services, configuration update pending": {ie.SvcType_MobileTermSvc, true},
		"elevated signaling":                                       {ie.SvcType_ElevatedSignalling, false},
	} {
		t.Run(name, func(t *testing.T) {
			ue := amfSelf.NewAmfUe("imsi-208930000000731")
			t.Cleanup(ue.Remove)
			ue.SecurityContextAvailable = true
			ue.NgKsi = models.Amf_Comm_NgKsi{Tsc: models.Amf_Comm_ScType_NATIVE, Ksi: 1}
			ue.State[anType].Set(context.Registered)
			want := []nasMessage.MsgType{nasMessage.MsgTypeSvcAccept}
			if tc.cucPending {
				ue.ConfigurationUpdateCommandFlags = &context.ConfigurationUpdateCommandFlags{NeedNITZ: true}
				want = append(want, nasMessage.MsgTypeCfgUpdateCmd)
			}
			conn := new(ngaptesting.SctpConnStub)
			ran := &context.AmfRan{AnType: anType, Conn: conn, Log: logger.NgapLog}
			ue.AttachRanUe(&context.RanUe{Ran: ran, RanUeNgapId: 1, AmfUeNgapId: 1, Tai: tai, Log: logger.NgapLog})

			require.NoError(t, HandleServiceRequest(ue, anType, &nasMessage.SvcReq{
				Ngksi:   &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 1},
				SvcType: &ie.SvcType{Value: tc.serviceType},
			}))
			// The UE's side of the test's security context, which has the null algorithms
			ueSecCtx := nasMessage.NewSecCtx(nasMessage.UESide, nasMessage.Bearer3GPP,
				nasMessage.AlgCiphering128NEA0, nasMessage.AlgIntegrity128NIA0, nil, nil)
			var sent []nasMessage.MsgType
			for _, b := range conn.MsgList {
				decoded, err := ngapMessage.Parse(b)
				require.NoError(t, err)
				downlink, ok := decoded.(*ngapMessage.DownlinkNASTransport)
				require.True(t, ok, "unexpected NGAP message %T", decoded)
				msg, err := nasMessage.Parse(downlink.NASPDU.Value, ueSecCtx)
				require.NoError(t, err)
				sent = append(sent, msg.MsgType())
			}
			require.Equal(t, want, sent)
		})
	}
}
