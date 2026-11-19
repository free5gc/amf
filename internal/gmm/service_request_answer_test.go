package gmm

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

// TS 24.501 5.6.1.4, 5.6.1.5: a SERVICE REQUEST of a registered UE with a valid security context gets an answer,
// for mobile terminated services when nothing is pending for the UE, and for elevated signaling.
func TestServiceRequestIsAnswered(t *testing.T) {
	const anType = models.AccessType_3_GPP_ACCESS
	for name, tc := range map[string]struct {
		serviceType ie.ConstSvcType
		cucPending  bool
	}{
		"mobile terminated services":                               {ie.SvcType_MobileTermSvc, false},
		"mobile terminated services, configuration update pending": {ie.SvcType_MobileTermSvc, true},
		"elevated signaling":                                       {ie.SvcType_ElevatedSignalling, false},
	} {
		t.Run(name, func(t *testing.T) {
			ue := newGutiTestUe(t, true)
			conn := ue.GetRanUe(anType).Ran.Conn.(*ngaptesting.SctpConnStub)
			conn.MsgList = nil
			ue.ConfigurationUpdateCommandFlags = nil
			want := []nasMessage.MsgType{nasMessage.MsgTypeSvcAccept}
			if tc.cucPending {
				ue.ConfigurationUpdateCommandFlags = &context.ConfigurationUpdateCommandFlags{NeedNITZ: true}
				want = append(want, nasMessage.MsgTypeCfgUpdateCmd)
			}

			require.NoError(t, HandleServiceRequest(ue, anType, &nasMessage.SvcReq{
				Ngksi:   &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 1},
				SvcType: &ie.SvcType{Value: tc.serviceType},
			}))
			ue.StopT3555() // T3555 is not under test

			var sent []nasMessage.MsgType
			for _, msg := range pagingTestNas(t, conn.MsgList) {
				sent = append(sent, msg.MsgType())
			}
			require.Equal(t, want, sent)
		})
	}
}
