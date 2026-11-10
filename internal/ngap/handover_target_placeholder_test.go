package ngap

import (
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
)

// The HANDOVER REQUEST ACKNOWLEDGE is the first returned message for the
// handover target (TS 38.413 10.6). It is accepted for the placeholder, which
// has no RAN-UE-NGAP-ID yet, and binds the RAN-UE-NGAP-ID it carries; for a
// connection that already has one, 0xffffffff included, it is an
// inconsistent remote AP ID.
func TestHandoverRequestAcknowledgeBindsPlaceholderOnly(t *testing.T) {
	ack := func(ranUe *amf_context.RanUe, ranUeNgapID int64) *ngapMessage.HandoverRequestAcknowledge {
		return &ngapMessage.HandoverRequestAcknowledge{
			AMFUENGAPID: &ngapType.AMFUENGAPID{Value: ranUe.AmfUeNgapId},
			RANUENGAPID: &ngapType.RANUENGAPID{Value: ranUeNgapID},
		}
	}

	t.Run("placeholder", func(t *testing.T) {
		NewAmfContext(amf_context.GetSelf())
		ran := NewAmfRan(new(ngaptesting.SctpConnStub))
		placeholder, err := ran.NewRanUeUnspecified()
		require.NoError(t, err)

		dispatchMain(ran, ack(placeholder, 9), nil)

		require.True(t, placeholder.RanUeNgapIdAssigned)
		require.Equal(t, int64(9), placeholder.RanUeNgapId)
		require.Equal(t, placeholder, ran.RanUeFindByRanUeNgapID(9))
	})

	t.Run("connection with RAN-UE-NGAP-ID 0xffffffff", func(t *testing.T) {
		amfSelf := amf_context.GetSelf()
		NewAmfContext(amfSelf)
		ran := NewAmfRan(new(ngaptesting.SctpConnStub))
		ranUe, err := ran.NewRanUe(maxRanUeNgapID)
		require.NoError(t, err)

		dispatchMain(ran, ack(ranUe, 9), nil)

		require.Nil(t, amfSelf.RanUeFindByAmfUeNgapID(ranUe.AmfUeNgapId), "released as inconsistent")
		require.Nil(t, ran.RanUeFindByRanUeNgapID(9))
	})
}
