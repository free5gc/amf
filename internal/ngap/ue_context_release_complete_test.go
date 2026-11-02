package ngap

import (
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	ngap_message "github.com/free5gc/amf/internal/ngap/message"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// TS 38.413 8.3.3 / 10.4: UE CONTEXT RELEASE COMPLETE is the response to a
// UE CONTEXT RELEASE COMMAND. Without an outstanding command the AMF ignores it
// instead of releasing the UE's live N2 connection.
func TestUeContextReleaseCompleteRequiresOutstandingCommand(t *testing.T) {
	const anType = models.AccessType_3_GPP_ACCESS
	testCases := []struct {
		name string
		// commandSent: the AMF sent UE CONTEXT RELEASE COMMAND first
		commandSent bool
		// ranIDOffset is added to the connection's RAN-UE-NGAP-ID in the completion
		ranIDOffset int64
		released    bool
	}{
		{name: "unsolicited completion is ignored", commandSent: false, released: false},
		{name: "completion of a release command releases the connection", commandSent: true, released: true},
		// Not covered by this check: a completion whose RAN-UE-NGAP-ID differs
		// from the connection's takes the existing invalid AP ID handling in
		// ranUeFind, which releases the connection named by the AMF-UE-NGAP-ID
		// before the handler runs.
		{
			name:        "unsolicited completion with an inconsistent RAN-UE-NGAP-ID takes the invalid AP ID path",
			commandSent: false, ranIDOffset: 1, released: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			amfSelf := amf_context.GetSelf()
			NewAmfContext(amfSelf)
			ran := NewAmfRan(new(ngaptesting.SctpConnStub))
			ranUe, err := ran.NewRanUe(3)
			require.NoError(t, err)
			amfUe := amfSelf.NewAmfUe("imsi-208930000000124")
			amfUe.AttachRanUe(ranUe)
			amfUe.State[anType].Set(amf_context.Registered)

			if tc.commandSent {
				ngap_message.SendUEContextReleaseCommand(ranUe, amf_context.UeContextN2NormalRelease,
					ngap_message.CauseChoiceNas, ngapType.CauseNasPresentNormalRelease)
			}
			dispatchMain(ran, &ngapMessage.UEContextReleaseComplete{
				AMFUENGAPID: &ngapType.AMFUENGAPID{Value: ranUe.AmfUeNgapId},
				RANUENGAPID: &ngapType.RANUENGAPID{Value: ranUe.RanUeNgapId + tc.ranIDOffset},
			}, nil)

			require.Equal(t, !tc.released, amfSelf.RanUeFindByAmfUeNgapID(ranUe.AmfUeNgapId) == ranUe,
				"RanUe kept")
			require.Equal(t, !tc.released, amfUe.RanUe[anType] == ranUe, "AmfUe still CM-CONNECTED")
			_, pooled := amfSelf.AmfUeFindBySupi(amfUe.Supi)
			require.True(t, pooled, "an N2 release keeps the AmfUe")
		})
	}
}
