package ngap

import (
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	ngap_message "github.com/free5gc/amf/internal/ngap/message"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
)

// maxRanUeNgapID is the largest RAN-UE-NGAP-ID, INTEGER (0..2^32-1) in
// TS 38.413 9.3.3.2. The AMF also uses this value internally for a handover
// target that has no RAN-UE-NGAP-ID yet.
const maxRanUeNgapID int64 = 0xffffffff

// A UE-associated logical NG-connection whose RAN-UE-NGAP-ID is 0xffffffff is
// an ordinary connection: an NG Reset releases it (TS 38.413 8.7.4.2.2) and the
// UE CONTEXT RELEASE COMMAND names it by the UE NGAP ID pair (8.3.3.2).
func TestRanUeNgapIDMaxIsAnOrdinaryConnection(t *testing.T) {
	resets := []struct {
		name      string
		resetType func(ranUe *amf_context.RanUe) *ngapType.ResetType
	}{
		{
			name: "NG Reset all",
			resetType: func(*amf_context.RanUe) *ngapType.ResetType {
				return &ngapType.ResetType{Choice: &ngapType.ResetAll{}}
			},
		},
		{
			name: "NG Reset part of NG interface by RAN-UE-NGAP-ID",
			resetType: func(*amf_context.RanUe) *ngapType.ResetType {
				return &ngapType.ResetType{Choice: &ngapType.UEAssociatedLogicalNGConnectionList{
					List: []ngapType.UEAssociatedLogicalNGConnectionItem{{
						RANUENGAPID: &ngapType.RANUENGAPID{Value: maxRanUeNgapID},
					}},
				}}
			},
		},
		{
			name: "NG Reset part of NG interface by AMF-UE-NGAP-ID",
			resetType: func(ranUe *amf_context.RanUe) *ngapType.ResetType {
				return &ngapType.ResetType{Choice: &ngapType.UEAssociatedLogicalNGConnectionList{
					List: []ngapType.UEAssociatedLogicalNGConnectionItem{{
						AMFUENGAPID: &ngapType.AMFUENGAPID{Value: ranUe.AmfUeNgapId},
					}},
				}}
			},
		},
	}
	for _, reset := range resets {
		t.Run(reset.name, func(t *testing.T) {
			amfSelf := amf_context.GetSelf()
			NewAmfContext(amfSelf)
			ran := NewAmfRan(new(ngaptesting.SctpConnStub))
			ranUe, err := ran.NewRanUe(maxRanUeNgapID)
			require.NoError(t, err)
			require.Equal(t, ranUe, ran.RanUeFindByRanUeNgapID(maxRanUeNgapID))

			handleNGResetMain(ran, nil, reset.resetType(ranUe))

			require.Nil(t, ran.RanUeFindByRanUeNgapID(maxRanUeNgapID))
			require.Nil(t, amfSelf.RanUeFindByAmfUeNgapID(ranUe.AmfUeNgapId), "the reset released the connection")
		})
	}

	t.Run("UE CONTEXT RELEASE COMMAND", func(t *testing.T) {
		NewAmfContext(amf_context.GetSelf())
		conn := new(ngaptesting.SctpConnStub)
		ran := NewAmfRan(conn)
		ranUe, err := ran.NewRanUe(maxRanUeNgapID)
		require.NoError(t, err)

		ngap_message.SendUEContextReleaseCommand(ranUe, amf_context.UeContextN2NormalRelease,
			ngap_message.CauseChoiceRadioNetwork, ngapType.CauseRadioNetworkPresentUnspecified)

		require.Len(t, conn.MsgList, 1)
		decoded, err := ngapMessage.Parse(conn.MsgList[0])
		require.NoError(t, err)
		command, ok := decoded.(*ngapMessage.UEContextReleaseCommand)
		require.True(t, ok)
		pair, ok := command.UENGAPIDs.Choice.(*ngapType.UENGAPIDPair)
		require.True(t, ok, "UE NGAP ID pair, got %T", command.UENGAPIDs.Choice)
		require.Equal(t, ranUe.AmfUeNgapId, pair.AMFUENGAPID.Value)
		require.Equal(t, maxRanUeNgapID, pair.RANUENGAPID.Value)
	})
}
