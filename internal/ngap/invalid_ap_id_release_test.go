package ngap

import (
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/ngap/aper"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// TS 38.413 10.6: a message with an erroneous AP ID releases the
// UE-associated logical NG-connections that have the erroneous AP ID as local
// or remote identifier. When the AMF-UE-NGAP-ID is unknown, the connection
// that happens to use the received RAN-UE-NGAP-ID does not have the erroneous
// AP ID (except for a first returned message, where both received AP IDs are
// released), so it must stay. An inconsistent RAN-UE-NGAP-ID is itself the
// erroneous AP ID, so the connection that uses it is still released.
func TestApIdErrorReleasesOnlyConnectionsWithTheErroneousApId(t *testing.T) {
	const anType = models.AccessType_3_GPP_ACCESS
	const unknownAmfUeNgapID int64 = 999999

	type ues struct {
		x, y, other *amf_context.RanUe // x, y on ran; other on another NG interface
	}
	testCases := []struct {
		name string
		// message names AP IDs taken from the UEs
		message func(u ues) ngapMessage.Message
		// errorIndication is the cause the AMF answers with, if any
		errorIndication *ngapType.CauseRadioNetwork
		xKept, yKept    bool
	}{
		{
			name: "unknown AMF-UE-NGAP-ID with a live RAN-UE-NGAP-ID",
			message: func(u ues) ngapMessage.Message {
				return &ngapMessage.UplinkNASTransport{
					AMFUENGAPID: &ngapType.AMFUENGAPID{Value: unknownAmfUeNgapID},
					RANUENGAPID: &ngapType.RANUENGAPID{Value: u.y.RanUeNgapId},
					NASPDU:      &ngapType.NASPDU{Value: aper.OctetString{0x7e, 0x00}},
				}
			},
			errorIndication: &ngapType.CauseRadioNetwork{Value: ngapType.CauseRadioNetworkPresentUnknownLocalUENGAPID},
			xKept:           true,
			yKept:           true,
		},
		{
			name: "unknown AMF-UE-NGAP-ID with a live RAN-UE-NGAP-ID in the last message",
			message: func(u ues) ngapMessage.Message {
				return &ngapMessage.UEContextReleaseComplete{
					AMFUENGAPID: &ngapType.AMFUENGAPID{Value: unknownAmfUeNgapID},
					RANUENGAPID: &ngapType.RANUENGAPID{Value: u.y.RanUeNgapId},
				}
			},
			xKept: true,
			yKept: true,
		},
		{
			name: "AMF-UE-NGAP-ID of another NG interface with a live RAN-UE-NGAP-ID",
			message: func(u ues) ngapMessage.Message {
				return &ngapMessage.UEContextReleaseComplete{
					AMFUENGAPID: &ngapType.AMFUENGAPID{Value: u.other.AmfUeNgapId},
					RANUENGAPID: &ngapType.RANUENGAPID{Value: u.y.RanUeNgapId},
				}
			},
			xKept: true,
			yKept: true,
		},
		{
			name: "inconsistent RAN-UE-NGAP-ID that belongs to another connection",
			message: func(u ues) ngapMessage.Message {
				return &ngapMessage.UEContextReleaseComplete{
					AMFUENGAPID: &ngapType.AMFUENGAPID{Value: u.x.AmfUeNgapId},
					RANUENGAPID: &ngapType.RANUENGAPID{Value: u.y.RanUeNgapId},
				}
			},
			xKept: false,
			yKept: false,
		},
		{
			name: "unknown AMF-UE-NGAP-ID in a first returned message",
			message: func(u ues) ngapMessage.Message {
				return &ngapMessage.HandoverRequestAcknowledge{
					AMFUENGAPID: &ngapType.AMFUENGAPID{Value: unknownAmfUeNgapID},
					RANUENGAPID: &ngapType.RANUENGAPID{Value: u.y.RanUeNgapId},
				}
			},
			errorIndication: &ngapType.CauseRadioNetwork{Value: ngapType.CauseRadioNetworkPresentUnknownLocalUENGAPID},
			xKept:           true,
			yKept:           false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			amfSelf := amf_context.GetSelf()
			NewAmfContext(amfSelf)
			conn := new(ngaptesting.SctpConnStub)
			ran := NewAmfRan(conn)
			otherRan := NewAmfRan(new(ngaptesting.SctpConnStub))
			var u ues
			var err error
			u.x, err = ran.NewRanUe(5)
			require.NoError(t, err)
			u.y, err = ran.NewRanUe(7)
			require.NoError(t, err)
			u.other, err = otherRan.NewRanUe(9)
			require.NoError(t, err)
			amfUeX := amfSelf.NewAmfUe("imsi-208930000000005")
			amfUeX.AttachRanUe(u.x)
			amfUeY := amfSelf.NewAmfUe("imsi-208930000000007")
			amfUeY.AttachRanUe(u.y)

			dispatchMain(ran, tc.message(u), nil)

			require.Equal(t, tc.xKept, ran.RanUeFindByRanUeNgapID(5) == u.x, "connection X kept")
			require.Equal(t, tc.xKept, amfUeX.RanUe[anType] == u.x, "AmfUe X still on connection X")
			require.Equal(t, tc.yKept, ran.RanUeFindByRanUeNgapID(7) == u.y, "connection Y kept")
			require.Equal(t, tc.yKept, amfUeY.RanUe[anType] == u.y, "AmfUe Y still on connection Y")
			require.Equal(t, u.other, otherRan.RanUeFindByRanUeNgapID(9), "connection of the other NG interface kept")

			var causes []ngapType.CauseRadioNetwork
			for _, msg := range conn.MsgList {
				decoded, parseErr := ngapMessage.Parse(msg)
				require.NoError(t, parseErr)
				if indication, isIndication := decoded.(*ngapMessage.ErrorIndication); isIndication {
					cause, isRadioNetwork := indication.Cause.Choice.(*ngapType.CauseRadioNetwork)
					require.True(t, isRadioNetwork)
					causes = append(causes, *cause)
				}
			}
			if tc.errorIndication == nil {
				require.Empty(t, causes, "no Error Indication for the last message")
			} else {
				require.Equal(t, []ngapType.CauseRadioNetwork{*tc.errorIndication}, causes)
			}
		})
	}
}
