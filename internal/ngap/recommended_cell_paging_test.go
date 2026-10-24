package ngap

import (
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	ngap_message "github.com/free5gc/amf/internal/ngap/message"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/ngap/aper"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// The gNB reports, in UE CONTEXT RELEASE COMPLETE, a recommended cell whose
// NG-RAN CGI uses the choice-Extensions alternative. The next PAGING for the
// UE must still decode.
func TestPagingAfterReleaseWithExtensionRecommendedCellDecodes(t *testing.T) {
	amfSelf := amf_context.GetSelf()
	NewAmfContext(amfSelf)
	ran := NewAmfRan(&ngaptesting.SctpConnStub{})
	ranUe, err := ran.NewRanUe(1)
	require.NoError(t, err)
	amfUe := amfSelf.NewAmfUe("imsi-208930000000002")
	amfUe.AttachRanUe(ranUe)
	amfUe.RegistrationArea[models.AccessType_3_GPP_ACCESS] = []models.Tai{
		{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, Tac: "000001"},
	}

	info := &ngapType.InfoOnRecommendedCellsAndRANNodesForPaging{
		RecommendedCellsForPaging: &ngapType.RecommendedCellsForPaging{
			RecommendedCellList: &ngapType.RecommendedCellList{List: []ngapType.RecommendedCellItem{{
				NGRANCGI: &ngapType.NGRANCGI{Choice: &ngapType.ProtocolIESingleContainerNGRANCGIExtIEs{}},
			}}},
		},
		RecommendRANNodesForPaging: &ngapType.RecommendedRANNodesForPaging{
			RecommendedRANNodeList: &ngapType.RecommendedRANNodeList{List: []ngapType.RecommendedRANNodeItem{{
				AMFPagingTarget: &ngapType.AMFPagingTarget{Choice: &ngapType.TAI{
					PLMNIdentity: &ngapType.PLMNIdentity{Value: aper.OctetString{0x02, 0xf8, 0x39}},
					TAC:          &ngapType.TAC{Value: aper.OctetString{0x00, 0x00, 0x01}},
				}},
			}}},
		},
	}
	handleUEContextReleaseCompleteMain(ran, ranUe, nil, info, nil, nil)
	require.NotNil(t, amfUe.InfoOnRecommendedCellsAndRanNodesForPaging)

	pkt, err := ngap_message.BuildPaging(amfUe, nil, false)
	require.NoError(t, err)
	decoded, err := ngapMessage.Parse(pkt)
	require.NoError(t, err, "the PAGING must decode")
	paging, ok := decoded.(*ngapMessage.Paging)
	require.True(t, ok)
	require.Nil(t, paging.AssistanceDataForPaging)
}
