package message

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

func pagingTestUe(cells ...context.RecommendedCell) *context.AmfUe {
	return &context.AmfUe{
		Guti: "20893cafe0000000001",
		RegistrationArea: map[models.AccessType][]models.Tai{
			models.AccessType_3_GPP_ACCESS: {{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, Tac: "000001"}},
		},
		InfoOnRecommendedCellsAndRanNodesForPaging: &context.InfoOnRecommendedCellsAndRanNodesForPaging{
			RecommendedCells: cells,
		},
	}
}

func decodePaging(t *testing.T, ue *context.AmfUe) *ngapMessage.Paging {
	t.Helper()
	pkt, err := BuildPaging(ue, nil, false)
	require.NoError(t, err)
	decoded, err := ngapMessage.Parse(pkt)
	require.NoError(t, err, "the PAGING built by the AMF must decode")
	paging, ok := decoded.(*ngapMessage.Paging)
	require.True(t, ok)
	return paging
}

// A recommended cell whose NG-RAN CGI used the choice-Extensions alternative is
// stored without a CGI and cannot be encoded. It used to leave an empty
// Recommended Cell List (SIZE(1..16)) in the PAGING.
func TestBuildPagingOmitsAssistanceDataWithoutUsableRecommendedCell(t *testing.T) {
	paging := decodePaging(t, pagingTestUe(context.RecommendedCell{}))
	require.Nil(t, paging.AssistanceDataForPaging)
}

func TestBuildPagingKeepsUsableRecommendedCell(t *testing.T) {
	usable := context.RecommendedCell{NgRanCGI: context.NGRANCGI{
		Present: context.NgRanCgiPresentNRCGI,
		NRCGI:   &models.Ncgi{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, NrCellId: "000000010"},
	}}
	paging := decodePaging(t, pagingTestUe(context.RecommendedCell{}, usable))
	require.NotNil(t, paging.AssistanceDataForPaging)
	cells := paging.AssistanceDataForPaging.AssistanceDataForRecommendedCells.RecommendedCellsForPaging
	require.Len(t, cells.RecommendedCellList.List, 1)
}
