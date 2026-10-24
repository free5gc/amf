package ngap

import (
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	ngapType "github.com/free5gc/ngap/ie"
	"github.com/free5gc/openapi/models"
)

func TestHandleLocationReportWithoutAreaOfInterestListDoesNotPanic(t *testing.T) {
	ran := &amf_context.AmfRan{
		AnType: models.AccessType_3_GPP_ACCESS,
		Log:    logger.NgapLog,
	}
	ranUe := &amf_context.RanUe{Ran: ran, Log: ran.Log}

	uEPresenceList := &ngapType.UEPresenceInAreaOfInterestList{
		List: []ngapType.UEPresenceInAreaOfInterestItem{{
			LocationReportingReferenceID: &ngapType.LocationReportingReferenceID{Value: 1},
			UEPresence:                   &ngapType.UEPresence{Value: ngapType.UEPresencePresentIn},
		}},
	}
	locationReportingRequestType := &ngapType.LocationReportingRequestType{
		EventType:  &ngapType.EventType{Value: ngapType.EventTypePresentUePresenceInAreaOfInterest},
		ReportArea: &ngapType.ReportArea{Value: ngapType.ReportAreaPresentCell},
	}

	require.NotPanics(t, func() {
		handleLocationReportMain(ran, ranUe, nil, uEPresenceList, locationReportingRequestType)
	})
}
