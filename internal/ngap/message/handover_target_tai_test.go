package message

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/amf/pkg/factory"
	ngapType "github.com/free5gc/ngap/ie"
	"github.com/free5gc/openapi/models"
)

func TestHandoverRequestRetainsSelectedTargetTAI(t *testing.T) {
	previousConfig := factory.AmfConfig
	factory.AmfConfig = &factory.Config{}
	t.Cleanup(func() { factory.AmfConfig = previousConfig })
	configureGoldenAMFContext()

	sourceUe := newGoldenRanUE()
	sourceUe.Log = logger.NgapLog.WithField("test", "selected target TAI")
	sourceUe.Tai = models.Tai{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, Tac: "000001"}
	targetTai := models.Tai{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, Tac: "000002"}
	snssai := models.Snssai{Sst: 1, Sd: "010203"}
	conn := &ngaptesting.SctpConnStub{}
	targetRan := &context.AmfRan{
		AnType: models.AccessType_3_GPP_ACCESS, Conn: conn, Log: sourceUe.Log,
		SupportedTAList: []context.SupportedTAI{{Tai: targetTai, SNssaiList: []models.Snssai{snssai}}},
	}

	SendHandoverRequest(sourceUe, targetRan, targetTai, goldenCause(), goldenHandoverSetupList(),
		ngapType.SourceToTargetTransparentContainer{Value: []byte{1}}, false)

	require.NotNil(t, sourceUe.TargetUe)
	t.Cleanup(func() {
		sourceUe.TargetUe.DetachAmfUe()
		require.NoError(t, sourceUe.TargetUe.Remove())
	})
	require.Len(t, conn.MsgList, 1, "Handover Request must be sent to the target RAN")
	require.Equal(t, targetTai, sourceUe.TargetUe.Tai)
	require.True(t, sourceUe.AmfUe.CheckSliceAvailabilityInTargetRan(snssai, targetRan, sourceUe.TargetUe.Tai))
	require.False(t, sourceUe.AmfUe.CheckSliceAvailabilityInTargetRan(snssai, targetRan, sourceUe.Tai))
	require.Equal(t, "000001", sourceUe.Tai.Tac, "preparation must not change the source location")
}
