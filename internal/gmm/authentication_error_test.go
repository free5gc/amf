package gmm

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	nasMessage "github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/fsm"
)

// TS 24.501 5.5.1.2.5: a registration that cannot be authenticated, here because
// the NRF cannot be reached to select an AUSF, is answered with one REGISTRATION
// REJECT.
func TestAuthenticationErrorSendsOneRegistrationReject(t *testing.T) {
	const anType = models.AccessType_3_GPP_ACCESS
	ue, conn := newNssaiTestUe(t) // its NRF is unreachable

	require.NoError(t, GmmFSM.SendEvent(ue.State[anType], StartAuthEvent, fsm.ArgsType{
		ArgAmfUe:      ue,
		ArgAccessType: anType,
	}, logger.GmmLog))

	require.Len(t, conn.MsgList, 1)
	decoded, err := ngapMessage.Parse(conn.MsgList[0])
	require.NoError(t, err)
	downlink, ok := decoded.(*ngapMessage.DownlinkNASTransport)
	require.True(t, ok, "NGAP message is %T", decoded)
	nasMsg, err := nasMessage.ParseGMM(downlink.NASPDU.Value)
	require.NoError(t, err)
	require.IsType(t, &nasMessage.RegRej{}, nasMsg)
	require.True(t, ue.State[anType].Is(context.Deregistered))
}
