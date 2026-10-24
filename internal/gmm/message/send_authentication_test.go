package message

import (
	"encoding/hex"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/openapi/models"
)

// TS 24.501 5.4.1.3.2: each AUTHENTICATION REQUEST is supervised by one T3560.
// Sending a new challenge must stop the timer of the previous one; otherwise the
// old timer keeps retransmitting the superseded challenge and its fifth expiry
// removes the UE context (5.4.1.3.7 b).
func TestSendAuthenticationRequestStopsPreviousT3560(t *testing.T) {
	amfSelf := context.GetSelf()
	amfSelf.ServedGuamiList = []models.Guami{{PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"}, AmfId: "cafe00"}}
	amfSelf.T3560Cfg = factory.TimerValue{Enable: true, ExpireTime: time.Hour, MaxRetryTimes: 4}

	conn := new(ngaptesting.SctpConnStub)
	ran := &context.AmfRan{AnType: models.AccessType_3_GPP_ACCESS, Conn: conn, Log: logger.NgapLog}
	ranUe := &context.RanUe{Ran: ran, RanUeNgapId: 1, AmfUeNgapId: 1, Log: logger.NgapLog}
	ue := amfSelf.NewAmfUe("")
	ue.AttachRanUe(ranUe)
	t.Cleanup(ue.Remove)
	ue.ABBA = []uint8{0x00, 0x00}
	ue.AuthenticationCtx = &models.Ausf_UEAU_UEAuthenticationCtx{
		AuthType: models.Ausf_UEAU_AuthType_5_G_AKA,
		Var5gAuthData: map[string]interface{}{
			"rand": hex.EncodeToString(make([]byte, 16)),
			"autn": hex.EncodeToString(make([]byte, 16)),
		},
	}

	// T3560 of a previous challenge is still running.
	var retransmissions atomic.Int32
	previous := context.NewTimer(5*time.Millisecond, 1000, func(int32) { retransmissions.Add(1) }, func() {})
	ue.T3560 = previous

	SendAuthenticationRequest(ranUe)

	require.Len(t, conn.MsgList, 1)
	require.NotNil(t, ue.T3560)
	require.NotSame(t, previous, ue.T3560)
	time.Sleep(20 * time.Millisecond) // let an expiry that raced with Stop finish
	before := retransmissions.Load()
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, before, retransmissions.Load(), "the T3560 of the superseded challenge is still running")
}
