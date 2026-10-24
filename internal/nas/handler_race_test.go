package nas_test

import (
	"net"
	"sync"
	"testing"
	"time"

	amf_context "github.com/free5gc/amf/internal/context"
	gmm_common "github.com/free5gc/amf/internal/gmm/common"
	"github.com/free5gc/amf/internal/logger"
	amf_nas "github.com/free5gc/amf/internal/nas"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

type discardConn struct{}

func (discardConn) Read([]byte) (int, error) {
	return 0, nil
}

func (discardConn) Write(b []byte) (int, error) {
	return len(b), nil
}

func (discardConn) Close() error {
	return nil
}

func (discardConn) LocalAddr() net.Addr {
	return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (discardConn) RemoteAddr() net.Addr {
	return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (discardConn) SetDeadline(time.Time) error {
	return nil
}

func (discardConn) SetReadDeadline(time.Time) error {
	return nil
}

func (discardConn) SetWriteDeadline(time.Time) error {
	return nil
}

// TestHandleNASRacesHoldingRanUeRelease drives HandleNAS for an N2 connection
// on one NGAP worker while the HandleNAS of the UE's new connection releases
// that old RanUe on another worker (ClearHoldingRanUe detaches it).  HandleNAS
// attaches a new AmfUe when the RanUe has none and must then use the AmfUe it
// attached, not re-read ranUe.AmfUe, which the release can clear at any time.
func TestHandleNASRacesHoldingRanUeRelease(t *testing.T) {
	_, tai := setupFuzzAMF()
	ranUe := &amf_context.RanUe{
		Ran: &amf_context.AmfRan{
			AnType: models.AccessType_3_GPP_ACCESS,
			Conn:   discardConn{},
			Log:    logger.NgapLog,
		},
		RanUeNgapId: 1,
		AmfUeNgapId: 1,
		Log:         logger.NgapLog,
		Tai:         tai,
	}
	// An undecodable NAS PDU: HandleNAS attaches an AmfUe, fails to decode
	// and logs through the AmfUe.
	nasPdu := []byte{0x7e, 0x00, 0x00}

	const iterations = 200
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			amf_nas.HandleNAS(ranUe, ngapMessage.ProcedureCodeUplinkNASTransport, nasPdu, false)
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < iterations; i++ {
			gmm_common.ClearHoldingRanUe(ranUe)
		}
	}()
	close(start)
	wg.Wait()
}
