package processor

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	amf_nas "github.com/free5gc/amf/internal/nas"
	"github.com/free5gc/amf/internal/nas/nas_security"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/mediatype/multipart"
	"github.com/free5gc/openapi/models"
)

var (
	countTestKnasEnc = [16]byte{1, 2, 3, 4}
	countTestKnasInt = [16]byte{5, 6, 7, 8}
)

func newCountTestUe(t *testing.T, supi string) *context.AmfUe {
	t.Helper()
	amfSelf := context.GetSelf()
	amfSelf.ServedGuamiList = []models.Guami{{
		PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"},
		AmfId:  "cafe01",
	}}
	ue := amfSelf.NewAmfUe(supi)
	t.Cleanup(func() { amfSelf.UePool.Delete(supi) })
	ue.SecurityContextAvailable = true
	ue.CipheringAlg = uint8(message.AlgCiphering128NEA2)
	ue.IntegrityAlg = uint8(message.AlgIntegrity128NIA2)
	ue.KnasEnc = countTestKnasEnc
	ue.KnasInt = countTestKnasInt
	ue.ULCount.Set(0, 9)
	ue.ULCount.MarkAccepted()
	return ue
}

func uplinkAt(t *testing.T, count uint32, msg message.Message, st message.SecHdrType) []byte {
	t.Helper()
	sender := message.NewSecCtx(message.UESide, message.Bearer3GPP,
		message.AlgCiphering128NEA2, message.AlgIntegrity128NIA2, countTestKnasEnc[:], countTestKnasInt[:])
	sender.UplinkCount.Set(uint16(count>>8), uint8(count))
	payload, err := message.Marshal(msg, sender, st)
	require.NoError(t, err)
	return payload
}

// The REGISTRATION REQUEST at COUNT 10 reaches this AMF over NGAP (HandleNAS ->
// nas_security.Decode) while a target AMF forwards the same message in
// UEContextTransfer(INIT_REG). TS 24.501 4.4.3.2: COUNT 10 is accepted by one of them only.
func TestNGAPDecodeAndUEContextTransferAcceptCountOnce(t *testing.T) {
	const supi = "imsi-208930000001157"
	var guti ie.MobileId5GS
	require.NoError(t, guti.UnmarshalBinary([]byte{0xf2, 0x02, 0xf8, 0x39, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x01}))
	registrationRequest := uplinkAt(t, 10, &message.RegReq{
		RegType5GS:  &ie.RegType5GS{FOR_Pending: true, Value: ie.RegType_InitialReg},
		Ngksi:       &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 1},
		MobileId5GS: &guti,
	}, message.SecHdrTypeIntegrityProtected)
	transfer := models.UEContextTransferRequestBody{
		JsonData: &models.Amf_Comm_UeContextTransferReqData{
			Reason:     models.Amf_Comm_TransferReason_INIT_REG,
			AccessType: models.AccessType_3_GPP_ACCESS,
		},
		BinaryDataN1Message: &multipart.RelatedContent{Content: registrationRequest},
	}

	p := &Processor{}
	for round := 0; round < 300; round++ {
		ue := newCountTestUe(t, supi)
		var wg sync.WaitGroup
		start := make(chan struct{})
		var ngapAccepted, sbiAccepted bool
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, integrityProtected, err := nas_security.Decode(ue, models.AccessType_3_GPP_ACCESS,
				registrationRequest, true)
			ngapAccepted = err == nil && integrityProtected
		}()
		go func() {
			defer wg.Done()
			<-start
			rsp, problemDetails := p.UEContextTransferProcedure(supi, transfer)
			sbiAccepted = problemDetails == nil && rsp != nil
		}()
		close(start)
		wg.Wait()
		require.True(t, ngapAccepted != sbiAccepted,
			"round %d: NGAP accepted=%v, UEContextTransfer accepted=%v", round, ngapAccepted, sbiAccepted)
		require.Equal(t, uint32(10), ue.ULCount.Get())
		context.GetSelf().UePool.Delete(supi)
	}
}

// lockedConn records what the AMF sends to the gNB from several goroutines.
type lockedConn struct {
	net.Conn
	mu   sync.Mutex
	sent [][]byte
}

func (c *lockedConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, append([]byte(nil), b...))
	return len(b), nil
}

func (c *lockedConn) RemoteAddr() net.Addr { return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func (c *lockedConn) messages() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.sent...)
}

// The shape of the cross-NF deadlock of a lock held across HandleNAS: the UE's UL NAS
// TRANSPORT is forwarded to the SMF (UpdateSmContext) and the SMF does not answer until
// its own N1N2MessageTransfer for the same UE has completed (as when its T3591/T3592 holds
// the SM context lock). The N1N2MessageTransfer, which encodes a downlink NAS message,
// must complete while HandleNAS is blocked in the SMF call.
func TestN1N2TransferCompletesWhileHandleNASWaitsOnSMF(t *testing.T) {
	const supi = "imsi-208930000001158"
	const pduSessionID = 5

	smfEntered := make(chan struct{}, 1)
	releaseSMF := make(chan struct{})
	smf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		smfEntered <- struct{}{}
		<-releaseSMF
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("{}")); err != nil {
			t.Error(err)
		}
	}))
	defer smf.Close()
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseSMF) }) }
	defer release()

	_, err := consumer.NewConsumer(nil)
	require.NoError(t, err)

	ue := newCountTestUe(t, supi)
	ue.State[models.AccessType_3_GPP_ACCESS].Set(context.Registered)
	smContext := context.NewSmContext(pduSessionID)
	smContext.SetAccessType(models.AccessType_3_GPP_ACCESS)
	smContext.SetSnssai(models.Snssai{Sst: 1, Sd: "010203"})
	smContext.SetSmfUri(smf.URL)
	smContext.SetSmContextRef("sm-context-5")
	ue.StoreSmContext(pduSessionID, smContext)

	conn := &lockedConn{}
	ran := &context.AmfRan{AnType: models.AccessType_3_GPP_ACCESS, Conn: conn, Log: logger.NgapLog}
	ranUe := &context.RanUe{Ran: ran, RanUeNgapId: 1, AmfUeNgapId: 1, Log: logger.NgapLog}
	ue.AttachRanUe(ranUe)

	modificationRequest, err := (&message.PDUSessModReq{PDUSessId: pduSessionID, PTI: 1}).MarshalBinary()
	require.NoError(t, err)
	ulNasTransport := uplinkAt(t, 10, &message.ULNASTransport{
		PayloadCntrType: &ie.PayloadCntrType{Value: ie.PayloadCntrType_N1SMInfo},
		PayloadCntr:     &ie.PayloadCntr{Pct: ie.PayloadCntrType_N1SMInfo, Contents: modificationRequest},
		PDUSessID:       &ie.PDUSessId2{Value: pduSessionID},
	}, message.SecHdrTypeIntegrityProtectedAndCiphered)

	handleNASDone := make(chan struct{})
	go func() {
		defer close(handleNASDone)
		amf_nas.HandleNAS(ranUe, ngapMessage.ProcedureCodeUplinkNASTransport, ulNasTransport, false)
	}()
	select {
	case <-smfEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("HandleNAS did not forward the 5GSM message to the SMF")
	}

	modificationCommand, err := (&message.PDUSessModCmd{PDUSessId: pduSessionID, PTI: 1}).MarshalBinary()
	require.NoError(t, err)
	type transferResult struct {
		rsp           *models.Amf_Comm_N1N2MessageTransferRspData
		problem       *models.ProblemDetails
		transferError *models.Amf_Comm_N1N2MessageTransferError
	}
	transferDone := make(chan transferResult, 1)
	go func() {
		rsp, _, problem, transferError := (&Processor{}).N1N2MessageTransferProcedure(supi, "",
			models.N1N2MessageTransferRequestBody{
				JsonData: &models.Amf_Comm_N1N2MessageTransferReqData{
					PduSessionId: pduSessionID,
					N1MessageContainer: &models.Amf_Comm_N1MessageContainer{
						N1MessageClass:   models.Amf_Comm_N1MessageClass_SM,
						N1MessageContent: &models.RefToBinaryData{ContentId: "n1"},
					},
				},
				BinaryDataN1Message: &multipart.RelatedContent{Content: modificationCommand},
			})
		transferDone <- transferResult{rsp, problem, transferError}
	}()

	var result transferResult
	select {
	case result = <-transferDone:
	case <-time.After(3 * time.Second):
		t.Fatal("N1N2MessageTransfer blocked while HandleNAS waits on the SMF")
	}
	select {
	case <-handleNASDone:
		t.Fatal("HandleNAS returned before the SMF answered")
	default:
	}
	require.Nil(t, result.problem)
	require.Nil(t, result.transferError)
	require.NotNil(t, result.rsp)
	require.Equal(t, models.Amf_Comm_N1N2MessageTransferCause_N1_N2_TRANSFER_INITIATED, result.rsp.Cause)

	// The UE accepts the forwarded PDU SESSION MODIFICATION COMMAND at downlink COUNT 0.
	ueSecurity := message.NewSecCtx(message.UESide, message.Bearer3GPP,
		message.AlgCiphering128NEA2, message.AlgIntegrity128NIA2, countTestKnasEnc[:], countTestKnasInt[:])
	var downlink *ngapMessage.DownlinkNASTransport
	for _, sent := range conn.messages() {
		decoded, parseErr := ngapMessage.Parse(sent)
		require.NoError(t, parseErr)
		if d, ok := decoded.(*ngapMessage.DownlinkNASTransport); ok {
			downlink = d
		}
	}
	require.NotNil(t, downlink, "no DOWNLINK NAS TRANSPORT sent")
	nasMsg, err := message.Parse(downlink.NASPDU.Value, ueSecurity)
	require.NoError(t, err)
	require.IsType(t, &message.DLNASTransport{}, nasMsg)

	release()
	select {
	case <-handleNASDone:
	case <-time.After(10 * time.Second):
		t.Fatal("HandleNAS did not finish after the SMF answered")
	}
	require.Equal(t, uint32(10), ue.ULCount.Get())
	require.Equal(t, uint32(1), ue.DLCount.Get())
}
