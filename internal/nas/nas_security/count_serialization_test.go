package nas_security

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

// TS 24.501 4.4.3.2: a given uplink NAS COUNT is accepted at most one time, also when
// two goroutines decode the same message for one UE at once (e.g. the NGAP worker and an
// SBI UEContextTransfer).
func TestConcurrentDecodeAcceptsUplinkCountOnce(t *testing.T) {
	const decoders = 8
	ue := newSecurityTestUE()
	ue.SecurityContextAvailable = true
	sender := message.NewSecCtx(message.UESide, message.Bearer3GPP,
		ie.AlgCiphering(ue.CipheringAlg), ie.AlgIntegrity(ue.IntegrityAlg), ue.KnasEnc[:], ue.KnasInt[:])
	sender.UplinkCount.Set(0, 100)
	payload, err := message.Marshal(&message.RegComplete{}, sender,
		message.SecHdrTypeIntegrityProtectedAndCiphered)
	require.NoError(t, err)

	for round := 0; round < 200; round++ {
		ue.ULCount.Set(0, 99)
		ue.ULCount.MarkAccepted()
		var wg sync.WaitGroup
		start := make(chan struct{})
		accepted := make([]bool, decoders)
		for i := range accepted {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				_, integrityProtected, decodeErr := Decode(ue, models.AccessType_3_GPP_ACCESS, payload, false)
				accepted[i] = decodeErr == nil && integrityProtected
			}(i)
		}
		close(start)
		wg.Wait()

		n := 0
		for _, ok := range accepted {
			if ok {
				n++
			}
		}
		require.Equal(t, 1, n, "round %d: COUNT 100 accepted %d times", round, n)
		require.Equal(t, uint32(100), ue.ULCount.Get())
	}
}

// Concurrent downlink encodes for one UE (an SBI N1N2MessageTransfer and a GMM message on
// the NGAP worker) must each take a different downlink NAS COUNT: a repeated COUNT is
// replayed for the UE and reuses the NEA keystream.
func TestConcurrentEncodeUsesEachDownlinkCountOnce(t *testing.T) {
	const encoders, perEncoder = 8, 32 // 256 messages: every SQN exactly once
	ue := newSecurityTestUE()
	ue.SecurityContextAvailable = true

	var wg sync.WaitGroup
	start := make(chan struct{})
	payloads := make([][][]byte, encoders)
	for i := range payloads {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			for j := 0; j < perEncoder; j++ {
				payload, err := Encode(ue, &message.CfgUpdateCmd{},
					models.AccessType_3_GPP_ACCESS, message.SecHdrTypeIntegrityProtectedAndCiphered)
				if err != nil {
					t.Error(err)
					return
				}
				payloads[i] = append(payloads[i], payload)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	seen := make(map[uint8]bool)
	for _, list := range payloads {
		for _, payload := range list {
			sqn := payload[6] // EPD, security header type, 4-octet MAC, SQN
			require.False(t, seen[sqn], "downlink SQN %d used twice", sqn)
			seen[sqn] = true
		}
	}
	require.Len(t, seen, encoders*perEncoder)
	require.Equal(t, uint32(encoders*perEncoder), ue.DLCount.Get())
}
