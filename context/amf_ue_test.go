package context_test

import (
	"encoding/hex"
	"fmt"
	"free5gc/lib/CommonConsumerTestData/AMF/TestAmf"
	"free5gc/lib/nas/security"
	"free5gc/lib/openapi/models"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAmfKdf(t *testing.T) {
	TestAmf.AmfInit()
	TestAmf.UeAttach(models.AccessType__3_GPP_ACCESS)
	ue, _ := TestAmf.TestAmf.AmfUeFindBySupi("imsi-2089300007487")
	ue.ABBA = []uint8{0x00, 0x00}
	ue.Kamf = strings.Repeat("1", 64)
	ue.CipheringAlg = security.AlgCiphering128NEA2
	ue.IntegrityAlg = security.AlgIntegrity128NIA2
	ue.ULCountOverflow = 0x0011
	ue.ULCountSQN = 0x02
	count := ue.GetSecurityULCount()
	assert.Equal(t, []byte("\x00\x00\x11\x02"), count)
	fmt.Printf("Uplink Count: 0x%0x\n", count)
	ue.DerivateAlgKey()
	fmt.Printf("KnasEnc: 0x%0x\nKnasInt: 0x%0x\n", ue.KnasEnc, ue.KnasInt)
	assert.Equal(t, 16, len(ue.KnasEnc))
	assert.Equal(t, 16, len(ue.KnasInt))
	ue.DerivateAnKey(models.AccessType__3_GPP_ACCESS)
	assert.Equal(t, 32, len(ue.Kgnb))
	fmt.Printf("Kgnb: 0x%0x\n", ue.Kgnb)
	ue.NH, _ = hex.DecodeString(strings.Repeat("2", 64))
	ue.DerivateNH(ue.NH)
	assert.Equal(t, 32, len(ue.NH))
	fmt.Printf("NH: 0x%0x\n", ue.NH)
}
