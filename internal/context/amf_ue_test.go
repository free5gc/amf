package context

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

func TestCopyDataFromUeContextModelUplinkCount(t *testing.T) {
	knasEnc := [16]byte{1, 2, 3, 4}
	knasInt := [16]byte{5, 6, 7, 8}
	uplink := func(t *testing.T, count uint32) []byte {
		t.Helper()
		sender := message.NewSecCtx(message.UESide, message.Bearer3GPP,
			message.AlgCiphering128NEA2, message.AlgIntegrity128NIA2, knasEnc[:], knasInt[:])
		sender.UplinkCount.Set(uint16(count>>8), uint8(count))
		payload, err := message.Marshal(&message.RegComplete{}, sender,
			message.SecHdrTypeIntegrityProtectedAndCiphered)
		require.NoError(t, err)
		return payload
	}
	transferred := func(ulCount int32) *models.Amf_Comm_UeContext {
		return &models.Amf_Comm_UeContext{
			SeafData: &models.Amf_Comm_SeafData{
				NgKsi:  &models.Amf_Comm_NgKsi{Tsc: models.Amf_Comm_ScType_NATIVE, Ksi: 1},
				KeyAmf: &models.Amf_Comm_KeyAmf{KeyType: models.Amf_Comm_KeyAmfType_KAMF, KeyVal: "00"},
			},
			MmContextList: []models.Amf_Comm_MmContext{{
				AccessType: models.AccessType_3_GPP_ACCESS,
				NasSecurityMode: &models.Amf_Comm_NasSecurityMode{
					IntegrityAlgorithm: models.Amf_Comm_IntegrityAlgorithm_NIA2,
					CipheringAlgorithm: models.Amf_Comm_CipheringAlgorithm_NEA2,
				},
				NasUplinkCount: ulCount,
			}},
		}
	}
	newTargetUe := func() *AmfUe {
		ue := new(AmfUe)
		ue.init()
		ue.SecurityContextAvailable = true
		ue.KnasEnc = knasEnc
		ue.KnasInt = knasInt
		return ue
	}

	for _, count := range []int32{100, 0xffff00} {
		ue := newTargetUe()
		ue.CopyDataFromUeContextModel(transferred(count))
		require.True(t, ue.SecurityContextAvailable)
		require.Equal(t, uint32(count), ue.ULCount.Get())

		receiver := &message.SecCtx{
			Side:          message.CoreNetworkSide,
			Bearer:        message.Bearer3GPP,
			UplinkCount:   &ue.ULCount,
			DownlinkCount: &ue.DLCount,
			CipheringAlg:  message.AlgCiphering128NEA2,
			IntegrityAlg:  message.AlgIntegrity128NIA2,
			KnasEnc:       knasEnc,
			KnasInt:       knasInt,
		}
		// The old AMF already accepted the transferred COUNT.
		_, err := message.Parse(uplink(t, uint32(count)), receiver)
		require.Error(t, err, "COUNT %d", count)
		require.Equal(t, uint32(count), ue.ULCount.Get())

		_, err = message.Parse(uplink(t, uint32(count)+1), receiver)
		require.NoError(t, err, "COUNT %d", count+1)
		require.Equal(t, uint32(count)+1, ue.ULCount.Get())
	}
}
