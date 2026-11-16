package processor

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/mediatype/multipart"
	"github.com/free5gc/openapi/models"
)

// TS 24.501 4.4.3.2: the source AMF accepts the COUNT of the REGISTRATION REQUEST in a
// UEContextTransfer once; the same message again fails the integrity check.
func TestUEContextTransferProcedureAcceptsRegistrationRequestOnce(t *testing.T) {
	const supi = "imsi-208930000001156"
	knasEnc := [16]byte{1, 2, 3, 4}
	knasInt := [16]byte{5, 6, 7, 8}

	amfSelf := context.GetSelf()
	amfSelf.ServedGuamiList = []models.Guami{{
		PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"},
		AmfId:  "cafe00",
	}}
	ue := amfSelf.NewAmfUe(supi)
	t.Cleanup(func() { amfSelf.UePool.Delete(supi) })
	ue.SecurityContextAvailable = true
	ue.CipheringAlg = uint8(message.AlgCiphering128NEA2)
	ue.IntegrityAlg = uint8(message.AlgIntegrity128NIA2)
	ue.KnasEnc = knasEnc
	ue.KnasInt = knasInt
	ue.ULCount.Set(0, 9)
	ue.ULCount.MarkAccepted()

	var guti ie.MobileId5GS
	require.NoError(t, guti.UnmarshalBinary([]byte{0xf2, 0x02, 0xf8, 0x39, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x01}))
	// The REGISTRATION REQUEST that the UE sent to the new AMF at uplink COUNT 10.
	sender := message.NewSecCtx(message.UESide, message.Bearer3GPP,
		message.AlgCiphering128NEA2, message.AlgIntegrity128NIA2, knasEnc[:], knasInt[:])
	sender.UplinkCount.Set(0, 10)
	registrationRequest, err := message.Marshal(&message.RegReq{
		RegType5GS:  &ie.RegType5GS{FOR_Pending: true, Value: ie.RegType_InitialReg},
		Ngksi:       &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 1},
		MobileId5GS: &guti,
	}, sender, message.SecHdrTypeIntegrityProtected)
	require.NoError(t, err)
	request := models.UEContextTransferRequestBody{
		JsonData: &models.Amf_Comm_UeContextTransferReqData{
			Reason:     models.Amf_Comm_TransferReason_INIT_REG,
			AccessType: models.AccessType_3_GPP_ACCESS,
		},
		BinaryDataN1Message: &multipart.RelatedContent{Content: registrationRequest},
	}

	p := &Processor{}
	response, problemDetails := p.UEContextTransferProcedure(supi, request)
	require.Nil(t, problemDetails)
	require.NotNil(t, response)
	require.Len(t, response.JsonData.UeContext.MmContextList, 1)
	require.Equal(t, int32(10), response.JsonData.UeContext.MmContextList[0].NasUplinkCount)

	response, problemDetails = p.UEContextTransferProcedure(supi, request)
	require.Nil(t, response)
	require.NotNil(t, problemDetails)
	require.Equal(t, int32(http.StatusForbidden), problemDetails.Status)
	require.Equal(t, "INTEGRITY_CHECK_FAIL", problemDetails.Cause)
	require.Equal(t, uint32(10), ue.ULCount.Get())
}
