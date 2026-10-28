package nas_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	amf_nas "github.com/free5gc/amf/internal/nas"
	//"github.com/free5gc/nas/ie"
	"github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

/*
func TestIssue1087InvalidSUCI(t *testing.T) {
    identity := append([]byte(nil), fuzzMobileIdentity...)
    identity[6] = (identity[6] & 0xF0) | 0x05

    var mobileID ie.MobileId5GS
    err := mobileID.UnmarshalBinary(identity)

    t.Logf("NAS Parser returned: %v", err)

    require.Error(t, err)
    require.ErrorContains(t, err, "unsupported protection scheme ID 5")
}

func TestIssue1087RegistrationPDU(t *testing.T) {
    pdu := registrationRequest(t)

    t.Logf("Registration Request PDU: %x", pdu)

    msg, err := message.Parse(pdu, nil)

    require.NoError(t, err)
    require.NotNil(t, msg)
}

func TestIssue1087InvalidRegistrationPDU(t *testing.T) {
    pdu := registrationRequest(t)
    pdu[12] = (pdu[12] & 0xF0) | 0x05

    t.Logf("Invalid Registration Request PDU: %x", pdu)

    msg, err := message.Parse(pdu, nil)

    t.Logf("NAS Parser returned: %v", err)

    require.Error(t, err)
    require.ErrorContains(t, err, "unsupported protection scheme ID 5")
    require.Nil(t, msg)
}
*/

func TestIssue1087HandleNAS(t *testing.T) {
	// 1. 初始化AMF測試環境
	// amfSelf, tai := setupFuzzAMF()
	_, tai := setupFuzzAMF()

	// 2. 建立RanUe，但不建立AmfUe
	ranUe := &amf_context.RanUe{
		Ran: &amf_context.AmfRan{
			AnType: models.AccessType_3_GPP_ACCESS,
			Log:    logger.NgapLog,
		},
		Log: logger.NgapLog,
		Tai: tai,
	}

	require.Nil(t, ranUe.AmfUe)

	// 3. 建立非法Registration Request
	pdu := registrationRequest(t)
	pdu[12] = (pdu[12] & 0xF0) | 0x05

	t.Logf("Invalid Registration Request PDU: %x", pdu)

	// 4. 確認NAS Parser確實會拒絕
	_, err := message.Parse(pdu, nil)
	require.ErrorContains(t, err, "unsupported protection scheme ID 5")

	// Preserve the original RAN UE identifiers for verification.
	originalRan := ranUe.Ran
	originalRanUeNgapId := ranUe.RanUeNgapId
	originalAmfUeNgapId := ranUe.AmfUeNgapId

	// 5. 將非法NAS PDU交給AMF
	amf_nas.HandleNAS(
		ranUe,
		ngapMessage.ProcedureCodeInitialUEMessage,
		pdu,
		true,
	)

	// 6. 觀察HandleNAS執行後的狀態
	if ranUe.AmfUe == nil {
		t.Log("HandleNAS result: no AmfUe remains attached after decoding failure")
	} else {
		t.Log("HandleNAS result: AmfUe WAS created")
	}

	// Verify that the newly created AmfUe is released after NAS decoding fails.
	require.Nil(t, ranUe.AmfUe)

	// Verify that cleanup preserves the existing RAN UE context.
	require.Same(t, originalRan, ranUe.Ran)
	require.Equal(t, originalRanUeNgapId, ranUe.RanUeNgapId)
	require.Equal(t, originalAmfUeNgapId, ranUe.AmfUeNgapId)

	// Verify that the existing RanUe is preserved after AmfUe cleanup.
	require.NotNil(t, ranUe.Ran)
}

func TestIssue1087ExistingAmfUe(t *testing.T) {
	_, tai := setupFuzzAMF()

	// Create an existing UE context before handling the invalid NAS message.
	amfUe := amf_context.GetSelf().NewAmfUe("")

	ranUe := &amf_context.RanUe{
		Ran: &amf_context.AmfRan{
			AnType: models.AccessType_3_GPP_ACCESS,
			Log:    logger.NgapLog,
		},
		AmfUe: amfUe,
		Log:   logger.NgapLog,
		Tai:   tai,
	}

	// Send a Registration Request with an unsupported SUCI protection scheme.
	pdu := registrationRequest(t)
	pdu[12] = (pdu[12] & 0xF0) | 0x05

	amf_nas.HandleNAS(
		ranUe,
		ngapMessage.ProcedureCodeInitialUEMessage,
		pdu,
		true,
	)

	// A decoding error must not remove an existing UE context.
	require.Same(t, amfUe, ranUe.AmfUe)

	// Clean up the UE context created by this test.
	amfUe.Remove()
}
