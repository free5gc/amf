package ngap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/free5gc/aper"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

func TestExtractUEID_InitialUEMessage(t *testing.T) {
	// Create InitialUEMessage with RAN-UE-NGAP-ID
	ranUeNgapID := int64(12345)

	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{
				Value: ngapType.ProcedureCodeInitialUEMessage,
			},
			Criticality: ngapType.Criticality{
				Value: ngapType.CriticalityPresentIgnore,
			},
		},
	}
	pdu.InitiatingMessage.Value.Present = ngapType.InitiatingMessagePresentInitialUEMessage
	pdu.InitiatingMessage.Value.InitialUEMessage = &ngapType.InitialUEMessage{}

	// RAN UE NGAP ID
	ie := ngapType.InitialUEMessageIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.InitialUEMessageIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = &ngapType.RANUENGAPID{Value: ranUeNgapID}
	pdu.InitiatingMessage.Value.InitialUEMessage.ProtocolIEs.List = append(
		pdu.InitiatingMessage.Value.InitialUEMessage.ProtocolIEs.List, ie)

	// Encode the PDU
	encodedMsg, err := ngap.Encoder(pdu)
	require.NoError(t, err)

	// Test extraction
	ueID, found := ExtractUEID(encodedMsg)
	assert.True(t, found, "UE ID should be found")
	assert.Equal(t, uint64(ranUeNgapID), ueID, "UE ID should match RAN-UE-NGAP-ID")
}

func TestExtractUEID_UplinkNASTransport(t *testing.T) {
	// Create UplinkNASTransport with AMF-UE-NGAP-ID and RAN-UE-NGAP-ID
	amfUeNgapID := int64(67890)
	ranUeNgapID := int64(12345)

	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{
				Value: ngapType.ProcedureCodeUplinkNASTransport,
			},
			Criticality: ngapType.Criticality{
				Value: ngapType.CriticalityPresentIgnore,
			},
		},
	}
	pdu.InitiatingMessage.Value.Present = ngapType.InitiatingMessagePresentUplinkNASTransport
	pdu.InitiatingMessage.Value.UplinkNASTransport = &ngapType.UplinkNASTransport{}

	// AMF UE NGAP ID
	ie := ngapType.UplinkNASTransportIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.UplinkNASTransportIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = &ngapType.AMFUENGAPID{Value: amfUeNgapID}
	pdu.InitiatingMessage.Value.UplinkNASTransport.ProtocolIEs.List = append(
		pdu.InitiatingMessage.Value.UplinkNASTransport.ProtocolIEs.List, ie)

	// RAN UE NGAP ID
	ie2 := ngapType.UplinkNASTransportIEs{}
	ie2.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie2.Criticality.Value = ngapType.CriticalityPresentReject
	ie2.Value.Present = ngapType.UplinkNASTransportIEsPresentRANUENGAPID
	ie2.Value.RANUENGAPID = &ngapType.RANUENGAPID{Value: ranUeNgapID}
	pdu.InitiatingMessage.Value.UplinkNASTransport.ProtocolIEs.List = append(
		pdu.InitiatingMessage.Value.UplinkNASTransport.ProtocolIEs.List, ie2)

	// Encode the PDU
	encodedMsg, err := ngap.Encoder(pdu)
	require.NoError(t, err)

	// Test extraction - should prefer AMF-UE-NGAP-ID
	ueID, found := ExtractUEID(encodedMsg)
	assert.True(t, found, "UE ID should be found")
	assert.Equal(t, uint64(amfUeNgapID), ueID, "UE ID should match AMF-UE-NGAP-ID")
}

func TestExtractUEID_InitialContextSetupResponse(t *testing.T) {
	// Create InitialContextSetupResponse (SuccessfulOutcome)
	amfUeNgapID := int64(99999)

	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentSuccessfulOutcome,
		SuccessfulOutcome: &ngapType.SuccessfulOutcome{
			ProcedureCode: ngapType.ProcedureCode{
				Value: ngapType.ProcedureCodeInitialContextSetup,
			},
			Criticality: ngapType.Criticality{
				Value: ngapType.CriticalityPresentReject,
			},
		},
	}
	pdu.SuccessfulOutcome.Value.Present = ngapType.SuccessfulOutcomePresentInitialContextSetupResponse
	pdu.SuccessfulOutcome.Value.InitialContextSetupResponse = &ngapType.InitialContextSetupResponse{}

	// AMF UE NGAP ID
	ie := ngapType.InitialContextSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.InitialContextSetupResponseIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = &ngapType.AMFUENGAPID{Value: amfUeNgapID}
	pdu.SuccessfulOutcome.Value.InitialContextSetupResponse.ProtocolIEs.List = append(
		pdu.SuccessfulOutcome.Value.InitialContextSetupResponse.ProtocolIEs.List, ie)

	// Encode the PDU
	encodedMsg, err := ngap.Encoder(pdu)
	require.NoError(t, err)

	// Test extraction
	ueID, found := ExtractUEID(encodedMsg)
	assert.True(t, found, "UE ID should be found")
	assert.Equal(t, uint64(amfUeNgapID), ueID, "UE ID should match AMF-UE-NGAP-ID")
}

func TestExtractUEID_NGSetupRequest(t *testing.T) {
	// Test NGSetupRequest (non-UE message)
	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{
				Value: ngapType.ProcedureCodeNGSetup,
			},
			Criticality: ngapType.Criticality{
				Value: ngapType.CriticalityPresentReject,
			},
		},
	}
	pdu.InitiatingMessage.Value.Present = ngapType.InitiatingMessagePresentNGSetupRequest
	pdu.InitiatingMessage.Value.NGSetupRequest = &ngapType.NGSetupRequest{}

	// Add GlobalRANNodeID IE
	ie := ngapType.NGSetupRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDGlobalRANNodeID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.NGSetupRequestIEsPresentGlobalRANNodeID
	ie.Value.GlobalRANNodeID = &ngapType.GlobalRANNodeID{
		Present: ngapType.GlobalRANNodeIDPresentGlobalGNBID,
		GlobalGNBID: &ngapType.GlobalGNBID{
			PLMNIdentity: ngapType.PLMNIdentity{Value: aper.OctetString("\x02\xf8\x39")},
			GNBID: ngapType.GNBID{
				Present: ngapType.GNBIDPresentGNBID,
				GNBID: &aper.BitString{
					Bytes:     []byte{0x45, 0x46, 0x47},
					BitLength: 24,
				},
			},
		},
	}
	pdu.InitiatingMessage.Value.NGSetupRequest.ProtocolIEs.List = append(
		pdu.InitiatingMessage.Value.NGSetupRequest.ProtocolIEs.List, ie)

	// Encode the PDU
	encodedMsg, err := ngap.Encoder(pdu)
	require.NoError(t, err)

	// Test extraction - should return not found for non-UE messages
	ueID, found := ExtractUEID(encodedMsg)
	assert.False(t, found, "UE ID should not be found for non-UE message")
	assert.Equal(t, uint64(0), ueID, "UE ID should be 0 for non-UE message")
}

func TestExtractUEID_InvalidMessage(t *testing.T) {
	// Test with invalid/corrupted message
	invalidMsg := []byte{0xff, 0xff, 0xff, 0xff}

	ueID, found := ExtractUEID(invalidMsg)
	assert.False(t, found, "UE ID should not be found for invalid message")
	assert.Equal(t, uint64(0), ueID, "UE ID should be 0 for invalid message")
}

func TestExtractUEID_HandoverRequired(t *testing.T) {
	// Test HandoverRequired message
	amfUeNgapID := int64(11111)

	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{
				Value: ngapType.ProcedureCodeHandoverPreparation,
			},
			Criticality: ngapType.Criticality{
				Value: ngapType.CriticalityPresentReject,
			},
		},
	}
	pdu.InitiatingMessage.Value.Present = ngapType.InitiatingMessagePresentHandoverRequired
	pdu.InitiatingMessage.Value.HandoverRequired = &ngapType.HandoverRequired{}

	// AMF UE NGAP ID
	ie := ngapType.HandoverRequiredIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverRequiredIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = &ngapType.AMFUENGAPID{Value: amfUeNgapID}
	pdu.InitiatingMessage.Value.HandoverRequired.ProtocolIEs.List = append(
		pdu.InitiatingMessage.Value.HandoverRequired.ProtocolIEs.List, ie)

	// Encode the PDU
	encodedMsg, err := ngap.Encoder(pdu)
	require.NoError(t, err)

	// Test extraction
	ueID, found := ExtractUEID(encodedMsg)
	assert.True(t, found, "UE ID should be found")
	assert.Equal(t, uint64(amfUeNgapID), ueID, "UE ID should match AMF-UE-NGAP-ID")
}

func TestExtractUEID_PDUSessionResourceSetupResponse(t *testing.T) {
	// Test PDUSessionResourceSetupResponse
	amfUeNgapID := int64(22222)

	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentSuccessfulOutcome,
		SuccessfulOutcome: &ngapType.SuccessfulOutcome{
			ProcedureCode: ngapType.ProcedureCode{
				Value: ngapType.ProcedureCodePDUSessionResourceSetup,
			},
			Criticality: ngapType.Criticality{
				Value: ngapType.CriticalityPresentReject,
			},
		},
	}
	pdu.SuccessfulOutcome.Value.Present = ngapType.SuccessfulOutcomePresentPDUSessionResourceSetupResponse
	pdu.SuccessfulOutcome.Value.PDUSessionResourceSetupResponse = &ngapType.PDUSessionResourceSetupResponse{}

	// AMF UE NGAP ID
	ie := ngapType.PDUSessionResourceSetupResponseIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.PDUSessionResourceSetupResponseIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = &ngapType.AMFUENGAPID{Value: amfUeNgapID}
	pdu.SuccessfulOutcome.Value.PDUSessionResourceSetupResponse.ProtocolIEs.List = append(
		pdu.SuccessfulOutcome.Value.PDUSessionResourceSetupResponse.ProtocolIEs.List, ie)

	// Encode the PDU
	encodedMsg, err := ngap.Encoder(pdu)
	require.NoError(t, err)

	// Test extraction
	ueID, found := ExtractUEID(encodedMsg)
	assert.True(t, found, "UE ID should be found")
	assert.Equal(t, uint64(amfUeNgapID), ueID, "UE ID should match AMF-UE-NGAP-ID")
}

func TestExtractUEID_UEContextReleaseRequest(t *testing.T) {
	// Test UEContextReleaseRequest
	amfUeNgapID := int64(33333)

	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{
				Value: ngapType.ProcedureCodeUEContextReleaseRequest,
			},
			Criticality: ngapType.Criticality{
				Value: ngapType.CriticalityPresentIgnore,
			},
		},
	}
	pdu.InitiatingMessage.Value.Present = ngapType.InitiatingMessagePresentUEContextReleaseRequest
	pdu.InitiatingMessage.Value.UEContextReleaseRequest = &ngapType.UEContextReleaseRequest{}

	// AMF UE NGAP ID
	ie := ngapType.UEContextReleaseRequestIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.UEContextReleaseRequestIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = &ngapType.AMFUENGAPID{Value: amfUeNgapID}
	pdu.InitiatingMessage.Value.UEContextReleaseRequest.ProtocolIEs.List = append(
		pdu.InitiatingMessage.Value.UEContextReleaseRequest.ProtocolIEs.List, ie)

	// Encode the PDU
	encodedMsg, err := ngap.Encoder(pdu)
	require.NoError(t, err)

	// Test extraction
	ueID, found := ExtractUEID(encodedMsg)
	assert.True(t, found, "UE ID should be found")
	assert.Equal(t, uint64(amfUeNgapID), ueID, "UE ID should match AMF-UE-NGAP-ID")
}
