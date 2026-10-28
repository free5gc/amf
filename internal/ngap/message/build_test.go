//nolint:lll // Golden byte fixtures are intentionally kept as contiguous protocol values.
package message

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	"github.com/free5gc/ngap/aper"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

func TestBuildDownlinkNasTransportGolden(t *testing.T) {
	got, err := BuildDownlinkNasTransport(
		&context.RanUe{AmfUeNgapId: 0x01020304, RanUeNgapId: 0x05060708},
		[]byte{0x7e, 0x00, 0x41},
		nil,
	)
	require.NoError(t, err)
	require.Equal(t, []byte{
		0x00, 0x04, 0x40, 0x1d, 0x00, 0x00, 0x03, 0x00, 0x0a, 0x00, 0x05,
		0x60, 0x01, 0x02, 0x03, 0x04, 0x00, 0x55, 0x00, 0x05, 0xc0, 0x05,
		0x06, 0x07, 0x08, 0x00, 0x26, 0x00, 0x04, 0x03, 0x7e, 0x00, 0x41,
	}, got)

	decoded := decodeMessage(t, got)
	require.Equal(t, ngapMessage.ProcedureCodeDownlinkNASTransport, decoded.ProcedureCode())
}

func TestBuildNGResetAcknowledgeMinimalGolden(t *testing.T) {
	got, err := BuildNGResetAcknowledge(nil, nil)
	require.NoError(t, err)
	require.Equal(t, []byte{0x20, 0x14, 0x00, 0x03, 0x00, 0x00, 0x00}, got)

	decoded := decodeMessage(t, got)
	require.Equal(t, ngapMessage.ProcedureCodeNGReset, decoded.ProcedureCode())
}

func TestBuildOverloadStopGolden(t *testing.T) {
	got, err := BuildOverloadStop()
	require.NoError(t, err)
	require.Equal(t, []byte{0x00, 0x17, 0x00, 0x03, 0x00, 0x00, 0x00}, got)

	decoded := decodeMessage(t, got)
	require.Equal(t, ngapMessage.ProcedureCodeOverloadStop, decoded.ProcedureCode())
}

// BuildTraceStart is currently a placeholder: it creates no NGAP procedure
// and therefore must not silently turn into a wire message during a module
// upgrade.  Its error is the compatibility contract until implemented.
func TestBuildTraceStartUnsupportedContract(t *testing.T) {
	payload, err := BuildTraceStart()
	require.Error(t, err)
	require.Nil(t, payload)
}

func TestAMFNGAPControlBuilderGoldenBaseline(t *testing.T) {
	previousConfig := factory.AmfConfig
	factory.AmfConfig = &factory.Config{}
	t.Cleanup(func() { factory.AmfConfig = previousConfig })

	configureGoldenAMFContext()
	ue := newGoldenRanUE()
	cause := goldenCause()
	amfID, ranID := ue.AmfUeNgapId, ue.RanUeNgapId

	builds := []struct {
		name      string
		procedure int64
		build     func() ([]byte, error)
	}{
		{"pdu_session_resource_release_command", ngapMessage.ProcedureCodePDUSessionResourceRelease, func() ([]byte, error) {
			return BuildPDUSessionResourceReleaseCommand(ue, []byte{0x7e, 0, 0x64, 0x5f}, goldenReleaseList())
		}},
		{"ng_setup_response", ngapMessage.ProcedureCodeNGSetup, func() ([]byte, error) { return BuildNGSetupResponse(nil) }},
		{"ng_setup_failure", ngapMessage.ProcedureCodeNGSetup, func() ([]byte, error) { return BuildNGSetupFailure(cause, nil) }},
		{"ng_reset", ngapMessage.ProcedureCodeNGReset, func() ([]byte, error) { return BuildNGReset(cause, nil) }},
		{"ue_context_release_command", ngapMessage.ProcedureCodeUEContextRelease, func() ([]byte, error) {
			return BuildUEContextReleaseCommand(ue, CauseChoiceRadioNetwork, aper.Enumerated(0))
		}},
		{"error_indication", ngapMessage.ProcedureCodeErrorIndication, func() ([]byte, error) {
			return BuildErrorIndication(&amfID, &ranID, &cause, nil)
		}},
		{"ue_radio_capability_check_request", ngapMessage.ProcedureCodeUERadioCapabilityCheck, func() ([]byte, error) {
			return BuildUERadioCapabilityCheckRequest(ue)
		}},
		{"handover_cancel_acknowledge", ngapMessage.ProcedureCodeHandoverCancel, func() ([]byte, error) {
			return BuildHandoverCancelAcknowledge(ue, nil)
		}},
		{"pdu_session_resource_setup_request", ngapMessage.ProcedureCodePDUSessionResourceSetup, func() ([]byte, error) {
			return BuildPDUSessionResourceSetupRequest(ue, []byte{0x7e, 0, 0x41}, goldenSetupList())
		}},
		{"pdu_session_resource_modify_confirm", ngapMessage.ProcedureCodePDUSessionResourceModifyIndication, func() ([]byte, error) {
			return BuildPDUSessionResourceModifyConfirm(ue, goldenModifyConfirmList(), ngapType.PDUSessionResourceFailedToModifyListModCfm{}, nil)
		}},
		{"pdu_session_resource_modify_request", ngapMessage.ProcedureCodePDUSessionResourceModify, func() ([]byte, error) {
			return BuildPDUSessionResourceModifyRequest(ue, goldenModifyRequestList())
		}},
		{"ran_configuration_update_acknowledge", ngapMessage.ProcedureCodeRANConfigurationUpdate, func() ([]byte, error) {
			return BuildRanConfigurationUpdateAcknowledge(nil)
		}},
		{"ran_configuration_update_failure", ngapMessage.ProcedureCodeRANConfigurationUpdate, func() ([]byte, error) {
			return BuildRanConfigurationUpdateFailure(cause, nil)
		}},
		{"overload_start", ngapMessage.ProcedureCodeOverloadStart, func() ([]byte, error) {
			return BuildOverloadStart(nil, 0, nil)
		}},
		{"deactivate_trace", ngapMessage.ProcedureCodeDeactivateTrace, func() ([]byte, error) {
			ue.GetAmfUe().TraceData = &models.TraceData{TraceRef: "20893-010203"}
			ue.Trsr = "0405"
			defer func() {
				ue.GetAmfUe().TraceData = nil
				ue.Trsr = ""
			}()
			return BuildDeactivateTrace(ue.GetAmfUe(), models.AccessType_3_GPP_ACCESS)
		}},
		{"ue_tnla_binding_release_request", ngapMessage.ProcedureCodeUETNLABindingRelease, func() ([]byte, error) {
			return BuildUETNLABindingReleaseRequest(ue)
		}},
		{"location_reporting_control", ngapMessage.ProcedureCodeLocationReportingControl, func() ([]byte, error) {
			return BuildLocationReportingControl(ue, nil, 0, ngapType.EventType{Value: ngapType.EventTypePresentDirect})
		}},
		{"downlink_ue_associated_nrppa_transport", ngapMessage.ProcedureCodeDownlinkUEAssociatedNRPPaTransport, func() ([]byte, error) {
			return BuildDownlinkUEAssociatedNRPPaTransport(ue, ngapType.NRPPaPDU{Value: []byte{0x01}})
		}},
		{"initial_context_setup_request", ngapMessage.ProcedureCodeInitialContextSetup, func() ([]byte, error) {
			return BuildInitialContextSetupRequest(ue.GetAmfUe(), models.AccessType_3_GPP_ACCESS, []byte{0x7e, 0, 0x41}, nil, nil, nil, nil)
		}},
		{"ue_context_modification_request", ngapMessage.ProcedureCodeUEContextModification, func() ([]byte, error) {
			return BuildUEContextModificationRequest(ue.GetAmfUe(), models.AccessType_3_GPP_ACCESS, nil, nil, nil, nil, nil)
		}},
		{"handover_preparation_failure", ngapMessage.ProcedureCodeHandoverPreparation, func() ([]byte, error) {
			return BuildHandoverPreparationFailure(ue, cause, nil)
		}},
		{"path_switch_request_failure", ngapMessage.ProcedureCodePathSwitchRequest, func() ([]byte, error) {
			return BuildPathSwitchRequestFailure(ue.AmfUeNgapId, ue.RanUeNgapId, goldenPathSwitchFailureList(), nil)
		}},
		{"downlink_non_ue_associated_nrppa_transport", ngapMessage.ProcedureCodeDownlinkNonUEAssociatedNRPPaTransport, func() ([]byte, error) {
			return BuildDownlinkNonUEAssociatedNRPPATransport(ue, ngapType.NRPPaPDU{Value: []byte{0x01}})
		}},
		{"downlink_ran_configuration_transfer", ngapMessage.ProcedureCodeDownlinkRANConfigurationTransfer, func() ([]byte, error) {
			return BuildDownlinkRanConfigurationTransfer(nil)
		}},
		{"downlink_ran_status_transfer", ngapMessage.ProcedureCodeDownlinkRANStatusTransfer, func() ([]byte, error) {
			return BuildDownlinkRanStatusTransfer(ue, goldenStatusTransfer())
		}},
		{"reroute_nas_request", ngapMessage.ProcedureCodeRerouteNASRequest, func() ([]byte, error) {
			return BuildRerouteNasRequest(ue.GetAmfUe(), models.AccessType_3_GPP_ACCESS, &amfID, []byte{0x01}, nil)
		}},
		{"paging", ngapMessage.ProcedureCodePaging, func() ([]byte, error) { return BuildPaging(ue.GetAmfUe(), nil, false) }},
		{"amf_configuration_update", ngapMessage.ProcedureCodeAMFConfigurationUpdate, func() ([]byte, error) {
			return BuildAMFConfigurationUpdate(ngapType.TNLAssociationUsage{Value: 0}, ngapType.TNLAddressWeightFactor{Value: 1})
		}},
		{"handover_command", ngapMessage.ProcedureCodeHandoverPreparation, func() ([]byte, error) {
			return BuildHandoverCommand(ue, goldenHandoverList(), ngapType.PDUSessionResourceToReleaseListHOCmd{}, ngapType.TargetToSourceTransparentContainer{Value: []byte{1}}, nil)
		}},
		{"handover_request", ngapMessage.ProcedureCodeHandoverResourceAllocation, func() ([]byte, error) {
			ue.GetAmfUe().NH = make([]byte, 32)
			return BuildHandoverRequest(ue, cause, goldenHandoverSetupList(), ngapType.SourceToTargetTransparentContainer{Value: []byte{1}}, false)
		}},
		{"path_switch_request_acknowledge", ngapMessage.ProcedureCodePathSwitchRequest, func() ([]byte, error) {
			return BuildPathSwitchRequestAcknowledge(ue, goldenSwitchedList(), ngapType.PDUSessionResourceReleasedListPSAck{}, false, nil, nil, nil)
		}},
		{"amf_status_indication", ngapMessage.ProcedureCodeAMFStatusIndication, func() ([]byte, error) {
			return BuildAMFStatusIndication(goldenUnavailableGUAMIList())
		}},
	}

	for _, test := range builds {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.build()
			require.NoError(t, err)
			require.Equal(t, amfNGAPGolden[test.name], hex.EncodeToString(got))
			decoded := decodeMessage(t, got)
			require.Equal(t, test.procedure, goldenProcedureCode(decoded))
		})
	}
}

var amfNGAPGolden = map[string]string{
	"pdu_session_resource_release_command":       "001c0027000004000a0005600102030400550005c00506070800264005047e00645f004f00050000010101",
	"ng_setup_response":                          "201500330000040001000c0480616d662d676f6c64656e00600008000002f839cafe0000564001ff0050000b0002f83900001008010203",
	"ng_setup_failure":                           "40150009000001000f40020000",
	"ng_reset":                                   "0014000e000002000f400200000058000100",
	"ue_context_release_command":                 "002900170000020072000a0601020304c005060708000f40020000",
	"error_indication":                           "0009401b000003000a4005600102030400554005c005060708000f40020000",
	"ue_radio_capability_check_request":          "002b0015000002000a0005600102030400550005c005060708",
	"handover_cancel_acknowledge":                "200a0015000002000a4005600102030400554005c005060708",
	"pdu_session_resource_setup_request":         "001d0036000005000a0005600102030400550005c00506070800260004037e0041004a000700000100200101006e400a0c0bebc2003005f5e100",
	"pdu_session_resource_modify_confirm":        "201b001e000003000a4005600102030400554005c005060708003e40050000010101",
	"pdu_session_resource_modify_request":        "001a001e000003000a0005600102030400550005c005060708004000050000010101",
	"ran_configuration_update_acknowledge":       "20230003000000",
	"ran_configuration_update_failure":           "4023000e000002000f40020000006b400100",
	"overload_start":                             "00164003000000",
	"deactivate_trace":                           "00034021000003000a0005600102030400550005c005060708002c400802f8390102030405",
	"ue_tnla_binding_release_request":            "002d4015000002000a0005600102030400550005c005060708",
	"location_reporting_control":                 "0010401b000003000a0005600102030400550005c005060708002140020000",
	"downlink_ue_associated_nrppa_transport":     "00084022000004000a0005600102030400550005c00506070800590003020102002e00020101",
	"ue_context_modification_request":            "00280023000003000a0005600102030400550005c005060708006e400a0c0bebc2003005f5e100",
	"handover_preparation_failure":               "400c001b000003000a4005600102030400554005c005060708000f40020000",
	"path_switch_request_failure":                "4019001e000003000a4005600102030400554005c005060708004540050000010101",
	"initial_context_setup_request":              "000e0062000007000a0005600102030400550005c005060708001c00070002f839cafe0000000005020101020300770009000000000000000000005e0020000000000000000000000000000000000000000000000000000000000000000000264004037e0041",
	"downlink_non_ue_associated_nrppa_transport": "0005401000000200590003020102002e00020101",
	"downlink_ran_configuration_transfer":        "00064003000000",
	"reroute_nas_request":                        "0024002100000400550005c005060708000a40056001020304002a0002010100030002fe00",
	"amf_configuration_update":                   "000000580000070001000c0480616d662d676f6c64656e00600008000002f839cafe0000564001ff0050000b0002f83900001008010203000640090207c07f000001000100074007000f807f000001000840090303e07f0000010001",
	"downlink_ran_status_transfer":               "00074025000003000a0005600102030400550005c0050607080054000c000000000000000000000000",
	"paging":                                     "00184019000002007340071fc00001020304006740070002f839000001",
	"handover_command":                           "200c0029000005000a0005600102030400550005c005060708001d000100003b40050000010101006a00020101",
	"handover_request":                           "000d007c00000a000a00056001020304001d000100000f40020000006e000a0c0bebc2003005f5e10000770009000000000000000000005d00210000000000000000000000000000000000000000000000000000000000000000000049000700000100200101000000050201010203006500020101001c00070002f839cafe00",
	"path_switch_request_acknowledge":            "20190059000006000a4005600102030400554005c00506070800770009000000000000000000005d0021000000000000000000000000000000000000000000000000000000000000000000004d40050000010101000000050201010203",
	"amf_status_indication":                      "000140150000010078000e002002f839cafe000180414d4631",
}

func configureGoldenAMFContext() {
	self := context.GetSelf()
	self.Name = "amf-golden"
	self.RelativeCapacity = 255
	self.RegisterIPv4 = "127.0.0.1"
	self.ServedGuamiList = []models.Guami{{
		PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"},
		AmfId:  "cafe00",
	}}
	self.PlmnSupportList = []factory.PlmnSupportItem{{
		PlmnId:     &models.PlmnId{Mcc: "208", Mnc: "93"},
		SNssaiList: []models.Snssai{{Sst: 1, Sd: "010203"}},
	}}
	self.SupportTaiLists = []models.Tai{{
		PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"},
		Tac:    "000001",
	}}
}

func newGoldenRanUE() *context.RanUe {
	amfUe := &context.AmfUe{
		RanUe: map[models.AccessType]*context.RanUe{},
		AllowedNssai: map[models.AccessType][]models.Nssf_NSSel_AllowedSnssai{
			models.AccessType_3_GPP_ACCESS: {{AllowedSnssai: &models.Snssai{Sst: 1, Sd: "010203"}}},
		},
		Kgnb: make([]byte, 32),
		Guti: "00000cafe0001020304",
		RegistrationArea: map[models.AccessType][]models.Tai{
			models.AccessType_3_GPP_ACCESS: {{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, Tac: "000001"}},
		},
		UESecurityCapability: ie.UESecCapability{Length: 2},
		AccessAndMobilitySubscriptionData: &models.Udm_SDM_AccessAndMobilitySubscriptionData{
			SubscribedUeAmbr: &models.AmbrRm{Uplink: "100 Mbps", Downlink: "200 Mbps"},
		},
	}
	ran := &context.AmfRan{AnType: models.AccessType_3_GPP_ACCESS}
	ue := &context.RanUe{AmfUeNgapId: 0x01020304, RanUeNgapId: 0x05060708, Ran: ran, RoutingID: "0102"}
	ue.SetAmfUe(amfUe)
	amfUe.RanUe[models.AccessType_3_GPP_ACCESS] = ue
	return ue
}

func goldenStatusTransfer() ngapType.RANStatusTransferTransparentContainer {
	return ngapType.RANStatusTransferTransparentContainer{DRBsSubjectToStatusTransferList: &ngapType.DRBsSubjectToStatusTransferList{
		List: []ngapType.DRBsSubjectToStatusTransferItem{{
			DRBID: &ngapType.DRBID{Value: 1},
			DRBStatusUL: &ngapType.DRBStatusUL{Choice: &ngapType.DRBStatusUL12{
				ULCOUNTValue: &ngapType.COUNTValueForPDCPSN12{
					PDCPSN12: int64Pointer(0), HFNPDCPSN12: int64Pointer(0),
				},
			}},
			DRBStatusDL: &ngapType.DRBStatusDL{Choice: &ngapType.DRBStatusDL12{
				DLCOUNTValue: &ngapType.COUNTValueForPDCPSN12{
					PDCPSN12: int64Pointer(0), HFNPDCPSN12: int64Pointer(0),
				},
			}},
		}},
	}}
}

func goldenHandoverList() ngapType.PDUSessionResourceHandoverList {
	return ngapType.PDUSessionResourceHandoverList{List: []ngapType.PDUSessionResourceHandoverItem{{
		PDUSessionID: &ngapType.PDUSessionID{Value: 1}, HandoverCommandTransfer: octetStringPointer([]byte{1}),
	}}}
}

func goldenHandoverSetupList() ngapType.PDUSessionResourceSetupListHOReq {
	return ngapType.PDUSessionResourceSetupListHOReq{List: []ngapType.PDUSessionResourceSetupItemHOReq{{
		PDUSessionID:            &ngapType.PDUSessionID{Value: 1},
		SNSSAI:                  &ngapType.SNSSAI{SST: &ngapType.SST{Value: aper.OctetString{1}}},
		HandoverRequestTransfer: octetStringPointer([]byte{1}),
	}}}
}

func goldenSwitchedList() ngapType.PDUSessionResourceSwitchedList {
	return ngapType.PDUSessionResourceSwitchedList{List: []ngapType.PDUSessionResourceSwitchedItem{{
		PDUSessionID:                         &ngapType.PDUSessionID{Value: 1},
		PathSwitchRequestAcknowledgeTransfer: octetStringPointer([]byte{1}),
	}}}
}

func goldenUnavailableGUAMIList() ngapType.UnavailableGUAMIList {
	return ngapType.UnavailableGUAMIList{List: []ngapType.UnavailableGUAMIItem{{
		GUAMI: &ngapType.GUAMI{
			PLMNIdentity: &ngapType.PLMNIdentity{Value: aper.OctetString{0x02, 0xf8, 0x39}},
			AMFRegionID:  &ngapType.AMFRegionID{Value: aper.BitString{BitLength: 8, Bytes: []byte{0xca}}},
			AMFSetID:     &ngapType.AMFSetID{Value: aper.BitString{BitLength: 10, Bytes: []byte{0xfe, 0x00}}},
			AMFPointer:   &ngapType.AMFPointer{Value: aper.BitString{BitLength: 6, Bytes: []byte{0x00}}},
		},
		BackupAMFName: &ngapType.AMFName{Value: aper.PrintableString("AMF1")},
	}}}
}

func goldenReleaseList() ngapType.PDUSessionResourceToReleaseListRelCmd {
	return ngapType.PDUSessionResourceToReleaseListRelCmd{List: []ngapType.PDUSessionResourceToReleaseItemRelCmd{{
		PDUSessionID:                             &ngapType.PDUSessionID{Value: 1},
		PDUSessionResourceReleaseCommandTransfer: octetStringPointer([]byte{0x01}),
	}}}
}

func goldenSetupList() *ngapType.PDUSessionResourceSetupListSUReq {
	return &ngapType.PDUSessionResourceSetupListSUReq{List: []ngapType.PDUSessionResourceSetupItemSUReq{{
		PDUSessionID:                           &ngapType.PDUSessionID{Value: 1},
		SNSSAI:                                 &ngapType.SNSSAI{SST: &ngapType.SST{Value: aper.OctetString{1}}},
		PDUSessionResourceSetupRequestTransfer: octetStringPointer([]byte{0x01}),
	}}}
}

func goldenModifyConfirmList() ngapType.PDUSessionResourceModifyListModCfm {
	return ngapType.PDUSessionResourceModifyListModCfm{List: []ngapType.PDUSessionResourceModifyItemModCfm{{
		PDUSessionID:                            &ngapType.PDUSessionID{Value: 1},
		PDUSessionResourceModifyConfirmTransfer: octetStringPointer([]byte{0x01}),
	}}}
}

func goldenModifyRequestList() ngapType.PDUSessionResourceModifyListModReq {
	return ngapType.PDUSessionResourceModifyListModReq{List: []ngapType.PDUSessionResourceModifyItemModReq{{
		PDUSessionID:                            &ngapType.PDUSessionID{Value: 1},
		PDUSessionResourceModifyRequestTransfer: octetStringPointer([]byte{0x01}),
	}}}
}

func goldenCause() ngapType.Cause {
	return ngapType.Cause{Choice: &ngapType.CauseRadioNetwork{Value: 0}}
}

func goldenPathSwitchFailureList() *ngapType.PDUSessionResourceReleasedListPSFail {
	return &ngapType.PDUSessionResourceReleasedListPSFail{
		List: []ngapType.PDUSessionResourceReleasedItemPSFail{{
			PDUSessionID:                          &ngapType.PDUSessionID{Value: 1},
			PathSwitchRequestUnsuccessfulTransfer: octetStringPointer([]byte{1}),
		}},
	}
}

func int64Pointer(value int64) *int64 {
	return &value
}

func octetStringPointer(value []byte) *aper.OctetString {
	octets := aper.OctetString(value)
	return &octets
}

func decodeMessage(t *testing.T, payload []byte) ngapMessage.Message {
	t.Helper()
	msg, err := ngapMessage.Parse(payload)
	require.NoError(t, err)
	require.NotNil(t, msg)
	return msg
}

func goldenProcedureCode(msg ngapMessage.Message) int64 {
	return msg.ProcedureCode()
}
