package processor_test

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"syscall"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/h2non/gock"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/internal/sbi/processor"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/amf/pkg/service"
	"github.com/free5gc/aper"

	/*	"github.com/free5gc/nas/nasMessage"
		"github.com/free5gc/nas/nasType"
		"github.com/free5gc/nas/security" */
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapConvert"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/sctp"
	"github.com/free5gc/util/httpwrapper"
)

var plmnIdModel = models.PlmnId{
	Mcc: "208",
	Mnc: "93",
}
var TestPlmn = ngapConvert.PlmnIdToNgap(plmnIdModel)

// Mock AMF Config, copied from free5gc/config/amfcfg.yaml
var testConfig = factory.Config{
	Info: &factory.Info{
		Version:     "v1.0.0",
		Description: "AMF test Configuration",
	},
	Configuration: &factory.Configuration{
		AmfName: "TestAMF",
		NgapIpList: []string{
			"127.0.0.18",
		},
		NgapPort: 38412,
		Sbi: &factory.Sbi{
			Scheme:       "http",
			RegisterIPv4: "127.0.0.18",
			BindingIPv4:  "127.0.0.18",
			Port:         8000,
		},
		ServiceNameList: []string{
			"namf-comm",
			"namf-evts",
			"namf-mt",
			"namf-loc",
			"namf-oam",
		},
		ServedGumaiList: []models.Guami{
			{
				PlmnId: &models.PlmnIdNid{
					Mcc: "208",
					Mnc: "93",
				},
				AmfId: "cafe56",
			},
		},
		SupportTAIList: []models.Tai{
			{
				PlmnId: &plmnIdModel,
				Tac: "000001",
			},
		},
		PlmnSupportList: []factory.PlmnSupportItem{
			{
				PlmnId: &plmnIdModel,
				SNssaiList: []models.Snssai{
					{
						Sst: 1,
						Sd:  "010203",
					},
					{
						Sst: 1,
						Sd:  "112233",
					},
				},
			},
		},
		SupportDnnList: []string{
			"internet",
		},
		NrfUri: "http://127.0.0.10:8000",
		Security: &factory.Security{
			IntegrityOrder: []string{
				"NIA2",
			},
			CipheringOrder: []string{
				"NEA0",
				"NEA2",
			},
		},
		NetworkName: factory.NetworkName{
			Full:  "free5GC",
			Short: "free",
		},
		NgapIE: &factory.NgapIE{
			MobilityRestrictionList: &factory.MobilityRestrictionList{
				Enable: true,
			},
			MaskedIMEISV: &factory.MaskedIMEISV{
				Enable: true,
			},
			RedirectionVoiceFallback: &factory.RedirectionVoiceFallback{
				Enable: false,
			},
		},
		NasIE: &factory.NasIE{
			NetworkFeatureSupport5GS: &factory.NetworkFeatureSupport5GS{
				Enable:  true,
				Length:  1,
				ImsVoPS: 0,
				Emc:     0,
				Emf:     0,
				IwkN26:  0,
				Mpsi:    0,
				EmcN3:   0,
				Mcsi:    0,
			},
		},
		T3502Value:             720,
		T3512Value:             3600,
		Non3gppDeregTimerValue: 3240,
		T3513: factory.TimerValue{
			Enable:        true,
			ExpireTime:    6 * time.Second,
			MaxRetryTimes: 4,
		},
		T3522: factory.TimerValue{
			Enable:        true,
			ExpireTime:    6 * time.Second,
			MaxRetryTimes: 4,
		},
		T3550: factory.TimerValue{
			Enable:        true,
			ExpireTime:    6 * time.Second,
			MaxRetryTimes: 4,
		},
		T3555: factory.TimerValue{
			Enable:        true,
			ExpireTime:    6 * time.Second,
			MaxRetryTimes: 4,
		},
		T3560: factory.TimerValue{
			Enable:        true,
			ExpireTime:    6 * time.Second,
			MaxRetryTimes: 4,
		},
		T3565: factory.TimerValue{
			Enable:        true,
			ExpireTime:    6 * time.Second,
			MaxRetryTimes: 4,
		},
		T3570: factory.TimerValue{
			Enable:        true,
			ExpireTime:    6 * time.Second,
			MaxRetryTimes: 4,
		},
	},
	Logger: &factory.Logger{
		Enable:       true,
		Level:        "trace",
		ReportCaller: false,
	},
}

var mockRAN *amf_context.AmfRan
var RanId = models.GlobalRanNodeId{
	PlmnId: &plmnIdModel,
	N3IwfId: "123",
	GNbId: &models.GNbId{
		BitLength: 22,
		GNBValue:  "2a3f44",
	},
	NgeNbId: "2a3f44",
}

var pduSessionID int32 = 10

func initAMFConfig(t *testing.T) {
	factory.AmfConfig = &testConfig
	amfContext := amf_context.GetSelf()
	amf_context.InitAmfContext(amfContext)

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_SEQPACKET, syscall.IPPROTO_SCTP) // Initialize SCTP socket
	if err != nil {
		t.Errorf("initAMFConfig: create socket error: %+v", err)
	}

	conn := sctp.NewSCTPConn(fd, nil)

	addr := new(sctp.SCTPAddr)
	addr.IPAddrs = []net.IPAddr{
		{
			IP: net.IPv4(127, 0, 0, 2),
		},
	}
	addr.Port = 38412
	sctp.SCTPBind(fd, addr, sctp.SCTP_BINDX_ADD_ADDR)

	mockRAN = amfContext.NewAmfRan(conn) // Add a dummy RAN context

	t.Logf("mockRan remote addr: %+v\n", mockRAN.Conn.RemoteAddr())

	// targetGNBID := []byte("string")
	mockRanId := ngapConvert.RanIDToNgap(RanId)
	t.Logf("mockRanId: %x (bit length: %d)",
		mockRanId.GlobalGNBID.GNBID.GNBID.Bytes, mockRanId.GlobalGNBID.GNBID.GNBID.BitLength)
	mockRAN.SetRanId(&mockRanId)
	t.Logf("mockRAN ID: %s", mockRAN.RanID())
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func buildHandoverRequiredTransfer() (data ngapType.HandoverRequiredTransfer) {
	data.DirectForwardingPathAvailability = new(ngapType.DirectForwardingPathAvailability)
	data.DirectForwardingPathAvailability.Value = ngapType.DirectForwardingPathAvailabilityPresentDirectPathAvailable
	return data
}

func getHandoverRequiredTransfer(t *testing.T) []byte {
	data := buildHandoverRequiredTransfer()
	encodeData, err := aper.MarshalWithParams(data, "valueExt")
	if err != nil {
		t.Fatalf("aper MarshalWithParams error in GetHandoverRequiredTransfer: %+v", err)
	}
	return encodeData
}

func buildSourceToTargetTransparentTransfer(
	targetGNBID []byte, targetCellID []byte,
) (data ngapType.SourceNGRANNodeToTargetNGRANNodeTransparentContainer) {
	// RRC Container
	data.RRCContainer.Value = aper.OctetString("\x00\x00\x11")

	// PDU Session Resource Information List
	data.PDUSessionResourceInformationList = new(ngapType.PDUSessionResourceInformationList)
	infoItem := ngapType.PDUSessionResourceInformationItem{}
	infoItem.PDUSessionID.Value = int64(pduSessionID)
	qosItem := ngapType.QosFlowInformationItem{}
	qosItem.QosFlowIdentifier.Value = 1
	infoItem.QosFlowInformationList.List = append(infoItem.QosFlowInformationList.List, qosItem)
	data.PDUSessionResourceInformationList.List = append(data.PDUSessionResourceInformationList.List, infoItem)

	// Target Cell ID
	data.TargetCellID.Present = ngapType.TargetIDPresentTargetRANNodeID
	data.TargetCellID.NRCGI = new(ngapType.NRCGI)
	data.TargetCellID.NRCGI.PLMNIdentity = TestPlmn
	data.TargetCellID.NRCGI.NRCellIdentity.Value = aper.BitString{
		Bytes:     append(targetGNBID, targetCellID...),
		BitLength: 36,
	}

	// UE History Information
	lastVisitedCellItem := ngapType.LastVisitedCellItem{}
	lastVisitedCellInfo := &lastVisitedCellItem.LastVisitedCellInformation
	lastVisitedCellInfo.Present = ngapType.LastVisitedCellInformationPresentNGRANCell
	lastVisitedCellInfo.NGRANCell = new(ngapType.LastVisitedNGRANCellInformation)
	ngRanCell := lastVisitedCellInfo.NGRANCell
	ngRanCell.GlobalCellID.Present = ngapType.NGRANCGIPresentNRCGI
	ngRanCell.GlobalCellID.NRCGI = new(ngapType.NRCGI)
	ngRanCell.GlobalCellID.NRCGI.PLMNIdentity = TestPlmn
	ngRanCell.GlobalCellID.NRCGI.NRCellIdentity.Value = aper.BitString{
		Bytes:     []byte{0x00, 0x00, 0x00, 0x00, 0x10},
		BitLength: 36,
	}
	ngRanCell.CellType.CellSize.Value = ngapType.CellSizePresentVerysmall
	ngRanCell.TimeUEStayedInCell.Value = 10

	data.UEHistoryInformation.List = append(data.UEHistoryInformation.List, lastVisitedCellItem)
	return data
}

func getSourceToTargetTransparentTransfer(targetGNBID []byte, targetCellID []byte, t *testing.T) []byte {
	data := buildSourceToTargetTransparentTransfer(targetGNBID, targetCellID)
	encodeData, err := aper.MarshalWithParams(data, "valueExt")
	if err != nil {
		t.Fatalf("aper MarshalWithParams error in GetSourceToTargetTransparentTransfer: %+v\ndata: %+v", err, data)
	}
	return encodeData
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func buildHandoverRequiredNGAPBinaryData(t *testing.T) []byte {
	targetGNBID := []byte{0x00, 0x01, 0x02}
	targetCellID := []byte{0x01, 0x20}
	handoverRequiredTransfer := getHandoverRequiredTransfer(t)
	sourceToTargetTransparentContainer := getSourceToTargetTransparentTransfer(targetGNBID, targetCellID, t)

	pdu := ngapType.NGAPPDU{
		Present: ngapType.NGAPPDUPresentInitiatingMessage,
		InitiatingMessage: &ngapType.InitiatingMessage{
			ProcedureCode: ngapType.ProcedureCode{
				Value: ngapType.ProcedureCodeHandoverPreparation,
			},
			Criticality: ngapType.Criticality{
				Value: ngapType.CriticalityPresentReject,
			},
			Value: ngapType.InitiatingMessageValue{
				Present: ngapType.InitiatingMessagePresentHandoverRequired,
				HandoverRequired: &ngapType.HandoverRequired{
					ProtocolIEs: ngapType.ProtocolIEContainerHandoverRequiredIEs{
						List: []ngapType.HandoverRequiredIEs{
							{
								Id: ngapType.ProtocolIEID{
									Value: ngapType.ProtocolIEIDAMFUENGAPID,
								},
								Criticality: ngapType.Criticality{
									Value: ngapType.CriticalityPresentIgnore,
								},
								Value: ngapType.HandoverRequiredIEsValue{
									Present: ngapType.HandoverRequiredIEsPresentAMFUENGAPID,
									AMFUENGAPID: &ngapType.AMFUENGAPID{
										Value: 2,
									},
								},
							},
							{
								Id: ngapType.ProtocolIEID{
									Value: ngapType.ProtocolIEIDRANUENGAPID,
								},
								Criticality: ngapType.Criticality{
									Value: ngapType.CriticalityPresentIgnore,
								},
								Value: ngapType.HandoverRequiredIEsValue{
									Present: ngapType.HandoverRequiredIEsPresentRANUENGAPID,
									RANUENGAPID: &ngapType.RANUENGAPID{
										Value: 1,
									},
								},
							},
							{
								Id: ngapType.ProtocolIEID{
									Value: ngapType.ProtocolIEIDHandoverType,
								},
								Criticality: ngapType.Criticality{
									Value: ngapType.CriticalityPresentReject,
								},
								Value: ngapType.HandoverRequiredIEsValue{
									Present: ngapType.HandoverRequiredIEsPresentHandoverType,
									HandoverType: &ngapType.HandoverType{
										Value: ngapType.HandoverTypePresentIntra5gs,
									},
								},
							},
							{
								Id: ngapType.ProtocolIEID{
									Value: ngapType.ProtocolIEIDCause,
								},
								Criticality: ngapType.Criticality{
									Value: ngapType.CriticalityPresentIgnore,
								},
								Value: ngapType.HandoverRequiredIEsValue{
									Present: ngapType.HandoverRequiredIEsPresentCause,
									Cause: &ngapType.Cause{
										Present: ngapType.CausePresentRadioNetwork,
										RadioNetwork: &ngapType.CauseRadioNetwork{
											Value: ngapType.CauseRadioNetworkPresentHandoverDesirableForRadioReason,
										},
									},
								},
							},
							{
								Id: ngapType.ProtocolIEID{
									Value: ngapType.ProtocolIEIDTargetID,
								},
								Criticality: ngapType.Criticality{
									Value: ngapType.CriticalityPresentReject,
								},
								Value: ngapType.HandoverRequiredIEsValue{
									Present: ngapType.HandoverRequiredIEsPresentTargetID,
									TargetID: &ngapType.TargetID{
										Present: ngapType.TargetIDPresentTargetRANNodeID,
										TargetRANNodeID: &ngapType.TargetRANNodeID{
											GlobalRANNodeID: ngapConvert.RanIDToNgap(RanId),
											SelectedTAI: ngapType.TAI{
												PLMNIdentity: TestPlmn,
												TAC: ngapType.TAC{
													Value: aper.OctetString("\x30\x33\x99"),
												},
											},
										},
									},
								},
							},
							{
								Id: ngapType.ProtocolIEID{
									Value: ngapType.ProtocolIEIDPDUSessionResourceListHORqd,
								},
								Criticality: ngapType.Criticality{
									Value: ngapType.CriticalityPresentReject,
								},
								Value: ngapType.HandoverRequiredIEsValue{
									Present: ngapType.HandoverRequiredIEsPresentPDUSessionResourceListHORqd,
									PDUSessionResourceListHORqd: &ngapType.PDUSessionResourceListHORqd{
										List: []ngapType.PDUSessionResourceItemHORqd{
											{
												PDUSessionID: ngapType.PDUSessionID{
													Value: int64(pduSessionID),
												},
												HandoverRequiredTransfer: handoverRequiredTransfer,
											},
										},
									},
								},
							},
							{
								Id: ngapType.ProtocolIEID{
									Value: ngapType.ProtocolIEIDSourceToTargetTransparentContainer,
								},
								Criticality: ngapType.Criticality{
									Value: ngapType.CriticalityPresentReject,
								},
								Value: ngapType.HandoverRequiredIEsValue{
									Present: ngapType.HandoverRequiredIEsPresentSourceToTargetTransparentContainer,
									SourceToTargetTransparentContainer: &ngapType.SourceToTargetTransparentContainer{
										Value: sourceToTargetTransparentContainer,
									},
								},
							},
						},
					},
				},
			},
		},
	}
	binaryData, err := ngap.Encoder(pdu)
	if err != nil {
		t.Fatalf("NGAP Binary data encoding failure. (%+v)\n", err)
		panic(err)
	}

	return binaryData
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func TestHandleCreateUEContextRequest(t *testing.T) {
	openapi.InterceptH2CClient()
	defer openapi.RestoreH2CClient()
	initAMFConfig(t)

	// Setup mock AMF
	mockAMF := service.NewMockAmfAppInterface(gomock.NewController(t))
	consumer, err := consumer.NewConsumer(mockAMF)
	if err != nil {
		t.Fatalf("Failed to create consumer: %+v", err)
	}

	processor, err := processor.NewProcessor(mockAMF)
	if err != nil {
		t.Fatalf("Failed to create processor: %+v", err)
	}

	service.AMF = mockAMF

	mockAMF.EXPECT().Context().Return(amf_context.GetSelf()).AnyTimes()
	mockAMF.EXPECT().Consumer().Return(consumer).AnyTimes()

	// create SmContext for UE
	smfApiRoot := "http://127.0.0.1"
	smCtxReference := uuid.New().URN()
	smfInstanceId := uuid.New().String()

	// TODO: Setup mock SMF response
	defer gock.Off() // Flush pending mocks after test execution

	// build binary data for N2 Information
	resourceSetupRequestTransfer := ngapType.PDUSessionResourceSetupRequestTransfer{}
	// PDU Session Aggregate Maximum Bit Rate (Conditional)
	// UL NG-U UP TNL Information
	ie := ngapType.PDUSessionResourceSetupRequestTransferIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDULNGUUPTNLInformation
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	n3IP := net.IP{127, 0, 0, 8} // ref: config/upfcfg.yaml
	teidOct := make([]byte, 4) // ref: TS 29.502 V17.1.0 6.1.6.3.2 Simple data types
	binary.BigEndian.PutUint32(teidOct, uint32(0x5bd60076))
	ie.Value = ngapType.PDUSessionResourceSetupRequestTransferIEsValue{
		Present: ngapType.PDUSessionResourceSetupRequestTransferIEsPresentULNGUUPTNLInformation,
		ULNGUUPTNLInformation: &ngapType.UPTransportLayerInformation{
			Present: ngapType.UPTransportLayerInformationPresentGTPTunnel,
			GTPTunnel: &ngapType.GTPTunnel{
				TransportLayerAddress: ngapType.TransportLayerAddress{
					Value: aper.BitString{
						Bytes:     n3IP,
						BitLength: uint64(len(n3IP) * 8),
					},
				},
				GTPTEID: ngapType.GTPTEID{Value: teidOct},
			},
		},
	}
	resourceSetupRequestTransfer.ProtocolIEs.List = append(resourceSetupRequestTransfer.ProtocolIEs.List, ie)

	// PDU Session Type
	ie = ngapType.PDUSessionResourceSetupRequestTransferIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDPDUSessionType
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value = ngapType.PDUSessionResourceSetupRequestTransferIEsValue{
		Present: ngapType.PDUSessionResourceSetupRequestTransferIEsPresentPDUSessionType,
		PDUSessionType: &ngapType.PDUSessionType{
			Value: ngapType.PDUSessionTypePresentIpv4,
		},
	}
	resourceSetupRequestTransfer.ProtocolIEs.List = append(resourceSetupRequestTransfer.ProtocolIEs.List, ie)

	// QoS Flow Setup Request List
	// use Default 5qi, arp

	authDefQos := models.AuthorizedDefaultQos{
		Var5qi: 9,
		Arp: &models.Arp{
			PriorityLevel: 8,
		},
		PriorityLevel: 8,
	} // ref: smf/internal/sbi/processor/pdu_session_test.go; sessRule.AuthDefQos
	ie = ngapType.PDUSessionResourceSetupRequestTransferIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDQosFlowSetupRequestList
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value = ngapType.PDUSessionResourceSetupRequestTransferIEsValue{
		Present: ngapType.PDUSessionResourceSetupRequestTransferIEsPresentQosFlowSetupRequestList,
		QosFlowSetupRequestList: &ngapType.QosFlowSetupRequestList{
			List: []ngapType.QosFlowSetupRequestItem{
				{
					QosFlowIdentifier: ngapType.QosFlowIdentifier{
						Value: int64(1), // ref: smf/internal/context/session_rules.go; int64(sessRule.DefQosQFI),
					},
					QosFlowLevelQosParameters: ngapType.QosFlowLevelQosParameters{
						QosCharacteristics: ngapType.QosCharacteristics{
							Present: ngapType.QosCharacteristicsPresentNonDynamic5QI,
							NonDynamic5QI: &ngapType.NonDynamic5QIDescriptor{
								FiveQI: ngapType.FiveQI{
									Value: int64(authDefQos.Var5qi),
								},
							},
						},
						AllocationAndRetentionPriority: ngapType.AllocationAndRetentionPriority{
							PriorityLevelARP: ngapType.PriorityLevelARP{
								Value: int64(authDefQos.Arp.PriorityLevel),
							},
							PreEmptionCapability: ngapType.PreEmptionCapability{
								Value: ngapType.PreEmptionCapabilityPresentShallNotTriggerPreEmption,
							},
							PreEmptionVulnerability: ngapType.PreEmptionVulnerability{
								Value: ngapType.PreEmptionVulnerabilityPresentNotPreEmptable,
							},
						},
					},
				},
			},
		},
	}
	resourceSetupRequestTransfer.ProtocolIEs.List = append(resourceSetupRequestTransfer.ProtocolIEs.List, ie)

	n2Buf, err := aper.MarshalWithParams(resourceSetupRequestTransfer, "valueExt")
	if err != nil {
		fmt.Printf("encode resourceSetupRequestTransfer failed: %s", err)
	}

	// Build multipart/related message
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	// part 1: JSON metadata
	h1 := textproto.MIMEHeader{}
	h1.Set("Content-Type", "application/json")
	p1, _ := mw.CreatePart(h1)
	jsonBuf, err := json.Marshal(models.SmContextUpdatedData{
		HoState: models.HoState_PREPARING,
		N2SmInfoType: models.N2SmInfoType_PDU_RES_SETUP_REQ,
		N2SmInfo: &models.RefToBinaryData{
			ContentId: "PDU_RES_SETUP_REQ",
		},
	})
	if err == nil {
		p1.Write(jsonBuf)
	}

	// part 2: N2 SM info (PDU Session Resource Setup Request Transfer)
	h2 := textproto.MIMEHeader{}
	h2.Set("Content-Type", "application/vnd.3gpp.ngap")
	h2.Set("Content-ID", "PDU_RES_SETUP_REQ")
	p2, _ := mw.CreatePart(h2)
	p2.Write(n2Buf)

	// Write the closing boundary
	mw.Close()

	gock.New(smfApiRoot).
	     Post("/nsmf-pdusession/v1/sm-contexts/" + smCtxReference).
		 Reply(200).
		 SetHeader("Content-Type", fmt.Sprintf("multipart/related; boundary=%s", mw.Boundary())).
		 Body(bytes.NewReader(buf.Bytes()))

	// generate testing UE NasSecurityMode.
/*	genNasSecurityMode := func() *models.NasSecurityMode {
		amfUe := amf_context.GetSelf().NewAmfUe("imsi-2089300007487")

		amfUe.IntegrityAlg = security.AlgIntegrity128NIA2
		amfUe.CipheringAlg = security.AlgCiphering128NEA0

		amfUe.UESecurityCapability = nasType.UESecurityCapability{ // free5gc/test/ranUe.go: GetUESecurityCapability()
		    Iei:    nasMessage.RegistrationRequestUESecurityCapabilityType,
		    Len:    2,
		    Buffer: []uint8{0x00, 0x00},
	    }
		
		amfUe.UESecurityCapability.SetEA0_5G(1)
		amfUe.UESecurityCapability.SetIA2_128_5G(1)

		NasSecurityMode := new(models.NasSecurityMode)
		NasSecurityMode.IntegrityAlgorithm = models.IntegrityAlgorithm_NIA2
		NasSecurityMode.CipheringAlgorithm = models.CipheringAlgorithm_NEA0

		return NasSecurityMode
	} */

	CreateUeContextRequest := models.CreateUeContextRequest{
		JsonData: &models.UeContextCreateData{
			UeContext: &models.UeContext{
				Supi: "imsi-2089300007487",
				RestrictedRatList: []models.RatType{
					models.RatType_NR,
				},
				Pei: "imeisv-1234567890123412",
				MmContextList: []models.MmContext{
					{
						AccessType:           models.AccessType__3_GPP_ACCESS,
						NasSecurityMode: &models.NasSecurityMode{
							IntegrityAlgorithm: models.IntegrityAlgorithm_NIA2,
							CipheringAlgorithm: models.CipheringAlgorithm_NEA0,
						}, // genNasSecurityMode(),
						UeSecurityCapability: base64.StdEncoding.EncodeToString([]uint8{0x00, 0x00}), // "2e02f0f0",
					},
				},
				SessionContextList: []models.PduSessionContext{
					{
						PduSessionId: pduSessionID,
						SmContextRef: smfApiRoot + "/nsmf-pdusession/v1/sm-contexts/" + smCtxReference,
						SNssai: &testConfig.Configuration.PlmnSupportList[0].SNssaiList[0],
						Dnn: testConfig.Configuration.SupportDnnList[0],
						AccessType: models.AccessType__3_GPP_ACCESS,
						// NsInstance: ,
						PlmnId: &plmnIdModel,
						SmfServiceInstanceId: smfInstanceId,
						// HsmfId: ,
						// VsmfId: ,
					},
				},
				SubUeAmbr: &models.Ambr{
					Uplink: "1000 Mbps",
					Downlink: "1000 Mbps",
				},
				ServiceAreaRestriction: &models.ServiceAreaRestriction{
					RestrictionType: models.RestrictionType_ALLOWED_AREAS,
					Areas: []models.Area{
						{
							Tacs: []string{"000001"},
							AreaCode: "+886", // free5gc/test/consumerTestdata/PCF/TestAMPolicy/AMPolicy.go
						},
					},
				},
			},
			TargetId: &models.NgRanTargetId{
				RanNodeId: &RanId,
				Tai: &models.Tai{
					PlmnId: &models.PlmnId{
						Mcc: "208",
						Mnc: "93",
					},
					Tac: "000001",
				},
			},
			SourceToTargetData: &models.N2InfoContent{
				NgapMessageType: 0,
				NgapIeType:      "HANDOVER_REQUIRED",
				NgapData: &models.RefToBinaryData{
					ContentId: "N2SmInfo",
				},
			},
			PduSessionList: []models.N2SmInformation{
				{
					PduSessionId: pduSessionID,
				},
			},
			N2NotifyUri:       "127.0.0.1",
			UeRadioCapability: nil,
			NgapCause:         &models.NgApCause{
				Group: 0, // radioNetwork, based on TS 29.571 Type: NgApCause
				Value: int32(ngapType.CauseRadioNetworkPresentNgIntraSystemHandoverTriggered),
			},
			SupportedFeatures: "",
		},
		BinaryDataN2Information: buildHandoverRequiredNGAPBinaryData(t),
	}
	testCases := []struct {
		testDescription   string
		resultDescription string
		request           models.CreateUeContextRequest
		responseBody      any
		expectedHTTPResp  *httpwrapper.Response
	}{
		{
			testDescription:   "Valid Request",
			resultDescription: "",
			request:           CreateUeContextRequest,
			responseBody:      &models.CreateUeContextResponse201{},
			expectedHTTPResp: &httpwrapper.Response{
				Header: nil,
				Status: http.StatusCreated,
				Body: models.CreateUeContextResponse201{
					JsonData: &models.UeContextCreatedData{
						UeContext: &models.UeContext{
							Supi: CreateUeContextRequest.JsonData.UeContext.Supi,
						},
						PduSessionList:   CreateUeContextRequest.JsonData.PduSessionList,
						PcfReselectedInd: false,
					},
				},
			},
		},
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.testDescription, func(t *testing.T) {
			httpRecorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(httpRecorder)

			processor.HandleCreateUEContextRequest(c, tc.request)

			httpResp := httpRecorder.Result()
			if errClose := httpResp.Body.Close(); errClose != nil {
				t.Fatalf("Failed to close response body: %+v", errClose)
			}

			rawBytes, errReadAll := io.ReadAll(httpResp.Body)
			if errReadAll != nil {
				t.Fatalf("Failed to read response body: %+v", errReadAll)
			}

			err = openapi.Deserialize(tc.responseBody, rawBytes, httpResp.Header.Get("Content-Type"))
			if err != nil {
				t.Fatalf("Failed to deserialize response body: %+v", err)
			}

			respBytes, errMarshal := json.Marshal(tc.responseBody)
			if errMarshal != nil {
				t.Fatalf("Failed to marshal actual response body: %+v", errMarshal)
			}

			expectedBytes, errMarshal := json.Marshal(tc.expectedHTTPResp.Body)
			if errMarshal != nil {
				t.Fatalf("Failed to marshal expected response body: %+v", errMarshal)
			}

			require.Equal(t, tc.expectedHTTPResp.Status, httpResp.StatusCode)
			require.Equal(t, expectedBytes, respBytes)

			// wait for another go-routine to execute following procedure
			time.Sleep(100 * time.Millisecond)
		})
	}

	require.NoError(t, err)
}
