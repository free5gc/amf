package processor_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/internal/sbi/processor"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/amf/pkg/service"
	"github.com/free5gc/aper"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/httpwrapper"
)

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
				PlmnId: &models.PlmnId{
					Mcc: "208",
					Mnc: "93",
				},
				Tac: "000001",
			},
		},
		PlmnSupportList: []factory.PlmnSupportItem{
			{
				PlmnId: &models.PlmnId{
					Mcc: "208",
					Mnc: "93",
				},
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

func initAMFConfig() {
	factory.AmfConfig = &testConfig
	amfContext := amf_context.GetSelf()
	amf_context.InitAmfContext(amfContext)
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
											GlobalRANNodeID: ngapType.GlobalRANNodeID{
												Present: ngapType.GlobalRANNodeIDPresentGlobalGNBID,
												GlobalGNBID: &ngapType.GlobalGNBID{
													PLMNIdentity: ngapType.PLMNIdentity{
														Value: aper.OctetString("\x02\xf8\x39"),
													},
													GNBID: ngapType.GNBID{
														Present: ngapType.GNBIDPresentGNBID,
														GNBID: &aper.BitString{
															Bytes:     targetGNBID,
															BitLength: uint64(len(targetGNBID) * 8),
														},
													},
												},
											},
											SelectedTAI: ngapType.TAI{
												PLMNIdentity: ngapType.PLMNIdentity{
													Value: aper.OctetString("\x02\xf8\x39"),
												},
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
													Value: 10,
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

func TestHandleCreateUEContextRequest(t *testing.T) {
	openapi.InterceptH2CClient()
	defer openapi.RestoreH2CClient()
	initAMFConfig()

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
						UeSecurityCapability: "2e02f0f0",
					},
				},
			},
			TargetId: &models.NgRanTargetId{
				RanNodeId: &models.GlobalRanNodeId{
					PlmnId: &models.PlmnId{
						Mcc: "208",
						Mnc: "93",
					},
					N3IwfId: "123",
					GNbId: &models.GNbId{
						BitLength: 123,
						GNBValue:  "string",
					},
					NgeNbId: "string",
				},
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
					PduSessionId: 1,
				},
			},
			N2NotifyUri:       "127.0.0.1",
			UeRadioCapability: nil,
			NgapCause:         nil,
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
	var TestPlmn ngapType.PLMNIdentity
	TestPlmn.Value = aper.OctetString("\x02\xf8\x39")

	// RRC Container
	data.RRCContainer.Value = aper.OctetString("\x00\x00\x11")

	// PDU Session Resource Information List
	data.PDUSessionResourceInformationList = new(ngapType.PDUSessionResourceInformationList)
	infoItem := ngapType.PDUSessionResourceInformationItem{}
	infoItem.PDUSessionID.Value = 10
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
