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
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/h2non/gock"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	amf_context "github.com/free5gc/amf/internal/context"
	amf_ngap "github.com/free5gc/amf/internal/ngap"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/internal/sbi/processor"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/amf/pkg/service"
	"github.com/free5gc/aper"
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

var (
	mockRAN *amf_context.AmfRan
	RanId   = models.GlobalRanNodeId{
		PlmnId:  &plmnIdModel,
		N3IwfId: "123",
		GNbId: &models.GNbId{
			BitLength: 22,
			GNBValue:  "2a3f44",
		},
		NgeNbId: "2a3f44",
	}
)
var RanListenerIP = "127.0.0.2:38412"

var pduSessionID int32 = 10

var wg sync.WaitGroup

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
				Tac:    "000001",
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

// startSctpMockRAN starts an SCTP listener at listenAddr (e.g. "127.0.0.2:38412").
// It returns a channel that will receive the accepted *sctp.SCTPConn and a stop func.
func startSctpMockRAN(t *testing.T, listenAddr string) (acceptCh chan *sctp.SCTPConn, stop func()) {
	addr, err := sctp.ResolveSCTPAddr("sctp", listenAddr)
	if err != nil {
		t.Fatalf("ResolveSCTPAddr failed: %+v", err)
	}
	ln, err := sctp.ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("ListenSCTP failed: %+v", err)
	}
	acceptCh = make(chan *sctp.SCTPConn, 1)

	wg.Add(1)
	go func() {
		defer wg.Done()

		conn, errAccept := ln.AcceptSCTP(-1) // no timeout.
		if errAccept != nil {
			t.Logf("AcceptSCTP error: %+v", err)
			return
		}
		acceptCh <- conn
		// keep listener open (or close here if only one accept is needed)
	}()

	stop = func() {
		if errClose := ln.Close(); errClose != nil {
			t.Errorf("SCTP Listener Close() error: %s", err.Error())
		}
	}

	// give listener a moment to start
	time.Sleep(10 * time.Millisecond)
	return acceptCh, stop
}

func initAMFConfig(t *testing.T) {
	factory.AmfConfig = &testConfig
	amfContext := amf_context.GetSelf()
	amf_context.InitAmfContext(amfContext)

	// Create remote SCTP address
	remoteAddr, err := sctp.ResolveSCTPAddr("sctp", RanListenerIP)
	if err != nil {
		t.Errorf("initAMFConfig: resolve remote addr error: %+v", err)
		return
	}

	// Create local address
	localAddr, err := sctp.ResolveSCTPAddr("sctp", "127.0.0.18:0")
	if err != nil {
		panic(err)
	}

	// Establish SCTP connection with specified remote address
	conn, err := sctp.DialSCTP("sctp", localAddr, remoteAddr)
	if err != nil {
		t.Errorf("initAMFConfig: dial SCTP error: %+v", err)
		return
	}

	wg.Add(1)
	go func(conn *sctp.SCTPConn) {
		defer wg.Done()

		buf := make([]byte, 65536)

		if n, errRead := conn.Read(buf); errRead == nil {
			amf_ngap.Dispatch(conn, buf[:n])
		}
	}(conn)

	mockRAN = amfContext.NewAmfRan(conn) // Add mock RAN context

	mockRanId := ngapConvert.RanIDToNgap(RanId)
	mockRAN.SetRanId(&mockRanId)
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
		t.Fatalf("MarshalWithParams error in GetSourceToTargetTransparentTransfer: %+v\ndata: %+v", err, data)
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
				Present:          ngapType.InitiatingMessagePresentHandoverRequired,
				HandoverRequired: &ngapType.HandoverRequired{},
			},
		},
	}

	hoRequired := pdu.InitiatingMessage.Value.HandoverRequired

	// AMF UE NGAP ID
	ie := ngapType.HandoverRequiredIEs{}

	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value = ngapType.HandoverRequiredIEsValue{
		Present: ngapType.HandoverRequiredIEsPresentAMFUENGAPID,
		AMFUENGAPID: &ngapType.AMFUENGAPID{
			Value: 2,
		},
	}

	hoRequired.ProtocolIEs.List = append(hoRequired.ProtocolIEs.List, ie)

	// RAN UE NGAP ID
	ie = ngapType.HandoverRequiredIEs{}

	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value = ngapType.HandoverRequiredIEsValue{
		Present: ngapType.HandoverRequiredIEsPresentRANUENGAPID,
		RANUENGAPID: &ngapType.RANUENGAPID{
			Value: 1,
		},
	}

	hoRequired.ProtocolIEs.List = append(hoRequired.ProtocolIEs.List, ie)

	// Handover Type
	ie = ngapType.HandoverRequiredIEs{}

	ie.Id.Value = ngapType.ProtocolIEIDHandoverType
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value = ngapType.HandoverRequiredIEsValue{
		Present: ngapType.HandoverRequiredIEsPresentHandoverType,
		HandoverType: &ngapType.HandoverType{
			Value: ngapType.HandoverTypePresentIntra5gs,
		},
	}

	hoRequired.ProtocolIEs.List = append(hoRequired.ProtocolIEs.List, ie)

	// Cause
	ie = ngapType.HandoverRequiredIEs{}

	ie.Id.Value = ngapType.ProtocolIEIDCause
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value = ngapType.HandoverRequiredIEsValue{
		Present: ngapType.HandoverRequiredIEsPresentCause,
		Cause: &ngapType.Cause{
			Present: ngapType.CausePresentRadioNetwork,
			RadioNetwork: &ngapType.CauseRadioNetwork{
				Value: ngapType.CauseRadioNetworkPresentHandoverDesirableForRadioReason,
			},
		},
	}

	hoRequired.ProtocolIEs.List = append(hoRequired.ProtocolIEs.List, ie)

	// Target ID
	ie = ngapType.HandoverRequiredIEs{}

	ie.Id.Value = ngapType.ProtocolIEIDTargetID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value = ngapType.HandoverRequiredIEsValue{
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
	}

	hoRequired.ProtocolIEs.List = append(hoRequired.ProtocolIEs.List, ie)

	// PDU Session Resource List HO Rqd
	ie = ngapType.HandoverRequiredIEs{}

	ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceListHORqd
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value = ngapType.HandoverRequiredIEsValue{
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
	}

	hoRequired.ProtocolIEs.List = append(hoRequired.ProtocolIEs.List, ie)

	// Source To Target Transparent Container
	ie = ngapType.HandoverRequiredIEs{}

	ie.Id.Value = ngapType.ProtocolIEIDSourceToTargetTransparentContainer
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value = ngapType.HandoverRequiredIEsValue{
		Present: ngapType.HandoverRequiredIEsPresentSourceToTargetTransparentContainer,
		SourceToTargetTransparentContainer: &ngapType.SourceToTargetTransparentContainer{
			Value: sourceToTargetTransparentContainer,
		},
	}

	hoRequired.ProtocolIEs.List = append(hoRequired.ProtocolIEs.List, ie)

	binaryData, err := ngap.Encoder(pdu)
	if err != nil {
		t.Fatalf("NGAP Binary data encoding failure. (%+v)\n", err)
		panic(err)
	}

	return binaryData
}

func buildHandoverRequestAcknowledgeTransfer(t *testing.T) (binaryData []byte) {
	hoReqAckTransfer := ngapType.HandoverRequestAcknowledgeTransfer{}

	// DL NG-U UP TNL Information
	hoReqAckTransfer.DLNGUUPTNLInformation.Present = ngapType.UPTransportLayerInformationPresentGTPTunnel
	hoReqAckTransfer.DLNGUUPTNLInformation.GTPTunnel = &ngapType.GTPTunnel{}

	teidOct := make([]byte, 4) // ref: TS 29.502 V17.1.0 6.1.6.3.2 Simple data types
	binary.BigEndian.PutUint32(teidOct, uint32(0x5bd60076))

	gtpTunnel := hoReqAckTransfer.DLNGUUPTNLInformation.GTPTunnel
	gtpTunnel.TransportLayerAddress.Value.Bytes = net.IP{127, 0, 0, 8}
	gtpTunnel.TransportLayerAddress.Value.BitLength = uint64(len(net.IP{127, 0, 0, 8}) * 8)
	gtpTunnel.GTPTEID.Value = teidOct

	// QoS Flow Setup Response List
	item := ngapType.QosFlowItemWithDataForwarding{}
	item.QosFlowIdentifier.Value = int64(1)
	hoReqAckTransfer.QosFlowSetupResponseList.List = append(hoReqAckTransfer.QosFlowSetupResponseList.List, item)

	binaryData, err := aper.MarshalWithParams(hoReqAckTransfer, "valueExt")
	if err != nil {
		t.Fatalf("aper MarshalWithParams error in GetHandoverRequiredTransfer: %+v", err)
	}

	return binaryData
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func TestHandleCreateUEContextRequest(t *testing.T) {
	logrus.SetLevel(logrus.TraceLevel)

	openapi.InterceptH2CClient()
	defer openapi.RestoreH2CClient()

	acceptCh, stopListener := startSctpMockRAN(t, RanListenerIP)

	initAMFConfig(t)

	// get accepted conn
	conn := <-acceptCh
	if conn == nil {
		t.Fatalf("mock RAN did not accept connection")
	}

	defer func() {
		wg.Wait()

		time.Sleep(50 * time.Millisecond)

		if err := conn.Close(); err.Error() == "SCTPConn: SCTPWrite failed bad file descriptor" {
			t.Log("[T-RAN] SCTP conn closed\n",
				"Don't bother the above \"SCTPConn: SCTPWrite failed bad file descriptor\" message")
		}

		time.Sleep(100 * time.Millisecond)

		stopListener()
		t.Log("[T-RAN] SCTP listener closed\n",
			"Don't bother the above \"SCTP: Failed to shutdown fd operation not supported\" message")
	}()

	// Mock T-RAN: Capture Handover Request NGAP message, and respond with Handover Request Acknowledge.
	// read loop (in goroutine) to capture NGAP messages sent by AMF
	wg.Add(1)
	go func() {
		defer wg.Done()

		buf := make([]byte, 65536)

		n, err := conn.Read(buf)
		if err != nil {
			t.Logf("conn.Read error: %+v", err)
			return
		}
		pdu, err := ngap.Decoder(buf[:n])
		if err != nil {
			t.Logf("ngap decode error: %+v", err)
			return
		}

		// extract HANDOVER REQUEST IEs
		var amfUeNgapId *ngapType.AMFUENGAPID
		// var handoverType *ngapType.HandoverType
		// var ueAggregateMaximumBitRate *ngapType.UEAggregateMaximumBitRate
		// var cause *ngapType.Cause
		// var ueSecurityCapabilities *ngapType.UESecurityCapabilities
		// var securityContext *ngapType.SecurityContext
		var pduSessionResourceSetupListHOReq *ngapType.PDUSessionResourceSetupListHOReq
		// var allowedNSSAI *ngapType.AllowedNSSAI
		// var sourceToTargetTransparentContainer *ngapType.SourceToTargetTransparentContainer
		// var guami *ngapType.GUAMI

		for _, ie := range pdu.InitiatingMessage.Value.HandoverRequest.ProtocolIEs.List {
			switch ie.Id.Value {
			case ngapType.ProtocolIEIDAMFUENGAPID: // mandatory, reject
				amfUeNgapId = ie.Value.AMFUENGAPID
			case ngapType.ProtocolIEIDHandoverType: // mandatory, reject
				// handoverType = ie.Value.HandoverType
			case ngapType.ProtocolIEIDCause: // mandatory, ignore
				// cause = ie.Value.Cause
			case ngapType.ProtocolIEIDUEAggregateMaximumBitRate: // mandatory, reject
				// ueAggregateMaximumBitRate = ie.Value.UEAggregateMaximumBitRate
			case ngapType.ProtocolIEIDUESecurityCapabilities: // mandatory, reject
				// ueSecurityCapabilities = ie.Value.UESecurityCapabilities
			case ngapType.ProtocolIEIDSecurityContext: // mandatory, reject
				// securityContext = ie.Value.SecurityContext
			case ngapType.ProtocolIEIDPDUSessionResourceSetupListHOReq: // mandatory, reject
				pduSessionResourceSetupListHOReq = ie.Value.PDUSessionResourceSetupListHOReq
			case ngapType.ProtocolIEIDAllowedNSSAI: // mandatory, reject
				// allowedNSSAI = ie.Value.AllowedNSSAI
			case ngapType.ProtocolIEIDSourceToTargetTransparentContainer: // mandatory, reject
				// sourceToTargetTransparentContainer = ie.Value.SourceToTargetTransparentContainer
			case ngapType.ProtocolIEIDGUAMI: // mandatory, reject
				// guami = ie.Value.GUAMI
			default:
				switch ie.Criticality.Value {
				case ngapType.CriticalityPresentReject:
					t.Errorf("Not comprehended IE ID 0x%04x (criticality: reject)", ie.Id.Value)
				case ngapType.CriticalityPresentIgnore:
					t.Logf("Not comprehended IE ID 0x%04x (criticality: ignore)", ie.Id.Value)
				case ngapType.CriticalityPresentNotify:
					t.Logf("Not comprehended IE ID 0x%04x (criticality: notify)", ie.Id.Value)
				}
			}
		}

		// Create HANDOVER REQUEST ACKNOWLEDGE message in response to HANDOVER REQUEST
		hoReqAckPdu := ngapType.NGAPPDU{}
		hoReqAckPdu.Present = ngapType.NGAPPDUPresentSuccessfulOutcome
		hoReqAckPdu.SuccessfulOutcome = &ngapType.SuccessfulOutcome{}

		hoReqAckPdu.SuccessfulOutcome.ProcedureCode.Value = ngapType.ProcedureCodeHandoverResourceAllocation
		hoReqAckPdu.SuccessfulOutcome.Criticality.Value = ngapType.CriticalityPresentReject
		hoReqAckPdu.SuccessfulOutcome.Value.Present = ngapType.SuccessfulOutcomePresentHandoverRequestAcknowledge
		hoReqAckPdu.SuccessfulOutcome.Value.HandoverRequestAcknowledge = &ngapType.HandoverRequestAcknowledge{}

		hoReqAckIe := hoReqAckPdu.SuccessfulOutcome.Value.HandoverRequestAcknowledge

		// AMF UE NGAP ID
		ie := ngapType.HandoverRequestAcknowledgeIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
		ie.Value.Present = ngapType.HandoverRequestAcknowledgeIEsPresentAMFUENGAPID

		ie.Value.AMFUENGAPID = amfUeNgapId

		hoReqAckIe.ProtocolIEs.List = append(hoReqAckIe.ProtocolIEs.List, ie)

		// RAN UE NGAP ID
		ie = ngapType.HandoverRequestAcknowledgeIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
		ie.Value.Present = ngapType.HandoverRequestAcknowledgeIEsPresentRANUENGAPID
		ie.Value.RANUENGAPID = &ngapType.RANUENGAPID{
			Value: 1,
		}

		hoReqAckIe.ProtocolIEs.List = append(hoReqAckIe.ProtocolIEs.List, ie)

		// PDU Session Resource Admitted List
		ie = ngapType.HandoverRequestAcknowledgeIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceAdmittedList
		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
		ie.Value.Present = ngapType.HandoverRequestAcknowledgeIEsPresentPDUSessionResourceAdmittedList

		ie.Value.PDUSessionResourceAdmittedList = &ngapType.PDUSessionResourceAdmittedList{}
		if pduSessionResourceSetupListHOReq != nil {
			for _, setupItem := range pduSessionResourceSetupListHOReq.List {
				admittedItem := ngapType.PDUSessionResourceAdmittedItem{
					PDUSessionID:                       setupItem.PDUSessionID,
					HandoverRequestAcknowledgeTransfer: buildHandoverRequestAcknowledgeTransfer(t),
				}
				ie.Value.PDUSessionResourceAdmittedList.List = append(ie.Value.PDUSessionResourceAdmittedList.List, admittedItem)
			}
		}

		hoReqAckIe.ProtocolIEs.List = append(hoReqAckIe.ProtocolIEs.List, ie)

		// PDU Session Resource Failed to Setup List (optional)

		// Target to Source Transparent Container
		ie = ngapType.HandoverRequestAcknowledgeIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDTargetToSourceTransparentContainer
		ie.Criticality.Value = ngapType.CriticalityPresentReject
		ie.Value.Present = ngapType.HandoverRequestAcknowledgeIEsPresentTargetToSourceTransparentContainer

		// TODO
		ie.Value.TargetToSourceTransparentContainer = &ngapType.TargetToSourceTransparentContainer{}

		hoReqAckIe.ProtocolIEs.List = append(hoReqAckIe.ProtocolIEs.List, ie)

		// set SCTP PPID = ngap.PPID (so AMF's SCTP reader treats payload as NGAP)
		if info, errGetParam := conn.GetDefaultSentParam(); errGetParam == nil {
			info.PPID = ngap.PPID
			if err2 := conn.SetDefaultSentParam(info); err2 != nil {
				t.Logf("SetDefaultSentParam error: %+v", err2)
			}
		} else {
			// GetDefaultSentParam may fail for some libs; still try SetDefaultSentParam with new info
			if errGetParam = conn.SetDefaultSentParam(&sctp.SndRcvInfo{PPID: ngap.PPID}); errGetParam != nil {
				t.Errorf("SCTP Conn SetDefaultSentParam error: %s", err.Error())
			}
		}

		buff, err := ngap.Encoder(hoReqAckPdu)
		if err != nil {
			t.Errorf("ngap encode error: %+v", err)
		}

		_, err = conn.Write(buff)
		if err != nil {
			t.Errorf("conn.Write error: %+v", err)
		}
		t.Log("sent HANDOVER REQUEST ACKNOWLEDGE")
	}()

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

	// Setup mock SMF response for UpdateSmContextHandoverBetweenAMF
	defer gock.Off() // Flush pending mocks after test execution

	// build binary data for N2 Information
	resourceSetupRequestTransfer := ngapType.PDUSessionResourceSetupRequestTransfer{}
	// PDU Session Aggregate Maximum Bit Rate (Conditional)
	// UL NG-U UP TNL Information
	ie := ngapType.PDUSessionResourceSetupRequestTransferIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDULNGUUPTNLInformation
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	n3IP := net.IP{127, 0, 0, 8} // ref: config/upfcfg.yaml
	teidOct := make([]byte, 4)   // ref: TS 29.502 V17.1.0 6.1.6.3.2 Simple data types
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
						// ref: smf/internal/context/session_rules.go; int64(sessRule.DefQosQFI),
						Value: int64(1),
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
	p1, err := mw.CreatePart(h1)
	if err != nil {
		t.Errorf("UpdateSmContextHandoverBetweenAMF response Create Part 1 error: %s", err.Error())
	}
	jsonBuf, err := json.Marshal(models.SmContextUpdatedData{
		HoState:      models.HoState_PREPARING,
		N2SmInfoType: models.N2SmInfoType_PDU_RES_SETUP_REQ,
		N2SmInfo: &models.RefToBinaryData{
			ContentId: "PDU_RES_SETUP_REQ",
		},
	})
	if err == nil {
		if _, errWrite := p1.Write(jsonBuf); errWrite != nil {
			t.Errorf("UpdateSmContextHandoverBetweenAMF response write Part 1 error: %s", err.Error())
		}
	}

	// part 2: N2 SM info (PDU Session Resource Setup Request Transfer)
	h2 := textproto.MIMEHeader{}
	h2.Set("Content-Type", "application/vnd.3gpp.ngap")
	h2.Set("Content-ID", "PDU_RES_SETUP_REQ")
	p2, err := mw.CreatePart(h2)
	if err != nil {
		t.Errorf("UpdateSmContextHandoverBetweenAMF response Create Part 2 error: %s", err.Error())
	}
	if _, err = p2.Write(n2Buf); err != nil {
		t.Errorf("UpdateSmContextHandoverBetweenAMF response write Part 2 error: %s", err.Error())
	}

	// Write the closing boundary
	if err = mw.Close(); err != nil {
		t.Errorf("multipart writer Close() error: %s", err.Error())
	}

	gock.New(smfApiRoot).
		Post("/nsmf-pdusession/v1/sm-contexts/"+smCtxReference).
		Times(1).
		Reply(200).
		SetHeader("Content-Type", fmt.Sprintf("multipart/related; boundary=%s", mw.Boundary())).
		Body(bytes.NewReader(buf.Bytes()))

	// Create SMF response for UpdateSmContextN2HandoverPrepared
	var buff bytes.Buffer
	mw2 := multipart.NewWriter(&buff)

	// part 1: JSON metadata
	hd1 := textproto.MIMEHeader{}
	hd1.Set("Content-Type", "application/json")
	pt1, err := mw2.CreatePart(hd1)
	if err != nil {
		t.Errorf("UpdateSmContextN2HandoverPrepared response Create Part 1 error: %s", err.Error())
	}
	jsonBuff, err := json.Marshal(models.SmContextUpdatedData{
		HoState:      models.HoState_PREPARED,
		N2SmInfoType: models.N2SmInfoType_HANDOVER_CMD,
		N2SmInfo: &models.RefToBinaryData{
			ContentId: "HANDOVER_CMD",
		},
	})
	if err == nil {
		if _, err = pt1.Write(jsonBuff); err != nil {
			t.Errorf("UpdateSmContextN2HandoverPrepared response write Part 1 error: %s", err.Error())
		}
	}

	// part 2: N2 SM info (PDU Session Resource Setup Request Transfer)
	hd2 := textproto.MIMEHeader{}
	hd2.Set("Content-Type", "application/vnd.3gpp.ngap")
	hd2.Set("Content-ID", "HANDOVER_CMD")
	pt2, err := mw2.CreatePart(hd2)
	if err != nil {
		t.Errorf("UpdateSmContextN2HandoverPrepared response Create Part 2 error: %s", err.Error())
	}
	if _, err = pt2.Write(n2Buf); err != nil {
		t.Errorf("UpdateSmContextN2HandoverPrepared response write Part 2 error: %s", err.Error())
	}

	// Write the closing boundary
	if err = mw2.Close(); err != nil {
		t.Errorf("multipart writer2 Close() error: %s", err.Error())
	}

	gock.New(smfApiRoot).
		Post("/nsmf-pdusession/v1/sm-contexts/"+smCtxReference).
		Times(1).
		Reply(200).
		SetHeader("Content-Type", fmt.Sprintf("multipart/related; boundary=%s", mw2.Boundary())).
		Body(bytes.NewReader(buff.Bytes()))

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
						AccessType: models.AccessType__3_GPP_ACCESS,
						NasSecurityMode: &models.NasSecurityMode{
							IntegrityAlgorithm: models.IntegrityAlgorithm_NIA2,
							CipheringAlgorithm: models.CipheringAlgorithm_NEA0,
						}, // genNasSecurityMode(),
						UeSecurityCapability: base64.StdEncoding.EncodeToString([]uint8{0x00, 0x00}),
					},
				},
				SessionContextList: []models.PduSessionContext{
					{
						PduSessionId: pduSessionID,
						SmContextRef: smfApiRoot + "/nsmf-pdusession/v1/sm-contexts/" + smCtxReference,
						SNssai:       &testConfig.Configuration.PlmnSupportList[0].SNssaiList[0],
						Dnn:          testConfig.Configuration.SupportDnnList[0],
						AccessType:   models.AccessType__3_GPP_ACCESS,
						// NsInstance: ,
						PlmnId:               &plmnIdModel,
						SmfServiceInstanceId: smfInstanceId,
						// HsmfId: ,
						// VsmfId: ,
					},
				},
				SubUeAmbr: &models.Ambr{
					Uplink:   "1000 Mbps",
					Downlink: "1000 Mbps",
				},
				ServiceAreaRestriction: &models.ServiceAreaRestriction{
					RestrictionType: models.RestrictionType_ALLOWED_AREAS,
					Areas: []models.Area{
						{
							Tacs:     []string{"000001"},
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
			NgapCause: &models.NgApCause{
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
							Supi:      CreateUeContextRequest.JsonData.UeContext.Supi,
							Pei:       CreateUeContextRequest.JsonData.UeContext.Pei,
							SubUeAmbr: CreateUeContextRequest.JsonData.UeContext.SubUeAmbr,
						},
						TargetToSourceData: &models.N2InfoContent{
							NgapIeType: models.AmfCommunicationNgapIeType_TAR_TO_SRC_CONTAINER,
							NgapData: &models.RefToBinaryData{
								ContentId: "N2InfoContent",
							},
						},
						PduSessionList: CreateUeContextRequest.JsonData.PduSessionList,
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
