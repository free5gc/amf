package ngap

import (
	"fmt"

	"github.com/free5gc/amf/internal/context"
	ngapIE "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	ngapMetrics "github.com/free5gc/util/metrics/ngap"
)

func dispatchMain(ran *context.AmfRan, decoded ngapMessage.Message, encoded []byte) {
	metricOK := false
	defer ngapMetrics.IncrMetricsRcvMsg(messageName(decoded), &metricOK, nil)

	switch message := decoded.(type) {
	case *ngapMessage.NGSetupRequest:
		handleNGSetupRequestMain(
			ran, message.GlobalRANNodeID, message.RANNodeName, message.SupportedTAList,
			message.DefaultPagingDRX, nil,
		)
	case *ngapMessage.UplinkNASTransport:
		if ranUe := findRanUeForMessage(ran, message.AMFUENGAPID, message.RANUENGAPID, false); ranUe != nil {
			handleUplinkNASTransportMain(ran, ranUe, message.NASPDU, message.UserLocationInformation)
		}
	case *ngapMessage.NGReset:
		handleNGResetMain(ran, message.Cause, message.ResetType)
	case *ngapMessage.NGResetAcknowledge:
		handleNGResetAcknowledgeMain(
			ran, message.UEAssociatedLogicalNGConnectionList, message.CriticalityDiagnostics,
		)
	case *ngapMessage.UEContextReleaseComplete:
		if ranUe := findRanUeForMessage(
			ran, message.AMFUENGAPID, message.RANUENGAPID, false, false,
		); ranUe != nil {
			handleUEContextReleaseCompleteMain(
				ran, ranUe, message.UserLocationInformation,
				message.InfoOnRecommendedCellsAndRANNodesForPaging,
				message.PDUSessionResourceListCxtRelCpl, message.CriticalityDiagnostics,
			)
		}
	case *ngapMessage.PDUSessionResourceReleaseResponse:
		if ranUe := findRanUeForMessage(ran, message.AMFUENGAPID, message.RANUENGAPID, false); ranUe != nil {
			handlePDUSessionResourceReleaseResponseMain(
				ran, ranUe, message.PDUSessionResourceReleasedListRelRes,
				message.UserLocationInformation, message.CriticalityDiagnostics,
			)
		}
	case *ngapMessage.UERadioCapabilityCheckResponse:
		if ranUe := findRanUeForMessage(ran, message.AMFUENGAPID, message.RANUENGAPID, false); ranUe != nil {
			handleUERadioCapabilityCheckResponseMain(ran, ranUe, message.CriticalityDiagnostics)
		}
	case *ngapMessage.LocationReportingFailureIndication:
		if ranUe := findRanUeForMessage(ran, message.AMFUENGAPID, message.RANUENGAPID, false); ranUe != nil {
			handleLocationReportingFailureIndicationMain(ran, ranUe, message.Cause)
		}
	case *ngapMessage.InitialUEMessage:
		handleInitialUEMessageMain(
			ran, encoded, message.RANUENGAPID, message.NASPDU,
			message.UserLocationInformation, message.RRCEstablishmentCause,
			message.FiveGSTMSI, message.UEContextRequest,
		)
	case *ngapMessage.PDUSessionResourceSetupResponse:
		if ranUe := findRanUeForMessage(ran, message.AMFUENGAPID, message.RANUENGAPID, false); ranUe != nil {
			handlePDUSessionResourceSetupResponseMain(
				ran, ranUe, message.PDUSessionResourceSetupListSURes,
				message.PDUSessionResourceFailedToSetupListSURes, message.CriticalityDiagnostics,
			)
		}
	case *ngapMessage.PDUSessionResourceModifyResponse:
		if ranUe := findRanUeForMessage(ran, message.AMFUENGAPID, message.RANUENGAPID, false); ranUe != nil {
			handlePDUSessionResourceModifyResponseMain(
				ran, ranUe, message.PDUSessionResourceModifyListModRes,
				message.PDUSessionResourceFailedToModifyListModRes,
				message.UserLocationInformation, message.CriticalityDiagnostics,
			)
		}
	case *ngapMessage.PDUSessionResourceNotify:
		if ranUe := findRanUeForMessage(ran, message.AMFUENGAPID, message.RANUENGAPID, false); ranUe != nil {
			handlePDUSessionResourceNotifyMain(
				ran, ranUe, message.PDUSessionResourceNotifyList,
				message.PDUSessionResourceReleasedListNot, message.UserLocationInformation,
			)
		}
	case *ngapMessage.PDUSessionResourceModifyIndication:
		if ranUe := findRanUeForMessage(ran, message.AMFUENGAPID, message.RANUENGAPID, false); ranUe != nil {
			handlePDUSessionResourceModifyIndicationMain(
				ran, ranUe, message.PDUSessionResourceModifyListModInd,
			)
		}
	case *ngapMessage.InitialContextSetupResponse:
		if ranUe := findRanUeForMessage(ran, message.AMFUENGAPID, message.RANUENGAPID, false); ranUe != nil {
			handleInitialContextSetupResponseMain(
				ran, ranUe, message.PDUSessionResourceSetupListCxtRes,
				message.PDUSessionResourceFailedToSetupListCxtRes, message.CriticalityDiagnostics,
			)
		}
	case *ngapMessage.InitialContextSetupFailure:
		if ranUe := findRanUeForMessage(ran, message.AMFUENGAPID, message.RANUENGAPID, false); ranUe != nil {
			handleInitialContextSetupFailureMain(
				ran, ranUe, message.PDUSessionResourceFailedToSetupListCxtFail,
				message.Cause, message.CriticalityDiagnostics,
			)
		}
	case *ngapMessage.UEContextReleaseRequest:
		if ranUe := findRanUeForMessage(ran, message.AMFUENGAPID, message.RANUENGAPID, false); ranUe != nil {
			handleUEContextReleaseRequestMain(
				ran, ranUe, message.PDUSessionResourceListCxtRelReq, message.Cause,
			)
		}
	case *ngapMessage.UEContextModificationResponse:
		if ranUe := findRanUeForMessage(ran, message.AMFUENGAPID, message.RANUENGAPID, false); ranUe != nil {
			handleUEContextModificationResponseMain(
				ran, ranUe, message.RRCState, message.UserLocationInformation,
				message.CriticalityDiagnostics,
			)
		}
	case *ngapMessage.UEContextModificationFailure:
		if ranUe := findRanUeForMessage(ran, message.AMFUENGAPID, message.RANUENGAPID, false); ranUe != nil {
			handleUEContextModificationFailureMain(
				ran, ranUe, message.Cause, message.CriticalityDiagnostics,
			)
		}
	case *ngapMessage.RRCInactiveTransitionReport:
		if ranUe := findRanUeForMessage(ran, message.AMFUENGAPID, message.RANUENGAPID, false); ranUe != nil {
			handleRRCInactiveTransitionReportMain(
				ran, ranUe, message.RRCState, message.UserLocationInformation,
			)
		}
	case *ngapMessage.HandoverNotify:
		if targetUe := findRanUeForMessage(ran, message.AMFUENGAPID, message.RANUENGAPID, false); targetUe != nil {
			handleHandoverNotifyMain(ran, targetUe, message.UserLocationInformation)
		}
	case *ngapMessage.PathSwitchRequest:
		handlePathSwitchRequestMain(
			ran, message.RANUENGAPID, message.SourceAMFUENGAPID,
			message.UserLocationInformation, message.UESecurityCapabilities,
			message.PDUSessionResourceToBeSwitchedDLList,
			message.PDUSessionResourceFailedToSetupListPSReq,
		)
	case *ngapMessage.HandoverRequestAcknowledge:
		// An acknowledge whose AMF-UE-NGAP-ID and RAN-UE-NGAP-ID both match a
		// connection this NG-RAN node already holds, such as the repeat of an
		// acknowledge already processed, answers no outstanding Handover
		// Resource Allocation. TS 38.413 10.4: a logical error in a response
		// message of a class 1 procedure gets local error handling, so ignore
		// it. An acknowledge with a different RAN-UE-NGAP-ID is still checked
		// as an AP ID error (TS 38.413 10.6) below.
		if message.AMFUENGAPID != nil && message.RANUENGAPID != nil {
			if targetUe := context.GetSelf().RanUeFindByAmfUeNgapID(message.AMFUENGAPID.Value); targetUe != nil &&
				targetUe.Ran == ran && targetUe.RanUeNgapId != context.RanUeNgapIdUnspecified &&
				targetUe.RanUeNgapId == message.RANUENGAPID.Value {
				ran.Log.Warnf("Ignore duplicate HandoverRequestAcknowledge[AmfUeNgapID: %d, RanUeNgapID: %d]",
					targetUe.AmfUeNgapId, targetUe.RanUeNgapId)
				break
			}
		}
		if targetUe := findRanUeForMessage(ran, message.AMFUENGAPID, message.RANUENGAPID, true); targetUe != nil {
			handleHandoverRequestAcknowledgeMain(
				ran, targetUe, message.RANUENGAPID, message.PDUSessionResourceAdmittedList,
				message.PDUSessionResourceFailedToSetupListHOAck,
				message.TargetToSourceTransparentContainer, message.CriticalityDiagnostics,
			)
		}
	case *ngapMessage.HandoverFailure:
		if targetUe := findRanUeForMessage(ran, message.AMFUENGAPID, nil, true); targetUe != nil {
			handleHandoverFailureMain(ran, targetUe, message.Cause, message.CriticalityDiagnostics)
		}
	case *ngapMessage.HandoverRequired:
		if sourceUe := findRanUeForMessage(ran, message.AMFUENGAPID, message.RANUENGAPID, false); sourceUe != nil {
			handleHandoverRequiredMain(
				ran, sourceUe, message.HandoverType, message.Cause, message.TargetID,
				message.PDUSessionResourceListHORqd, message.SourceToTargetTransparentContainer,
			)
		}
	case *ngapMessage.HandoverCancel:
		if sourceUe := findRanUeForMessage(ran, message.AMFUENGAPID, message.RANUENGAPID, false); sourceUe != nil {
			handleHandoverCancelMain(ran, sourceUe, message.Cause)
		}
	case *ngapMessage.UplinkRANStatusTransfer:
		if ranUe := findRanUeForMessage(ran, message.AMFUENGAPID, message.RANUENGAPID, false); ranUe != nil {
			handleUplinkRANStatusTransferMain(
				ran, ranUe, message.RANStatusTransferTransparentContainer,
			)
		}
	case *ngapMessage.NASNonDeliveryIndication:
		if ranUe := findRanUeForMessage(ran, message.AMFUENGAPID, message.RANUENGAPID, false); ranUe != nil {
			handleNASNonDeliveryIndicationMain(ran, ranUe, message.NASPDU, message.Cause)
		}
	case *ngapMessage.RANConfigurationUpdate:
		handleRANConfigurationUpdateMain(ran, message.SupportedTAList, nil)
	case *ngapMessage.UplinkRANConfigurationTransfer:
		handleUplinkRANConfigurationTransferMain(ran, message.SONConfigurationTransferUL)
	case *ngapMessage.UplinkUEAssociatedNRPPaTransport:
		if ranUe := findRanUeForMessage(ran, message.AMFUENGAPID, message.RANUENGAPID, false); ranUe != nil {
			handleUplinkUEAssociatedNRPPaTransportMain(ran, ranUe, message.RoutingID)
		}
	case *ngapMessage.UplinkNonUEAssociatedNRPPaTransport:
		handleUplinkNonUEAssociatedNRPPaTransportMain(ran, message.RoutingID, message.NRPPaPDU)
	case *ngapMessage.LocationReport:
		if ranUe := findRanUeForMessage(ran, message.AMFUENGAPID, message.RANUENGAPID, false); ranUe != nil {
			handleLocationReportMain(
				ran, ranUe, message.UserLocationInformation,
				message.UEPresenceInAreaOfInterestList, message.LocationReportingRequestType,
			)
		}
	case *ngapMessage.UERadioCapabilityInfoIndication:
		if ranUe := findRanUeForMessage(ran, message.AMFUENGAPID, message.RANUENGAPID, false); ranUe != nil {
			handleUERadioCapabilityInfoIndicationMain(
				ran, ranUe, message.UERadioCapability, message.UERadioCapabilityForPaging,
			)
		}
	case *ngapMessage.AMFConfigurationUpdateFailure:
		handleAMFConfigurationUpdateFailureMain(ran, message.Cause, message.CriticalityDiagnostics)
	case *ngapMessage.AMFConfigurationUpdateAcknowledge:
		handleAMFConfigurationUpdateAcknowledgeMain(ran, message.CriticalityDiagnostics)
	case *ngapMessage.ErrorIndication:
		handleErrorIndicationMain(
			ran, message.AMFUENGAPID, message.RANUENGAPID,
			message.Cause, message.CriticalityDiagnostics,
		)
	case *ngapMessage.CellTrafficTrace:
		if ranUe := findRanUeForMessage(ran, message.AMFUENGAPID, message.RANUENGAPID, false); ranUe != nil {
			handleCellTrafficTraceMain(
				ran, ranUe, message.NGRANTraceID, message.NGRANCGI,
				message.TraceCollectionEntityIPAddress,
			)
		}
	default:
		ran.Log.Warnf("Unsupported NGAP message %T", decoded)
		return
	}
	metricOK = true
}

func findRanUeForMessage(
	ran *context.AmfRan,
	amfID *ngapIE.AMFUENGAPID,
	ranID *ngapIE.RANUENGAPID,
	firstReturnedMessage bool,
	sendErrorIndication ...bool,
) *context.RanUe {
	sendError := true
	if len(sendErrorIndication) != 0 {
		sendError = sendErrorIndication[0]
	}
	ranUe, err := ranUeFind(ran, amfID, ranID, firstReturnedMessage, sendError)
	if err != nil {
		ran.Log.Errorf("Find UE context: %v", err)
		return nil
	}
	return ranUe
}

func messageName(decoded ngapMessage.Message) string {
	if decoded == nil {
		return "Unknown"
	}
	return fmt.Sprintf("%T", decoded)[9:]
}
