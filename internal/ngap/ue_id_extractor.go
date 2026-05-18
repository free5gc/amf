package ngap

import (
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

// ExtractUEID performs lightweight NGAP message decoding to extract the UE identifier.
// It returns the UE ID (AMF-UE-NGAP-ID or RAN-UE-NGAP-ID) and a boolean indicating success.
// For messages without a UE ID (e.g., NGSetupRequest), it returns 0 and false.
func ExtractUEID(msg []byte) (uint64, bool) {
	// Decode the NGAP PDU
	pdu, err := ngap.Decoder(msg)
	if err != nil {
		logger.NgapLog.Warnf("Failed to decode NGAP message for UE ID extraction: %v", err)
		return 0, false
	}

	if pdu == nil {
		logger.NgapLog.Trace("NGAP PDU is nil")
		return 0, false
	}

	// Extract UE ID based on message type
	var ueID uint64
	var found bool

	switch pdu.Present {
	case ngapType.NGAPPDUPresentInitiatingMessage:
		ueID, found = extractFromInitiatingMessage(pdu.InitiatingMessage)
	case ngapType.NGAPPDUPresentSuccessfulOutcome:
		ueID, found = extractFromSuccessfulOutcome(pdu.SuccessfulOutcome)
	case ngapType.NGAPPDUPresentUnsuccessfulOutcome:
		ueID, found = extractFromUnsuccessfulOutcome(pdu.UnsuccessfulOutcome)
	default:
		logger.NgapLog.Tracef("Unknown NGAP PDU present type: %d", pdu.Present)
		return 0, false
	}

	if found {
		logger.NgapLog.Tracef("Extracted UE ID: %d", ueID)
	} else {
		logger.NgapLog.Trace("No UE ID found in message (possibly non-UE message)")
	}

	return ueID, found
}

// extractFromInitiatingMessage extracts UE ID from InitiatingMessage
func extractFromInitiatingMessage(msg *ngapType.InitiatingMessage) (uint64, bool) {
	if msg == nil {
		return 0, false
	}

	switch msg.ProcedureCode.Value {
	case ngapType.ProcedureCodeInitialUEMessage:
		// InitialUEMessage contains RAN-UE-NGAP-ID
		if msg.Value.InitialUEMessage != nil {
			for _, ie := range msg.Value.InitialUEMessage.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDRANUENGAPID && ie.Value.RANUENGAPID != nil {
					return uint64(ie.Value.RANUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodeUplinkNASTransport:
		// UplinkNASTransport contains both AMF-UE-NGAP-ID and RAN-UE-NGAP-ID.
		// We prefer extracting the AMF-UE-NGAP-ID if available.
		if msg.Value.UplinkNASTransport != nil {
			for _, ie := range msg.Value.UplinkNASTransport.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodeNASNonDeliveryIndication:
		if msg.Value.NASNonDeliveryIndication != nil {
			for _, ie := range msg.Value.NASNonDeliveryIndication.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodeHandoverPreparation:
		if msg.Value.HandoverRequired != nil {
			for _, ie := range msg.Value.HandoverRequired.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodeHandoverResourceAllocation:
		if msg.Value.HandoverRequest != nil {
			for _, ie := range msg.Value.HandoverRequest.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodeHandoverNotification:
		if msg.Value.HandoverNotify != nil {
			for _, ie := range msg.Value.HandoverNotify.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodePathSwitchRequest:
		if msg.Value.PathSwitchRequest != nil {
			for _, ie := range msg.Value.PathSwitchRequest.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDSourceAMFUENGAPID && ie.Value.SourceAMFUENGAPID != nil {
					return uint64(ie.Value.SourceAMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodeHandoverCancel:
		if msg.Value.HandoverCancel != nil {
			for _, ie := range msg.Value.HandoverCancel.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodeUplinkRANStatusTransfer:
		if msg.Value.UplinkRANStatusTransfer != nil {
			for _, ie := range msg.Value.UplinkRANStatusTransfer.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodeErrorIndication:
		if msg.Value.ErrorIndication != nil {
			for _, ie := range msg.Value.ErrorIndication.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodeUEContextReleaseRequest:
		if msg.Value.UEContextReleaseRequest != nil {
			for _, ie := range msg.Value.UEContextReleaseRequest.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodePDUSessionResourceNotify:
		if msg.Value.PDUSessionResourceNotify != nil {
			for _, ie := range msg.Value.PDUSessionResourceNotify.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodePDUSessionResourceModifyIndication:
		if msg.Value.PDUSessionResourceModifyIndication != nil {
			for _, ie := range msg.Value.PDUSessionResourceModifyIndication.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodeUERadioCapabilityInfoIndication:
		if msg.Value.UERadioCapabilityInfoIndication != nil {
			for _, ie := range msg.Value.UERadioCapabilityInfoIndication.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodeRRCInactiveTransitionReport:
		if msg.Value.RRCInactiveTransitionReport != nil {
			for _, ie := range msg.Value.RRCInactiveTransitionReport.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodeLocationReport:
		if msg.Value.LocationReport != nil {
			for _, ie := range msg.Value.LocationReport.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodeCellTrafficTrace:
		if msg.Value.CellTrafficTrace != nil {
			for _, ie := range msg.Value.CellTrafficTrace.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodeLocationReportingFailureIndication:
		if msg.Value.LocationReportingFailureIndication != nil {
			for _, ie := range msg.Value.LocationReportingFailureIndication.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodeSecondaryRATDataUsageReport:
		if msg.Value.SecondaryRATDataUsageReport != nil {
			for _, ie := range msg.Value.SecondaryRATDataUsageReport.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodeTraceFailureIndication:
		if msg.Value.TraceFailureIndication != nil {
			for _, ie := range msg.Value.TraceFailureIndication.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodeUplinkUEAssociatedNRPPaTransport:
		if msg.Value.UplinkUEAssociatedNRPPaTransport != nil {
			for _, ie := range msg.Value.UplinkUEAssociatedNRPPaTransport.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	default:
		// Non-UE specific messages (e.g., NGSetupRequest, RANConfigurationUpdate)
		logger.NgapLog.Tracef("No UE ID in procedure code: %d", msg.ProcedureCode.Value)
	}

	return 0, false
}

// extractFromSuccessfulOutcome extracts UE ID from SuccessfulOutcome
func extractFromSuccessfulOutcome(msg *ngapType.SuccessfulOutcome) (uint64, bool) {
	if msg == nil {
		return 0, false
	}

	switch msg.ProcedureCode.Value {
	case ngapType.ProcedureCodeInitialContextSetup:
		if msg.Value.InitialContextSetupResponse != nil {
			for _, ie := range msg.Value.InitialContextSetupResponse.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodePDUSessionResourceSetup:
		if msg.Value.PDUSessionResourceSetupResponse != nil {
			for _, ie := range msg.Value.PDUSessionResourceSetupResponse.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodePDUSessionResourceRelease:
		if msg.Value.PDUSessionResourceReleaseResponse != nil {
			for _, ie := range msg.Value.PDUSessionResourceReleaseResponse.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodePDUSessionResourceModify:
		if msg.Value.PDUSessionResourceModifyResponse != nil {
			for _, ie := range msg.Value.PDUSessionResourceModifyResponse.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodeUEContextModification:
		if msg.Value.UEContextModificationResponse != nil {
			for _, ie := range msg.Value.UEContextModificationResponse.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodeUEContextRelease:
		if msg.Value.UEContextReleaseComplete != nil {
			for _, ie := range msg.Value.UEContextReleaseComplete.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodeHandoverResourceAllocation:
		if msg.Value.HandoverRequestAcknowledge != nil {
			for _, ie := range msg.Value.HandoverRequestAcknowledge.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodePathSwitchRequest:
		if msg.Value.PathSwitchRequestAcknowledge != nil {
			for _, ie := range msg.Value.PathSwitchRequestAcknowledge.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodeUERadioCapabilityCheck:
		if msg.Value.UERadioCapabilityCheckResponse != nil {
			for _, ie := range msg.Value.UERadioCapabilityCheckResponse.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	default:
		logger.NgapLog.Tracef("No UE ID in successful outcome procedure code: %d", msg.ProcedureCode.Value)
	}

	return 0, false
}

// extractFromUnsuccessfulOutcome extracts UE ID from UnsuccessfulOutcome
func extractFromUnsuccessfulOutcome(msg *ngapType.UnsuccessfulOutcome) (uint64, bool) {
	if msg == nil {
		return 0, false
	}

	switch msg.ProcedureCode.Value {
	case ngapType.ProcedureCodeInitialContextSetup:
		if msg.Value.InitialContextSetupFailure != nil {
			for _, ie := range msg.Value.InitialContextSetupFailure.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodeHandoverResourceAllocation:
		if msg.Value.HandoverFailure != nil {
			for _, ie := range msg.Value.HandoverFailure.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodePathSwitchRequest:
		if msg.Value.PathSwitchRequestFailure != nil {
			for _, ie := range msg.Value.PathSwitchRequestFailure.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	case ngapType.ProcedureCodeUEContextModification:
		if msg.Value.UEContextModificationFailure != nil {
			for _, ie := range msg.Value.UEContextModificationFailure.ProtocolIEs.List {
				if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID && ie.Value.AMFUENGAPID != nil {
					return uint64(ie.Value.AMFUENGAPID.Value), true
				}
			}
		}

	default:
		logger.NgapLog.Tracef("No UE ID in unsuccessful outcome procedure code: %d", msg.ProcedureCode.Value)
	}

	return 0, false
}
