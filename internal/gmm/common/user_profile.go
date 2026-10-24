package common

import (
	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	business_metrics "github.com/free5gc/amf/internal/metrics/business"
	ngap_message "github.com/free5gc/amf/internal/ngap/message"
	"github.com/free5gc/amf/internal/sbi/consumer"
	ngapType "github.com/free5gc/ngap/ie"
	"github.com/free5gc/openapi/models"
)

func RemoveAmfUe(ue *context.AmfUe, notifyNF bool) {
	if notifyNF {
		// notify SMF to release all sessions
		ue.SmContextList.Range(func(key, value interface{}) bool {
			smContext := value.(*context.SmContext)

			problemDetail, err := consumer.GetConsumer().SendReleaseSmContextRequest(ue, smContext, nil, "", nil)
			if problemDetail != nil {
				ue.GmmLog.Errorf("Release SmContext Failed Problem[%+v]", problemDetail)
			} else if err != nil {
				ue.GmmLog.Errorf("Release SmContext Error[%v]", err.Error())
			}
			return true
		})

		// notify PCF to terminate AmPolicy association
		if ue.AmPolicyAssociation != nil {
			problemDetails, err := consumer.GetConsumer().AMPolicyControlDelete(ue)
			if problemDetails != nil {
				ue.GmmLog.Errorf("AM Policy Control Delete Failed Problem[%+v]", problemDetails)
			} else if err != nil {
				ue.GmmLog.Errorf("AM Policy Control Delete Error[%v]", err.Error())
			}
		}
	}

	PurgeAmfUeSubscriberData(ue)
	ue.Remove()
}

func PurgeAmfUeSubscriberData(ue *context.AmfUe) {
	if ue.GetRanUe(models.AccessType_3_GPP_ACCESS) != nil {
		err := PurgeSubscriberData(ue, models.AccessType_3_GPP_ACCESS)
		if err != nil {
			logger.GmmLog.Errorf("Purge subscriber data Error[%v]", err.Error())
		}
	}
	if ue.GetRanUe(models.AccessType_NON_3_GPP_ACCESS) != nil {
		err := PurgeSubscriberData(ue, models.AccessType_NON_3_GPP_ACCESS)
		if err != nil {
			logger.GmmLog.Errorf("Purge subscriber data Error[%v]", err.Error())
		}
	}
}

func AttachRanUeToAmfUeAndReleaseOldIfAny(amfUe *context.AmfUe, ranUe *context.RanUe) {
	if oldRanUe := linkNewRanUe(amfUe, ranUe); oldRanUe != nil {
		oldRanUe.Log.Infof("Implicit Deregistration - RanUeNgapID[%d]", oldRanUe.RanUeNgapId)
		oldRanUe.DetachAmfUe()
		causeGroup := ngap_message.CauseChoiceRadioNetwork
		causeValue := ngapType.CauseRadioNetworkPresentReleaseDueToNgranGeneratedReason
		ngap_message.SendUEContextReleaseCommand(oldRanUe, context.UeContextReleaseUeContext, causeGroup, causeValue)
	}
}

// linkNewRanUe links ranUe to amfUe and returns the RanUe it replaced, if any,
// after stopping the old connection's 5GMM timers.  Both happen under RanUeMu,
// so concurrent attaches to one pooled AmfUe neither write the map at the same
// time nor stop the same timer twice (a second Timer.Stop panics).  The caller
// releases the old RanUe after the lock is dropped: the release sends an NGAP
// message to the old gNB, and a gNB that stops reading must not block every
// reader of this AmfUe.  The unlock is deferred so that a panic in the timer
// stop, which ends the NGAP worker, does not also leave RanUeMu locked for
// every other user of the AmfUe.
func linkNewRanUe(amfUe *context.AmfUe, ranUe *context.RanUe) *context.RanUe {
	amfUe.RanUeMu.Lock()
	defer amfUe.RanUeMu.Unlock()

	oldRanUe := amfUe.RanUe[ranUe.Ran.AnType]
	if oldRanUe == nil {
		// We don't increase in AttachRanUe because we don't want to fidle with the counters in a ngap handover procedure
		if amfUe.AnTypeFlags[ranUe.Ran.AnType] {
			business_metrics.DecrUeCmIdleStateGauge(ranUe.Ran.AnType)
		}
		business_metrics.IncrUeCmConnectedStateGauge(ranUe.Ran.AnType)
		if amfUe.State[ranUe.Ran.AnType] != nil && amfUe.State[ranUe.Ran.AnType].Is(context.Registered) {
			business_metrics.IncrUeConnectivityGauge(ranUe.Ran.AnType)
		}
		amfUe.AnTypeFlags[ranUe.Ran.AnType] = true
	}
	amfUe.AttachRanUeLocked(ranUe)
	if oldRanUe != nil {
		if amfUe.HasT3550() {
			amfUe.State[ranUe.Ran.AnType].Set(context.Registered)
		}
		StopAll5GSMMTimers(amfUe)
	}
	return oldRanUe
}

func AttachRanUeToAmfUeAndReleaseOldHandover(amfUe *context.AmfUe, sourceRanUe, targetRanUe *context.RanUe) {
	logger.GmmLog.Debugln("In AttachRanUeToAmfUeAndReleaseOldHandover")

	linkHandoverTarget(amfUe, sourceRanUe, targetRanUe)
	if sourceRanUe != nil {
		sourceRanUe.DetachAmfUe()
		causeGroup := ngap_message.CauseChoiceRadioNetwork
		causeValue := ngapType.CauseRadioNetworkPresentSuccessfulHandover
		ngap_message.SendUEContextReleaseCommand(sourceRanUe, context.UeContextReleaseHandover, causeGroup, causeValue)
	} else {
		// This function will be call only by N2 Handover, so we can assume sourceRanUe will not be nil
		logger.GmmLog.Errorln("AttachRanUeToAmfUeAndReleaseOldHandover() is called but sourceRanUe is nil")
	}
	if sourceRanUe != nil && sourceRanUe.Ran != nil &&
		amfUe.OnGoing(sourceRanUe.Ran.AnType).Procedure == context.OnGoingProcedureN2Handover {
		amfUe.SetOnGoing(sourceRanUe.Ran.AnType, &context.OnGoing{
			Procedure: context.OnGoingProcedureNothing,
		})
	}
}

// linkHandoverTarget links targetRanUe to amfUe and, if there is a source
// RanUe, stops the 5GMM timers, under RanUeMu as in linkNewRanUe.  The caller
// releases the source after the lock is dropped.
func linkHandoverTarget(amfUe *context.AmfUe, sourceRanUe, targetRanUe *context.RanUe) {
	amfUe.RanUeMu.Lock()
	defer amfUe.RanUeMu.Unlock()

	amfUe.AttachRanUeLocked(targetRanUe)
	if sourceRanUe != nil {
		if amfUe.HasT3550() {
			amfUe.State[targetRanUe.Ran.AnType].Set(context.Registered)
		}
		StopAll5GSMMTimers(amfUe)
	}
}

func ClearHoldingRanUe(ranUe *context.RanUe) {
	if ranUe != nil {
		amfUe := ranUe.GetAmfUe()
		if amfUe != nil && amfUe.State[ranUe.Ran.AnType] != nil {
			if amfUe.State[ranUe.Ran.AnType].Is(context.Registered) && amfUe.CmConnect(ranUe.Ran.AnType) {
				business_metrics.DecrUeConnectivityGauge(ranUe.Ran.AnType)
			}
		}
		ranUe.DetachAmfUe()
		ranUe.Log.Infof("Clear Holding RanUE")
		causeGroup := ngap_message.CauseChoiceRadioNetwork
		causeValue := ngapType.CauseRadioNetworkPresentReleaseDueToNgranGeneratedReason
		ngap_message.SendUEContextReleaseCommand(ranUe, context.UeContextReleaseUeContext, causeGroup, causeValue)
	} else {
		logger.GmmLog.Warnf("RanUE is nil")
	}
}

func PurgeSubscriberData(ue *context.AmfUe, accessType models.AccessType) error {
	logger.GmmLog.Debugln("PurgeSubscriberData")

	if !ue.ContextValid {
		return nil
	}
	// Purge of subscriber data in AMF described in TS 23.502 4.5.3
	if ue.SdmSubscriptionId != "" {
		problemDetails, err := consumer.GetConsumer().SDMUnsubscribe(ue)
		if problemDetails != nil {
			logger.GmmLog.Errorf("SDM Unubscribe Failed Problem[%+v]", problemDetails)
		} else if err != nil {
			logger.GmmLog.Errorf("SDM Unubscribe Error[%+v]", err)
		}
		ue.SdmSubscriptionId = ""
	}

	if ue.UeCmRegistered[accessType] {
		problemDetails, err := consumer.GetConsumer().UeCmDeregistration(ue, accessType)
		if problemDetails != nil {
			logger.GmmLog.Errorf("UECM Deregistration Failed Problem[%+v]", problemDetails)
		} else if err != nil {
			logger.GmmLog.Errorf("UECM Deregistration Error[%+v]", err)
		}
		ue.UeCmRegistered[accessType] = false
	}
	return nil
}
