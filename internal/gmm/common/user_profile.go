package common

import (
	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	ngap_message "github.com/free5gc/amf/internal/ngap/message"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/openapi/models"
)

func RemoveAmfUe(ue *context.AmfUe, notifyNF bool) {
	if notifyNF {
		// notify SMF to release all sessions
		ue.SmContextList.Range(func(key, value interface{}) bool {
			smContext := value.(*context.SmContext)

			problemDetail, err := consumer.SendReleaseSmContextRequest(ue, smContext, nil, "", nil)
			if problemDetail != nil {
				ue.GmmLog.Errorf("Release SmContext Failed Problem[%+v]", problemDetail)
			} else if err != nil {
				ue.GmmLog.Errorf("Release SmContext Error[%v]", err.Error())
			}
			return true
		})

		// notify PCF to terminate AmPolicy association
		if ue.AmPolicyAssociation != nil {
			problemDetails, err := consumer.AMPolicyControlDelete(ue)
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
	if ue.RanUe[models.AccessType__3_GPP_ACCESS] != nil {
		err := purgeSubscriberData(ue, models.AccessType__3_GPP_ACCESS)
		if err != nil {
			logger.GmmLog.Errorf("Purge subscriber data Error[%v]", err.Error())
		}
	}
	if ue.RanUe[models.AccessType_NON_3_GPP_ACCESS] != nil {
		err := purgeSubscriberData(ue, models.AccessType_NON_3_GPP_ACCESS)
		if err != nil {
			logger.GmmLog.Errorf("Purge subscriber data Error[%v]", err.Error())
		}
	}
}

func AttachRanUeToAmfUeAndReleaseOldIfAny(ue *context.AmfUe, ranUe *context.RanUe) {
	if oldRanUe := ue.RanUe[ranUe.Ran.AnType]; oldRanUe != nil {
		oldRanUe.Log.Infof("Implicit Deregistration - RanUeNgapID[%d]", oldRanUe.RanUeNgapId)
		oldRanUe.DetachAmfUe()
		if ue.T3550 != nil {
			ue.State[ranUe.Ran.AnType].Set(context.Registered)
		}
		StopAll5GSMMTimers(ue)
		causeGroup := ngapType.CausePresentRadioNetwork
		causeValue := ngapType.CauseRadioNetworkPresentReleaseDueToNgranGeneratedReason
		ngap_message.SendUEContextReleaseCommand(oldRanUe, context.UeContextReleaseUeContext, causeGroup, causeValue)
	}
	ue.AttachRanUe(ranUe)
}

func purgeSubscriberData(ue *context.AmfUe, accessType models.AccessType) error {
	logger.GmmLog.Debugln("purgeSubscriberData")

	if !ue.ContextValid {
		return nil
	}
	// Purge of subscriber data in AMF described in TS 23.502 4.5.3
	if ue.SdmSubscriptionId != "" {
		problemDetails, err := consumer.SDMUnsubscribe(ue)
		if problemDetails != nil {
			logger.GmmLog.Errorf("SDM Unubscribe Failed Problem[%+v]", problemDetails)
		} else if err != nil {
			logger.GmmLog.Errorf("SDM Unubscribe Error[%+v]", err)
		}
		ue.SdmSubscriptionId = ""
	}

	if ue.UeCmRegistered[accessType] {
		problemDetails, err := consumer.UeCmDeregistration(ue, accessType)
		if problemDetails != nil {
			logger.GmmLog.Errorf("UECM_Registration Failed Problem[%+v]", problemDetails)
		} else if err != nil {
			logger.GmmLog.Errorf("UECM_Registration Error[%+v]", err)
		}
		ue.UeCmRegistered[accessType] = false
	}
	return nil
}
