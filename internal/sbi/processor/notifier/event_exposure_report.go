package callback

import (
	"time"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/openapi/models"
)

// periodicReportTickUnit scales AmfEventMode.RepPeriod (seconds, TS 29.518)
// into a ticker duration. Tests shrink this to keep PERIODIC coverage fast.
var periodicReportTickUnit = time.Second

func SubReports(ue *amf_context.AmfUe, subscriptionId string) {
	remainReport := ue.EventSubscriptionsInfo[subscriptionId].RemainReports
	if remainReport == nil {
		return
	}
	*remainReport--
}

// StartPeriodicReporting starts the per-(ue,subscription) ticker for a
// PERIODIC Namf_EventExposure subscription (TS 29.518 AmfEventMode.repPeriod).
// Caller must hold ue.Lock; sub must be the entry just stored at
// ue.EventSubscriptionsInfo[subscriptionId].
func StartPeriodicReporting(ue *amf_context.AmfUe, subscriptionId string, sub *amf_context.AmfUeEventSubscription) {
	opts := sub.EventSubscription.Options
	if opts == nil || opts.Trigger != models.Amf_EvtExpos_AmfEventTrigger_PERIODIC || opts.RepPeriod <= 0 {
		return
	}
	stop := make(chan struct{})
	sub.StopChan = stop
	go runPeriodicReporting(ue, subscriptionId, time.Duration(opts.RepPeriod)*periodicReportTickUnit, stop)
}

// StopPeriodicReportingLocked closes the running ticker, if any, for
// subscriptionId on ue. Caller must hold ue.Lock, and must still delete the
// map entry itself afterwards.
func StopPeriodicReportingLocked(ue *amf_context.AmfUe, subscriptionId string) {
	if sub, ok := ue.EventSubscriptionsInfo[subscriptionId]; ok && sub.StopChan != nil {
		close(sub.StopChan)
	}
}

func runPeriodicReporting(ue *amf_context.AmfUe, subscriptionId string, period time.Duration, stop chan struct{}) {
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if !firePeriodicReport(ue, subscriptionId) {
				return
			}
		}
	}
}

// firePeriodicReport builds and sends one PERIODIC report round, bundling a
// report for every event in the subscription's EventList into a single
// notification. It returns false once the subscription is gone or expired,
// telling the caller to stop ticking.
func firePeriodicReport(ue *amf_context.AmfUe, subscriptionId string) bool {
	ue.Lock.Lock()
	sub, ok := ue.EventSubscriptionsInfo[subscriptionId]
	if !ok {
		ue.Lock.Unlock()
		return false
	}

	var reports []models.Amf_EvtExpos_AmfEventReport
	active := true
	for _, ev := range sub.EventSubscription.EventList {
		report, okReport := NewAmfEventReport(ue, ev.Type, subscriptionId)
		if !okReport {
			continue
		}
		reports = append(reports, report)
		if !report.State.Active {
			active = false
		}
	}
	subExt := sub.EventSubscription
	if !active {
		delete(ue.EventSubscriptionsInfo, subscriptionId)
	}
	ue.Lock.Unlock()

	if len(reports) > 0 {
		SendAmfEventNotify(subExt, reports)
	}
	return active
}

// FireContinuousEventReport evaluates every CONTINUOUS-trigger
// Namf_EventExposure subscription on ue whose EventList includes eventType,
// and delivers a notification for each one that is still active (TS 29.518
// AmfEventMode.trigger = CONTINUOUS). Call this from the GMM state
// transition that corresponds to eventType.
func FireContinuousEventReport(ue *amf_context.AmfUe, eventType models.Amf_EvtExpos_AmfEventType) {
	type delivery struct {
		sub    *models.Amf_Comm_ExtAmfEventSubscription
		report models.Amf_EvtExpos_AmfEventReport
	}
	var toSend []delivery

	ue.Lock.Lock()
	for subscriptionId, sub := range ue.EventSubscriptionsInfo {
		opts := sub.EventSubscription.Options
		if opts == nil || opts.Trigger != models.Amf_EvtExpos_AmfEventTrigger_CONTINUOUS {
			continue
		}
		subscribed := false
		for _, ev := range sub.EventSubscription.EventList {
			if ev.Type == eventType {
				subscribed = true
				break
			}
		}
		if !subscribed {
			continue
		}

		SubReports(ue, subscriptionId)
		report, ok := NewAmfEventReport(ue, eventType, subscriptionId)
		if !ok {
			continue
		}
		toSend = append(toSend, delivery{sub.EventSubscription, report})
		if !report.State.Active {
			StopPeriodicReportingLocked(ue, subscriptionId)
			delete(ue.EventSubscriptionsInfo, subscriptionId)
		}
	}
	ue.Lock.Unlock()

	for _, d := range toSend {
		SendAmfEventNotify(d.sub, []models.Amf_EvtExpos_AmfEventReport{d.report})
	}
}

// DO NOT handle AmfEventType_PRESENCE_IN_AOI_REPORT and AmfEventType_UES_IN_AREA_REPORT(about area)
func NewAmfEventReport(
	ue *amf_context.AmfUe,
	amfEventType models.Amf_EvtExpos_AmfEventType,
	subscriptionId string,
) (
	report models.Amf_EvtExpos_AmfEventReport, ok bool,
) {
	ueSubscription, ok := ue.EventSubscriptionsInfo[subscriptionId]
	if !ok {
		return report, ok
	}

	report.AnyUe = ueSubscription.AnyUe
	report.Supi = ue.Supi
	report.Type = amfEventType
	report.TimeStamp = &ueSubscription.Timestamp
	report.State = new(models.Amf_EvtExpos_AmfEventState)
	mode := ueSubscription.EventSubscription.Options
	switch {
	case mode == nil:
		report.State.Active = true
	case mode.Trigger == models.Amf_EvtExpos_AmfEventTrigger_ONE_TIME:
		report.State.Active = false
	case mode.Trigger == models.Amf_EvtExpos_AmfEventTrigger_PERIODIC:
		report.State.Active = getDuration(mode.Expiry, &report.State.RemainDuration)
	case mode.Trigger == models.Amf_EvtExpos_AmfEventTrigger_CONTINUOUS:
		if ueSubscription.RemainReports == nil {
			logger.EeLog.Errorf("RemainReports is nil for CONTINUOUS subscription[%s]", subscriptionId)
			report.State.Active = false
		} else if *ueSubscription.RemainReports <= 0 {
			report.State.Active = false
		} else {
			report.State.Active = getDuration(mode.Expiry, &report.State.RemainDuration)
			if report.State.Active {
				report.State.RemainReports = *ueSubscription.RemainReports
			}
		}
	default:
		report.State.Active = false
	}

	switch amfEventType {
	case models.Amf_EvtExpos_AmfEventType_LOCATION_REPORT:
		report.Location = &ue.Location
	// case models.Amf_EvtExpos_AmfEventType_PRESENCE_IN_AOI_REPORT:
	// report.AreaList = (*subscription.EventList)[eventIndex].AreaList
	case models.Amf_EvtExpos_AmfEventType_TIMEZONE_REPORT:
		report.Timezone = ue.TimeZone
	case models.Amf_EvtExpos_AmfEventType_ACCESS_TYPE_REPORT:
		for accessType, state := range ue.State {
			if state.Is(amf_context.Registered) {
				report.AccessTypeList = append(report.AccessTypeList, accessType)
			}
		}
	case models.Amf_EvtExpos_AmfEventType_REGISTRATION_STATE_REPORT:
		var rmInfos []models.Amf_EvtExpos_RmInfo
		for accessType, state := range ue.State {
			rmInfo := models.Amf_EvtExpos_RmInfo{
				RmState:    models.Amf_EvtExpos_RmState_DEREGISTERED,
				AccessType: accessType,
			}
			if state.Is(amf_context.Registered) {
				rmInfo.RmState = models.Amf_EvtExpos_RmState_REGISTERED
			}
			rmInfos = append(rmInfos, rmInfo)
		}
		report.RmInfoList = rmInfos
	case models.Amf_EvtExpos_AmfEventType_CONNECTIVITY_STATE_REPORT:
		report.CmInfoList = ue.GetCmInfo()
	case models.Amf_EvtExpos_AmfEventType_REACHABILITY_REPORT:
		report.Reachability = ue.Reachability
	case models.Amf_EvtExpos_AmfEventType_COMMUNICATION_FAILURE_REPORT:
		// TODO : report.CommFailure
	case models.Amf_EvtExpos_AmfEventType_SUBSCRIPTION_ID_CHANGE:
		report.SubscriptionId = subscriptionId
	case models.Amf_EvtExpos_AmfEventType_SUBSCRIPTION_ID_ADDITION:
		report.SubscriptionId = subscriptionId
	}
	return report, ok
}

func getDuration(expiry *time.Time, remainDuration *int32) bool {
	if expiry != nil {
		if time.Now().After(*expiry) {
			return false
		} else {
			duration := time.Until(*expiry)
			*remainDuration = int32(duration.Seconds())
		}
	}
	return true
}
