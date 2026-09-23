package processor

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/metrics/sbi"
)

func (p *Processor) HandleCreateAMFEventSubscription(c *gin.Context,
	createEventSubscription models.Amf_EvtExpos_AmfCreateEventSubscription,
) {
	createdEventSubscription, problemDetails := p.CreateAMFEventSubscriptionProcedure(createEventSubscription)
	if createdEventSubscription != nil {
		c.JSON(http.StatusCreated, createdEventSubscription)
	} else if problemDetails != nil {
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
		c.JSON(int(problemDetails.Status), problemDetails)
	} else {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "UNSPECIFIED_NF_FAILURE",
		}
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
		c.JSON(http.StatusInternalServerError, problemDetails)
	}
}

// TODO: handle event filter
func (p *Processor) CreateAMFEventSubscriptionProcedure(
	createEventSubscription models.Amf_EvtExpos_AmfCreateEventSubscription,
) (
	*models.Amf_EvtExpos_AmfCreatedEventSubscription, *models.ProblemDetails,
) {
	amfSelf := context.GetSelf()

	createdEventSubscription := &models.Amf_EvtExpos_AmfCreatedEventSubscription{}
	subscription := createEventSubscription.Subscription
	if subscription == nil {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusBadRequest,
			Cause:  "SUBSCRIPTION_EMPTY",
		}
		return nil, problemDetails
	}
	contextEventSubscription := &context.AMFContextEventSubscription{}
	contextEventSubscription.EventSubscription = *subscription
	var isImmediate bool
	var immediateFlags []bool
	var reportlist []models.Amf_EvtExpos_AmfEventReport

	id, err := amfSelf.EventSubscriptionIDGenerator.Allocate()
	if err != nil {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "UNSPECIFIED_NF_FAILURE",
		}
		return nil, problemDetails
	}
	newSubscriptionID := strconv.Itoa(int(id))

	// store subscription in context
	ueEventSubscription := context.AmfUeEventSubscription{}
	extCtxEventSub := models.Amf_Comm_ExtAmfEventSubscription{
		EventList:                     contextEventSubscription.EventSubscription.EventList,
		EventNotifyUri:                contextEventSubscription.EventSubscription.EventNotifyUri,
		NotifyCorrelationId:           contextEventSubscription.EventSubscription.NotifyCorrelationId,
		NfId:                          contextEventSubscription.EventSubscription.NfId,
		SubsChangeNotifyUri:           contextEventSubscription.EventSubscription.SubsChangeNotifyUri,
		SubsChangeNotifyCorrelationId: contextEventSubscription.EventSubscription.SubsChangeNotifyCorrelationId,
		Supi:                          contextEventSubscription.EventSubscription.Supi,
		GroupId:                       contextEventSubscription.EventSubscription.GroupId,
		ExcludeSupiList:               contextEventSubscription.EventSubscription.ExcludeSupiList,
		ExcludeGpsiList:               contextEventSubscription.EventSubscription.ExcludeGpsiList,
		IncludeSupiList:               contextEventSubscription.EventSubscription.IncludeSupiList,
		IncludeGpsiList:               contextEventSubscription.EventSubscription.IncludeGpsiList,
		Gpsi:                          contextEventSubscription.EventSubscription.Gpsi,
		Pei:                           contextEventSubscription.EventSubscription.Pei,
		AnyUE:                         contextEventSubscription.EventSubscription.AnyUE,
		Options:                       contextEventSubscription.EventSubscription.Options,
		SourceNfType:                  contextEventSubscription.EventSubscription.SourceNfType,
	}
	ueEventSubscription.EventSubscription = &extCtxEventSub
	ueEventSubscription.Timestamp = time.Now().UTC()

	if subscription.Options != nil && subscription.Options.Trigger == models.Amf_EvtExpos_AmfEventTrigger_CONTINUOUS {
		ueEventSubscription.RemainReports = new(int32)
		*ueEventSubscription.RemainReports = subscription.Options.MaxReports
	}

	if subscription.EventList == nil {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusBadRequest,
			Cause:  "SUBSCRIPTION_EMPTY",
		}
		return nil, problemDetails
	}

	for _, events := range subscription.EventList {
		immediateFlags = append(immediateFlags, events.ImmediateFlag)
		if events.ImmediateFlag {
			isImmediate = true
		}
	}

	if subscription.AnyUE {
		contextEventSubscription.IsAnyUe = true
		ueEventSubscription.AnyUe = true
		amfSelf.UePool.Range(func(key, value interface{}) bool {
			ue := value.(*context.AmfUe)
			ue.Lock.Lock()
			ue.EventSubscriptionsInfo[newSubscriptionID] = new(context.AmfUeEventSubscription)
			*ue.EventSubscriptionsInfo[newSubscriptionID] = ueEventSubscription
			contextEventSubscription.UeSupiList = append(contextEventSubscription.UeSupiList, ue.Supi)
			ue.Lock.Unlock()
			return true
		})
	} else if subscription.GroupId != "" {
		contextEventSubscription.IsGroupUe = true
		ueEventSubscription.AnyUe = true
		amfSelf.UePool.Range(func(key, value interface{}) bool {
			ue := value.(*context.AmfUe)
			ue.Lock.Lock()
			if ue.GroupID == subscription.GroupId {
				ue.EventSubscriptionsInfo[newSubscriptionID] = new(context.AmfUeEventSubscription)
				*ue.EventSubscriptionsInfo[newSubscriptionID] = ueEventSubscription
				contextEventSubscription.UeSupiList = append(contextEventSubscription.UeSupiList, ue.Supi)
			}
			ue.Lock.Unlock()
			return true
		})
	} else {
		if ue, ok := amfSelf.AmfUeFindBySupi(subscription.Supi); !ok {
			problemDetails := &models.ProblemDetails{
				Status: http.StatusForbidden,
				Cause:  "UE_NOT_SERVED_BY_AMF",
			}
			return nil, problemDetails
		} else {
			ue.Lock.Lock()
			ue.EventSubscriptionsInfo[newSubscriptionID] = new(context.AmfUeEventSubscription)
			*ue.EventSubscriptionsInfo[newSubscriptionID] = ueEventSubscription
			contextEventSubscription.UeSupiList = append(contextEventSubscription.UeSupiList, ue.Supi)
			ue.Lock.Unlock()
		}
	}

	// delete subscription
	if subscription.Options != nil {
		contextEventSubscription.Expiry = subscription.Options.Expiry
	}
	amfSelf.NewEventSubscription(newSubscriptionID, contextEventSubscription)

	// build response

	createdEventSubscription.Subscription = subscription
	createdEventSubscription.SubscriptionId = newSubscriptionID

	// for immediate use
	if subscription.AnyUE {
		amfSelf.UePool.Range(func(key, value interface{}) bool {
			ue := value.(*context.AmfUe)
			ue.Lock.Lock()
			defer ue.Lock.Unlock()

			if isImmediate {
				p.subReports(ue, newSubscriptionID)
			}
			for i, flag := range immediateFlags {
				if flag {
					report, ok := p.newAmfEventReport(ue, subscription.EventList[i].Type, newSubscriptionID)
					if ok {
						reportlist = append(reportlist, report)
					}
				}
			}
			// delete subscription
			if reportlistLen := len(reportlist); reportlistLen > 0 && (!reportlist[reportlistLen-1].State.Active) {
				delete(ue.EventSubscriptionsInfo, newSubscriptionID)
			}
			return true
		})
	} else if subscription.GroupId != "" {
		amfSelf.UePool.Range(func(key, value interface{}) bool {
			ue := value.(*context.AmfUe)
			ue.Lock.Lock()
			defer ue.Lock.Unlock()

			if isImmediate {
				p.subReports(ue, newSubscriptionID)
			}
			if ue.GroupID == subscription.GroupId {
				for i, flag := range immediateFlags {
					if flag {
						report, ok := p.newAmfEventReport(ue, subscription.EventList[i].Type, newSubscriptionID)
						if ok {
							reportlist = append(reportlist, report)
						}
					}
				}
				// delete subscription
				if reportlistLen := len(reportlist); reportlistLen > 0 && (!reportlist[reportlistLen-1].State.Active) {
					delete(ue.EventSubscriptionsInfo, newSubscriptionID)
				}
			}
			return true
		})
	} else {
		ue, _ := amfSelf.AmfUeFindBySupi(subscription.Supi)
		ue.Lock.Lock()
		defer ue.Lock.Unlock()

		if isImmediate {
			p.subReports(ue, newSubscriptionID)
		}
		for i, flag := range immediateFlags {
			if flag {
				report, ok := p.newAmfEventReport(ue, subscription.EventList[i].Type, newSubscriptionID)
				if ok {
					reportlist = append(reportlist, report)
				}
			}
		}
		// delete subscription
		if reportlistLen := len(reportlist); reportlistLen > 0 && (!reportlist[reportlistLen-1].State.Active) {
			delete(ue.EventSubscriptionsInfo, newSubscriptionID)
		}
	}
	if len(reportlist) > 0 {
		createdEventSubscription.ReportList = reportlist
		// delete subscription
		if !reportlist[0].State.Active {
			amfSelf.DeleteEventSubscription(newSubscriptionID)
		}
	}

	return createdEventSubscription, nil
}

func (p *Processor) HandleDeleteAMFEventSubscription(c *gin.Context) {
	logger.EeLog.Infoln("Handle Delete AMF Event Subscription")

	subscriptionID := c.Param("subscriptionId")

	problemDetails := p.DeleteAMFEventSubscriptionProcedure(subscriptionID)
	if problemDetails != nil {
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
		c.JSON(int(problemDetails.Status), problemDetails)
	} else {
		// 3GPP TS 29.518 Namf_EventExposure Unsubscribe: successful deletion returns
		// 204 No Content (the generated SBI client only treats 204 as success).
		c.Status(http.StatusNoContent)
	}
}

func (p *Processor) DeleteAMFEventSubscriptionProcedure(subscriptionID string) *models.ProblemDetails {
	amfSelf := context.GetSelf()

	subscription, ok := amfSelf.FindEventSubscription(subscriptionID)
	if !ok {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "SUBSCRIPTION_NOT_FOUND",
		}
		return problemDetails
	}

	for _, supi := range subscription.UeSupiList {
		if ue, okAmfUeFindBySupi := amfSelf.AmfUeFindBySupi(supi); okAmfUeFindBySupi {
			ue.Lock.Lock()
			delete(ue.EventSubscriptionsInfo, subscriptionID)
			ue.Lock.Unlock()
		}
	}
	amfSelf.DeleteEventSubscription(subscriptionID)
	return nil
}

func (p *Processor) HandleModifyAMFEventSubscription(c *gin.Context,
	modifySubscriptionRequest models.ModifySubscriptionRequestBody,
) {
	logger.EeLog.Infoln("Handle Modify AMF Event Subscription")

	subscriptionID := c.Param("subscriptionId")

	updatedEventSubscription, problemDetails := p.
		ModifyAMFEventSubscriptionProcedure(subscriptionID, modifySubscriptionRequest)
	if updatedEventSubscription != nil {
		c.JSON(http.StatusOK, updatedEventSubscription)
	} else if problemDetails != nil {
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
		c.JSON(int(problemDetails.Status), problemDetails)
	} else {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "UNSPECIFIED_NF_FAILURE",
		}
		c.Set(sbi.IN_PB_DETAILS_CTX_STR, problemDetails.Cause)
		c.JSON(http.StatusInternalServerError, problemDetails)
	}
}

func (p *Processor) ModifyAMFEventSubscriptionProcedure(
	subscriptionID string,
	modifySubscriptionRequest models.ModifySubscriptionRequestBody) (
	*models.Amf_EvtExpos_AmfUpdatedEventSubscription, *models.ProblemDetails,
) {
	amfSelf := context.GetSelf()

	contextSubscription, ok := amfSelf.FindEventSubscription(subscriptionID)
	if !ok {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusNotFound,
			Cause:  "SUBSCRIPTION_NOT_FOUND",
		}
		return nil, problemDetails
	}

	if len(modifySubscriptionRequest.AmfUpdateEventOptions) != 0 {
		contextSubscription.Expiry = modifySubscriptionRequest.AmfUpdateEventOptions[0].Value
	} else if len(modifySubscriptionRequest.AmfUpdateEventSubscriptions) != 0 {
		subscription := &contextSubscription.EventSubscription
		if !contextSubscription.IsAnyUe && !contextSubscription.IsGroupUe {
			if _, okAmfUeFindBySupi := amfSelf.AmfUeFindBySupi(subscription.Supi); !okAmfUeFindBySupi {
				problemDetails := &models.ProblemDetails{
					Status: http.StatusForbidden,
					Cause:  "UE_NOT_SERVED_BY_AMF",
				}
				return nil, problemDetails
			}
		}
		op := modifySubscriptionRequest.AmfUpdateEventSubscriptions[0].Op
		// Value shall be present if the patch operation is "add" or "replace"
		if op == "replace" || op == "add" {
			if modifySubscriptionRequest.AmfUpdateEventSubscriptions[0].Value == nil {
				problemDetails := &models.ProblemDetails{
					Status: http.StatusBadRequest,
					Cause:  "MANDATORY_IE_MISSING",
					Detail: "The 'value' attribute is mandatory for 'add' and 'replace' operations",
				}
				return nil, problemDetails
			}
		}
		// TS 29.518 6.2.6.2.14
		path := modifySubscriptionRequest.AmfUpdateEventSubscriptions[0].Path
		prefix := "/eventList/"
		var index int
		if !strings.HasPrefix(path, prefix) || len(path) <= len(prefix) {
			problemDetails := &models.ProblemDetails{
				Status: http.StatusBadRequest,
				Cause:  "MANDATORY_IE_INCORRECT",
				Detail: "Path prefix is invalid or index is missing",
			}
			return nil, problemDetails
		}
		eventlistLen := len(subscription.EventList)
		// 11 is the length of prefix: "/eventList/", the current version only support it.
		if path[11:] == "-" {
			if op != "add" {
				problemDetails := &models.ProblemDetails{
					Status: http.StatusBadRequest,
					Cause:  "MANDATORY_IE_INCORRECT",
					Detail: "The character '-' is only allowed for 'add' operations",
				}
				return nil, problemDetails
			}
		} else {
			var err error
			index, err = strconv.Atoi(path[11:])
			if err != nil {
				problemDetails := &models.ProblemDetails{
					Status: http.StatusBadRequest,
					Cause:  "MANDATORY_IE_INCORRECT",
					Detail: "The array index must be a valid integer",
				}
				return nil, problemDetails
			}
			maxLen := eventlistLen
			if op == "add" {
				maxLen += 1
			}
			if index < 0 || index >= maxLen {
				problemDetails := &models.ProblemDetails{
					Status: http.StatusBadRequest,
					Cause:  "MANDATORY_IE_INCORRECT",
					Detail: "The array index is out of bounds",
				}
				return nil, problemDetails
			}
		}
		lists := (subscription.EventList)
		switch op {
		case "replace":
			event := *modifySubscriptionRequest.AmfUpdateEventSubscriptions[0].Value
			(subscription.EventList)[index] = event
		case "remove":
			eventlist := []models.Amf_EvtExpos_AmfEvent{}
			eventlist = append(eventlist, lists[:index]...)
			eventlist = append(eventlist, lists[index+1:]...)
			subscription.EventList = eventlist
		case "add":
			// TS 29.518 6.2.6.2.14 && RFC 6902
			event := *modifySubscriptionRequest.AmfUpdateEventSubscriptions[0].Value
			eventlist := []models.Amf_EvtExpos_AmfEvent{}
			if path[11:] == "-" {
				eventlist = append(eventlist, lists...)
				eventlist = append(eventlist, event)
			} else {
				eventlist = append(eventlist, lists[:index]...)
				eventlist = append(eventlist, event)
				eventlist = append(eventlist, lists[index:]...)
			}
			subscription.EventList = eventlist
		}
	}

	updatedEventSubscription := &models.Amf_EvtExpos_AmfUpdatedEventSubscription{
		Subscription: &contextSubscription.EventSubscription,
	}
	return updatedEventSubscription, nil
}

func (p *Processor) subReports(ue *context.AmfUe, subscriptionId string) {
	remainReport := ue.EventSubscriptionsInfo[subscriptionId].RemainReports
	if remainReport == nil {
		return
	}
	*remainReport--
}

// DO NOT handle AmfEventType_PRESENCE_IN_AOI_REPORT and AmfEventType_UES_IN_AREA_REPORT(about area)
func (p *Processor) newAmfEventReport(
	ue *context.AmfUe,
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
		report.State.Active = p.getDuration(mode.Expiry, &report.State.RemainDuration)
	case mode.Trigger == models.Amf_EvtExpos_AmfEventTrigger_CONTINUOUS:
		if ueSubscription.RemainReports == nil {
			logger.EeLog.Errorf("RemainReports is nil for CONTINUOUS subscription[%s]", subscriptionId)
			report.State.Active = false
		} else if *ueSubscription.RemainReports <= 0 {
			report.State.Active = false
		} else {
			report.State.Active = p.getDuration(mode.Expiry, &report.State.RemainDuration)
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
			if state.Is(context.Registered) {
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
			if state.Is(context.Registered) {
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

func (p *Processor) getDuration(expiry *time.Time, remainDuration *int32) bool {
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
