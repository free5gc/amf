package producer

import (
	"net/http"
	"strconv"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/httpwrapper"
)

type PduSession struct {
	PduSessionId string
	SmContextRef string
	Sst          string
	Sd           string
	Dnn          string
}

type UEContext struct {
	AccessType models.AccessType
	Supi       string
	Guti       string
	/* Tai */
	Mcc string
	Mnc string
	Tac string
	/* PDU sessions */
	PduSessions []PduSession
	/*Connection state */
	CmState models.CmState
}

type UEContexts []UEContext

func HandleOAMRegisteredUEContext(request *httpwrapper.Request) *httpwrapper.Response {
	logger.ProducerLog.Infof("[OAM] Handle Registered UE Context")

	supi := request.Params["supi"]

	ueContexts, problemDetails := OAMRegisteredUEContextProcedure(supi)
	if problemDetails != nil {
		return httpwrapper.NewResponse(int(problemDetails.Status), nil, problemDetails)
	} else {
		return httpwrapper.NewResponse(http.StatusOK, nil, ueContexts)
	}
}

func OAMRegisteredUEContextProcedure(supi string) (UEContexts, *models.ProblemDetails) {
	var ueContexts UEContexts
	amfSelf := context.GetSelf()

	if supi != "" {
		if ue, ok := amfSelf.AmfUeFindBySupi(supi); ok {
			ue.Lock.Lock()
			ueContext := buildUEContext(ue, models.AccessType__3_GPP_ACCESS)
			if ueContext != nil {
				ueContexts = append(ueContexts, *ueContext)
			}
			ueContext = buildUEContext(ue, models.AccessType_NON_3_GPP_ACCESS)
			if ueContext != nil {
				ueContexts = append(ueContexts, *ueContext)
			}
			ue.Lock.Unlock()
		} else {
			problemDetails := &models.ProblemDetails{
				Status: http.StatusNotFound,
				Cause:  "CONTEXT_NOT_FOUND",
			}
			return nil, problemDetails
		}
	} else {
		amfSelf.UePool.Range(func(key, value interface{}) bool {
			ue := value.(*context.AmfUe)
			ue.Lock.Lock()
			ueContext := buildUEContext(ue, models.AccessType__3_GPP_ACCESS)
			if ueContext != nil {
				ueContexts = append(ueContexts, *ueContext)
			}
			ueContext = buildUEContext(ue, models.AccessType_NON_3_GPP_ACCESS)
			if ueContext != nil {
				ueContexts = append(ueContexts, *ueContext)
			}
			ue.Lock.Unlock()
			return true
		})
	}

	return ueContexts, nil
}

func buildUEContext(ue *context.AmfUe, accessType models.AccessType) *UEContext {
	if ue.State[accessType].Is(context.Registered) {
		ueContext := &UEContext{
			AccessType: models.AccessType__3_GPP_ACCESS,
			Supi:       ue.Supi,
			Guti:       ue.Guti,
			Mcc:        ue.Tai.PlmnId.Mcc,
			Mnc:        ue.Tai.PlmnId.Mnc,
			Tac:        ue.Tai.Tac,
		}

		ue.SmContextList.Range(func(key, value interface{}) bool {
			smContext := value.(*context.SmContext)
			if smContext.AccessType() == accessType {
				pduSession := PduSession{
					PduSessionId: strconv.Itoa(int(smContext.PduSessionID())),
					SmContextRef: smContext.SmContextRef(),
					Sst:          strconv.Itoa(int(smContext.Snssai().Sst)),
					Sd:           smContext.Snssai().Sd,
					Dnn:          smContext.Dnn(),
				}
				ueContext.PduSessions = append(ueContext.PduSessions, pduSession)
			}
			return true
		})

		if ue.CmConnect(accessType) {
			ueContext.CmState = models.CmState_CONNECTED
		} else {
			ueContext.CmState = models.CmState_IDLE
		}
		return ueContext
	}
	return nil
}
