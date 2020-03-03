package amf_producer

import (
	"gofree5gc/lib/openapi/models"
	"gofree5gc/src/amf/amf_context"
	"gofree5gc/src/amf/amf_handler/amf_message"
	"gofree5gc/src/amf/gmm/gmm_state"
	"gofree5gc/src/amf/logger"
	"net/http"
)

type PduSession struct {
	PduSessionId int32
	Snssai       models.Snssai
	Dnn          string
}

type UEContext struct {
	AccessType  models.AccessType
	Supi        string
	Guti        string
	Tai         models.Tai
	PduSessions []PduSession
	CmState     models.CmState
}

type UEContexts struct {
	UEContexts []UEContext
}

func HandleOAMRegisteredUEContext(httpChannel chan amf_message.HandlerResponseMessage) {
	logger.ProducerLog.Infof("[OAM] Handle Registered UE Context")

	var response UEContexts
	response.UEContexts = make([]UEContext, 0) // initialize slice with length 0

	amfSelf := amf_context.AMF_Self()

	for _, ue := range amfSelf.UePool {
		ueContext := buildUEContext(ue, models.AccessType__3_GPP_ACCESS)
		if ueContext != nil {
			response.UEContexts = append(response.UEContexts, *ueContext)
		}
		ueContext = buildUEContext(ue, models.AccessType_NON_3_GPP_ACCESS)
		if ueContext != nil {
			response.UEContexts = append(response.UEContexts, *ueContext)
		}
	}

	amf_message.SendHttpResponseMessage(httpChannel, nil, http.StatusOK, response)
}

func buildUEContext(ue *amf_context.AmfUe, accessType models.AccessType) (ueContext *UEContext) {
	if ue.Sm[accessType].Check(gmm_state.REGISTERED) {
		ueContext = &UEContext{
			AccessType: models.AccessType__3_GPP_ACCESS,
			Supi:       ue.Supi,
			Guti:       ue.Guti,
			Tai:        ue.Tai,
		}

		for _, smContext := range ue.SmContextList {
			pduSessionContext := smContext.PduSessionContext
			if pduSessionContext != nil {
				if pduSessionContext.AccessType == accessType {
					pduSession := PduSession{
						PduSessionId: pduSessionContext.PduSessionId,
						Snssai:       *pduSessionContext.SNssai,
						Dnn:          pduSessionContext.Dnn,
					}
					ueContext.PduSessions = append(ueContext.PduSessions, pduSession)
				}
			}
		}

		if ue.CmConnect(accessType) {
			ueContext.CmState = models.CmState_CONNECTED
		} else {
			ueContext.CmState = models.CmState_IDLE
		}
	}
	return
}
