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

type UEInfo struct {
	AccessType  models.AccessType
	Supi        string
	Guti        string
	Tai         models.Tai
	PduSessions []PduSession
	CmState     models.CmState
}

func HandleOAMRegisteredUEContext(httpChannel chan amf_message.HandlerResponseMessage) {
	logger.ProducerLog.Infof("[OAM] Handle Registered UE Context")

	var ueInfos []UEInfo
	amfSelf := amf_context.AMF_Self()

	for _, ue := range amfSelf.UePool {
		ueInfo := buildUEInfo(ue, models.AccessType__3_GPP_ACCESS)
		if ueInfo != nil {
			ueInfos = append(ueInfos, *ueInfo)
		}
		ueInfo = buildUEInfo(ue, models.AccessType_NON_3_GPP_ACCESS)
		if ueInfo != nil {
			ueInfos = append(ueInfos, *ueInfo)
		}
	}

	amf_message.SendHttpResponseMessage(httpChannel, nil, http.StatusOK, ueInfos)
}

func buildUEInfo(ue *amf_context.AmfUe, accessType models.AccessType) (ueInfo *UEInfo) {
	if ue.Sm[accessType].Check(gmm_state.REGISTERED) {
		ueInfo = &UEInfo{
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
					ueInfo.PduSessions = append(ueInfo.PduSessions, pduSession)
				}
			}
		}

		if ue.CmConnect(accessType) {
			ueInfo.CmState = models.CmState_CONNECTED
		} else {
			ueInfo.CmState = models.CmState_IDLE
		}
	}
	return
}
