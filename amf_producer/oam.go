package amf_producer

import (
	"gofree5gc/lib/openapi/models"
	"gofree5gc/src/amf/amf_context"
	"gofree5gc/src/amf/amf_handler/amf_message"
	"gofree5gc/src/amf/gmm/gmm_state"
	"gofree5gc/src/amf/logger"
	"net/http"
)

type UEInfo struct {
	Supi    string
	Guti    string
	RanId   models.GlobalRanNodeId
	Tai     models.Tai
	CmState models.CmState
}

func HandleOAMRegisteredUEContext(httpChannel chan amf_message.HandlerResponseMessage) {
	logger.ProducerLog.Infof("[OAM] Handle Registered UE Context")

	var ueInfos []UEInfo
	amfSelf := amf_context.AMF_Self()

	for _, ue := range amfSelf.UePool {
		if ue.Sm[models.AccessType__3_GPP_ACCESS].Check(gmm_state.REGISTERED) {
			ueInfo := UEInfo{
				Supi: ue.Supi,
				Guti: ue.Guti,
				Tai:  ue.Tai,
			}
			if ue.CmConnect(models.AccessType__3_GPP_ACCESS) {
				ueInfo.CmState = models.CmState_CONNECTED
			} else {
				ueInfo.CmState = models.CmState_IDLE
			}
			ueInfos = append(ueInfos, ueInfo)
		}
		if ue.Sm[models.AccessType_NON_3_GPP_ACCESS].Check(gmm_state.REGISTERED) {
			ueInfo := UEInfo{
				Supi: ue.Supi,
				Guti: ue.Guti,
				Tai:  ue.Tai,
			}
			ueInfos = append(ueInfos, ueInfo)
		}
	}

	amf_message.SendHttpResponseMessage(httpChannel, nil, http.StatusOK, ueInfos)
}

// func aaa(ue *amf_context.AmfUe) (ueInfo UEInfo) {

// }
