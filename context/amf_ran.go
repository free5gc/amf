package context

import (
	"fmt"
	"free5gc/lib/ngap/ngapConvert"
	"free5gc/lib/ngap/ngapType"
	"free5gc/lib/openapi/models"
	"free5gc/src/amf/logger"
	"net"
)

const (
	RanPresentGNbId   = 1
	RanPresentNgeNbId = 2
	RanPresentN3IwfId = 3
)

type AmfRan struct {
	RanPresent int
	RanId      *models.GlobalRanNodeId
	Name       string
	AnType     models.AccessType
	/* socket Connect*/
	Conn net.Conn
	/* Supported TA List */
	SupportedTAList []SupportedTAI

	/* RAN UE List */
	RanUeList []*RanUe // RanUeNgapId as key
}

type SupportedTAI struct {
	Tai        models.Tai
	SNssaiList []models.Snssai
}

func NewSupportedTAI() (tai SupportedTAI) {
	tai.SNssaiList = make([]models.Snssai, 0, MaxNumOfSlice)
	return
}

func (ran *AmfRan) Remove() {
	ran.RemoveAllUeInRan()
	AMF_Self().DeleteAmfRan(ran.Conn)
}

func (ran *AmfRan) NewRanUe(ranUeNgapID int64) (*RanUe, error) {
	ranUe := RanUe{}
	self := AMF_Self()
	amfUeNgapID, err := self.AllocateAmfUeNgapID()
	if err != nil {
		return nil, fmt.Errorf("Allocate AMF UE NGAP ID error: %+v", err)
	}
	ranUe.AmfUeNgapId = amfUeNgapID
	ranUe.RanUeNgapId = ranUeNgapID
	ranUe.Ran = ran

	ran.RanUeList = append(ran.RanUeList, &ranUe)
	self.RanUePool.Store(ranUe.AmfUeNgapId, &ranUe)
	return &ranUe, nil
}

func (ran *AmfRan) RemoveAllUeInRan() {
	for _, ranUe := range ran.RanUeList {
		if err := ranUe.Remove(); err != nil {
			logger.ContextLog.Errorf("Remove RanUe error: %v", err)
		}
	}
}

func (ran *AmfRan) RanUeFindByRanUeNgapID(ranUeNgapID int64) *RanUe {
	for _, ranUe := range ran.RanUeList {
		if ranUe.RanUeNgapId == ranUeNgapID {
			return ranUe
		}
	}
	return nil
}

func (ran *AmfRan) SetRanId(ranNodeId *ngapType.GlobalRANNodeID) {
	ranId := ngapConvert.RanIdToModels(*ranNodeId)
	ran.RanPresent = ranNodeId.Present
	ran.RanId = &ranId
	if ranNodeId.Present == ngapType.GlobalRANNodeIDPresentGlobalN3IWFID {
		ran.AnType = models.AccessType_NON_3_GPP_ACCESS
	} else {
		ran.AnType = models.AccessType__3_GPP_ACCESS
	}
}
