package ngap

// Messages of the prepared target in the N2 handover handler tests.

import (
	"github.com/free5gc/ngap/aper"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
)

// newHoTestAck is the target's HANDOVER REQUEST ACKNOWLEDGE admitting the
// given PDU session with the target's RAN-UE-NGAP-ID ranID.
func newHoTestAck(e *hoTestEnv, ranID, pduSessionID int64) *ngapMessage.HandoverRequestAcknowledge {
	transfer := aper.OctetString{0x00}
	return &ngapMessage.HandoverRequestAcknowledge{
		AMFUENGAPID: &ngapType.AMFUENGAPID{Value: e.tgt.AmfUeNgapId},
		RANUENGAPID: &ngapType.RANUENGAPID{Value: ranID},
		PDUSessionResourceAdmittedList: &ngapType.PDUSessionResourceAdmittedList{
			List: []ngapType.PDUSessionResourceAdmittedItem{{
				PDUSessionID:                       &ngapType.PDUSessionID{Value: pduSessionID},
				HandoverRequestAcknowledgeTransfer: &transfer,
			}},
		},
		TargetToSourceTransparentContainer: &ngapType.TargetToSourceTransparentContainer{
			Value: aper.OctetString{0x00},
		},
	}
}

// newHoTestNotify is the target's HANDOVER NOTIFY with RAN-UE-NGAP-ID ranID.
func newHoTestNotify(e *hoTestEnv, ranID int64) *ngapMessage.HandoverNotify {
	return &ngapMessage.HandoverNotify{
		AMFUENGAPID: &ngapType.AMFUENGAPID{Value: e.tgt.AmfUeNgapId},
		RANUENGAPID: &ngapType.RANUENGAPID{Value: ranID},
	}
}
