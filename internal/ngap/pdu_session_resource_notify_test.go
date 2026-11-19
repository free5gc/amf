package ngap

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/ngap/aper"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/mediatype/multipart"
	"github.com/free5gc/openapi/models"
)

// The SMF refuses the N2 SM information of a PDU SESSION RESOURCE NOTIFY with an SmContextUpdateError
// that carries a 5GSM STATUS (TS 29.502 6.1.6.2.36): the AMF sends the 5GSM message to the UE.
func TestPDUSessionResourceNotifySendsTheN1SmMessageOfAnSmfError(t *testing.T) {
	// A 5GSM STATUS for session 5, PTI 0, cause #81 "invalid PTI value".
	gsmStatus := []byte{0x2e, 0x05, 0x00, 0xd6, 0x51}
	ct, body, serializeErr := openapi.Serialize(models.UpdateSmContextResponse403{
		JsonData: &models.Smf_PDUSess_SmContextUpdateError{
			Error:   &models.Smf_PDUSess_ExtProblemDetails{Status: http.StatusForbidden, Cause: "N1_SM_ERROR"},
			N1SmMsg: &models.RefToBinaryData{ContentId: "GSM_NAS"},
		},
		BinaryDataN1SmMessage: &multipart.RelatedContent{ContentID: "GSM_NAS", Content: gsmStatus},
	}, "multipart/related")
	require.NoError(t, serializeErr)
	smf := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write(body); err != nil {
			t.Error(err)
		}
	}))
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	smf.Config.Protocols = protocols
	smf.Start()
	t.Cleanup(smf.Close)

	transfer := aper.OctetString{0x00}
	for name, notify := range map[string]*ngapMessage.PDUSessionResourceNotify{
		"notify": {PDUSessionResourceNotifyList: &ngapType.PDUSessionResourceNotifyList{
			List: []ngapType.PDUSessionResourceNotifyItem{{
				PDUSessionID: &ngapType.PDUSessionID{Value: 5}, PDUSessionResourceNotifyTransfer: &transfer,
			}},
		}},
		"released": {PDUSessionResourceReleasedListNot: &ngapType.PDUSessionResourceReleasedListNot{
			List: []ngapType.PDUSessionResourceReleasedItemNot{{
				PDUSessionID: &ngapType.PDUSessionID{Value: 5}, PDUSessionResourceNotifyReleasedTransfer: &transfer,
			}},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			e := newHoTestEnv(t, false)
			sm, ok := e.amfUe.SmContextFindByPDUSessionID(5)
			require.True(t, ok)
			sm.SetSmfUri(smf.URL)
			notify.AMFUENGAPID = &ngapType.AMFUENGAPID{Value: e.src.AmfUeNgapId}
			notify.RANUENGAPID = &ngapType.RANUENGAPID{Value: e.src.RanUeNgapId}

			dispatchMain(e.srcRan, notify, nil)
			hoRequireSent(t, e.srcConn, "the SMF's 5GSM STATUS goes to the UE", "DownlinkNASTransport")
			decoded, err := ngapMessage.Parse(e.srcConn.MsgList[0])
			require.NoError(t, err)
			require.True(t, bytes.Contains(decoded.(*ngapMessage.DownlinkNASTransport).NASPDU.Value, gsmStatus))
		})
	}
}
