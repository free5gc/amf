package ngap

import (
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/ngap/aper"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// supportedTAList returns a Supported TA List of TAC 000001 for one PLMN, given as its three octets.
func supportedTAList(plmn []byte) *ngapType.SupportedTAList {
	return &ngapType.SupportedTAList{List: []ngapType.SupportedTAItem{{
		TAC: &ngapType.TAC{Value: aper.OctetString{0x00, 0x00, 0x01}},
		BroadcastPLMNList: &ngapType.BroadcastPLMNList{List: []ngapType.BroadcastPLMNItem{{
			PLMNIdentity: &ngapType.PLMNIdentity{Value: plmn},
			TAISliceSupportList: &ngapType.SliceSupportList{List: []ngapType.SliceSupportItem{{
				SNSSAI: &ngapType.SNSSAI{SST: &ngapType.SST{Value: aper.OctetString{0x01}}},
			}}},
		}}},
	}}}
}

// lastNgap returns the type of the last NGAP message that the AMF sent, as an empty message of that type: the
// test's AMF context does not have every IE of an NG SETUP RESPONSE.
func lastNgap(t *testing.T, conn *ngaptesting.SctpConnStub) ngapMessage.Message {
	t.Helper()
	require.NotEmpty(t, conn.MsgList)
	decoded, _, err := ngapMessage.ParseMessageType(conn.MsgList[len(conn.MsgList)-1])
	require.NoError(t, err)
	return decoded
}

var (
	servedPLMN   = []byte{0x02, 0xf8, 0x39} // 208-93
	unservedPLMN = []byte{0x99, 0xf9, 0x99} // 999-99
)

// TS 38.413 8.7.1.1, 8.7.1.4: an NG SETUP REQUEST again replaces the TAs of the earlier setup, so a setup that names
// only a PLMN that the AMF does not serve fails.
func TestNGSetupReplacesSupportedTAs(t *testing.T) {
	amfSelf := amf_context.GetSelf()
	savedTais := amfSelf.SupportTaiLists
	amfSelf.SupportTaiLists = []models.Tai{{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, Tac: "000001"}}
	t.Cleanup(func() { amfSelf.SupportTaiLists = savedTais })
	conn := new(ngaptesting.SctpConnStub)
	ran := NewAmfRan(conn) // set up with the served TA

	handleNGSetupRequestMain(ran, nil, nil, supportedTAList(unservedPLMN), nil, nil)

	_, ok := lastNgap(t, conn).(*ngapMessage.NGSetupFailure)
	require.True(t, ok, "a setup for an unserved PLMN is not refused")
	require.Len(t, ran.SupportedTAList, 1)
	require.Equal(t, "999", ran.SupportedTAList[0].Tai.PlmnId.Mcc)
}

// TS 38.413 8.7.2.2, 8.7.2.3: a RAN CONFIGURATION UPDATE with a Supported TA List overwrites the whole list, and one
// that the AMF does not accept leaves it as it was.
func TestRANConfigurationUpdateOverwritesSupportedTAs(t *testing.T) {
	amfSelf := amf_context.GetSelf()
	savedTais := amfSelf.SupportTaiLists
	amfSelf.SupportTaiLists = []models.Tai{{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, Tac: "000001"}}
	t.Cleanup(func() { amfSelf.SupportTaiLists = savedTais })
	conn := new(ngaptesting.SctpConnStub)
	ran := NewAmfRan(conn) // set up with the served TA

	handleRANConfigurationUpdateMain(ran, supportedTAList(unservedPLMN), nil)
	_, ok := lastNgap(t, conn).(*ngapMessage.RANConfigurationUpdateFailure)
	require.True(t, ok, "an update to an unserved PLMN only is acknowledged")
	require.Len(t, ran.SupportedTAList, 1)
	require.Equal(t, "208", ran.SupportedTAList[0].Tai.PlmnId.Mcc, "a refused update changed the list")

	ran.SupportedTAList = append(ran.SupportedTAList, amf_context.SupportedTAI{
		Tai: models.Tai{PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"}, Tac: "000002"},
	})
	handleRANConfigurationUpdateMain(ran, supportedTAList(servedPLMN), nil)
	_, ok = lastNgap(t, conn).(*ngapMessage.RANConfigurationUpdateAcknowledge)
	require.True(t, ok)
	require.Len(t, ran.SupportedTAList, 1, "the update did not overwrite the list")
	require.Equal(t, "000001", ran.SupportedTAList[0].Tai.Tac)
}
