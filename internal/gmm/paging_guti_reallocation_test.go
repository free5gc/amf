package gmm

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/mediatype/multipart"
	"github.com/free5gc/openapi/models"
)

// newGutiPagedTestUe returns a registered UE whose paging is ongoing, and its stub gNB connection with nothing sent.
func newGutiPagedTestUe(t *testing.T) (*context.AmfUe, *ngaptesting.SctpConnStub) {
	t.Helper()
	ue := newGutiTestUe(t, true)
	ue.SetOnGoing(models.AccessType_3_GPP_ACCESS, &context.OnGoing{Procedure: context.OnGoingProcedurePaging})
	ue.ConfigurationUpdateCommandFlags = nil
	conn := ue.GetRanUe(models.AccessType_3_GPP_ACCESS).Ran.Conn.(*ngaptesting.SctpConnStub)
	conn.MsgList = nil
	return ue, conn
}

// gutiPagingServiceRequest handles a SERVICE REQUEST of the given type by the 5G-S-TMSI with the given 5G-TMSI.
func gutiPagingServiceRequest(t *testing.T, ue *context.AmfUe, serviceType ie.ConstSvcType, tmsi int32) {
	t.Helper()
	sTmsi := &ie.MobileId5GS{}
	require.NoError(t, sTmsi.UnmarshalBinary(append([]byte{0xf4, 0xfe, 0x00},
		byte(tmsi>>24), byte(tmsi>>16), byte(tmsi>>8), byte(tmsi))))
	require.NoError(t, HandleServiceRequest(ue, models.AccessType_3_GPP_ACCESS, &nasMessage.SvcReq{
		Ngksi:   &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 1},
		SvcType: &ie.SvcType{Value: serviceType},
		TMSI5GS: sTmsi,
	}))
	ue.StopT3555() // T3555 is not under test
}

// pagingTestNas returns the 5GMM messages that the NGAP messages sent to the gNB carry, in order.
func pagingTestNas(t *testing.T, sent [][]byte) []nasMessage.Message {
	t.Helper()
	var messages []nasMessage.Message
	for _, b := range sent {
		decoded, err := ngapMessage.Parse(b)
		require.NoError(t, err)
		var pdu []byte
		switch msg := decoded.(type) {
		case *ngapMessage.DownlinkNASTransport:
			pdu = msg.NASPDU.Value
		case *ngapMessage.InitialContextSetupRequest:
			if msg.NASPDU != nil {
				pdu = msg.NASPDU.Value
			}
		}
		if len(pdu) == 0 {
			continue
		}
		// The test's security context has the null algorithms: after the security header, the plain message.
		if pdu[1] != uint8(nasMessage.SecHdrTypePlainNas) {
			pdu = pdu[7:]
		}
		nasMsg, err := nasMessage.ParseGMM(pdu)
		require.NoError(t, err)
		messages = append(messages, nasMsg)
	}
	return messages
}

// requireNewGutiCommand checks that msg is a CONFIGURATION UPDATE COMMAND that carries the UE's 5G-GUTI and asks for
// an acknowledgement.
func requireNewGutiCommand(t *testing.T, ue *context.AmfUe, msg nasMessage.Message) {
	t.Helper()
	command, ok := msg.(*nasMessage.CfgUpdateCmd)
	require.True(t, ok, "NAS message is %T, not a CONFIGURATION UPDATE COMMAND", msg)
	require.NotNil(t, command.GUTI5G, "the CONFIGURATION UPDATE COMMAND has no 5G-GUTI")
	require.Equal(t, ue.Guti, command.GUTI5G.GUTIStr())
	require.NotNil(t, command.CfgUpdateInd)
	require.True(t, command.CfgUpdateInd.ACK, "the CONFIGURATION UPDATE COMMAND asks for no acknowledgement")
}

// TS 24.501 5.3.3 c), TS 33.501 6.12.3: after a service request that answers a paging, the AMF
// assigns the UE a new 5G-GUTI, which a CONFIGURATION UPDATE COMMAND carries; the 5G-GUTI that was
// paged stays valid until the UE acknowledges the new one.
func TestPagedServiceRequestGetsNewGuti(t *testing.T) {
	ue, conn := newGutiPagedTestUe(t)
	pagedGuti := ue.Guti

	gutiPagingServiceRequest(t, ue, ie.SvcType_MobileTermSvc, ue.Tmsi)

	require.NotEqual(t, pagedGuti, ue.Guti, "no new 5G-GUTI after the paged service request")
	sent := pagingTestNas(t, conn.MsgList)
	require.Len(t, sent, 2, "a SERVICE ACCEPT and a CONFIGURATION UPDATE COMMAND")
	require.IsType(t, &nasMessage.SvcAccept{}, sent[0])
	requireNewGutiCommand(t, ue, sent[1])
	require.True(t, gutiResolves(pagedGuti), "the paged 5G-GUTI is invalid before the UE has the new one")
	require.True(t, gutiResolves(ue.Guti))

	require.NoError(t, HandleConfigurationUpdateComplete(ue, &nasMessage.CfgUpdateComplete{}))
	require.False(t, gutiResolves(pagedGuti), "the paged 5G-GUTI is still valid after CONFIGURATION UPDATE COMPLETE")
	require.True(t, gutiResolves(ue.Guti))
}

// The UE did not receive the 5G-GUTI of a REGISTRATION ACCEPT whose completion was lost, and answers the paging with
// its old one: that one stays valid until the new one is acknowledged, and the one it never received is released.
func TestPagedServiceRequestWithOldGutiGetsNewGuti(t *testing.T) {
	ue, conn := newGutiPagedTestUe(t)
	oldGuti, oldTmsi := ue.Guti, ue.Tmsi
	gutiTestAccept(t, ue, oldGuti)
	unacknowledgedGuti := ue.Guti
	conn.MsgList = nil

	gutiPagingServiceRequest(t, ue, ie.SvcType_MobileTermSvc, oldTmsi)

	sent := pagingTestNas(t, conn.MsgList)
	require.Len(t, sent, 2, "a SERVICE ACCEPT and a CONFIGURATION UPDATE COMMAND")
	requireNewGutiCommand(t, ue, sent[1])
	require.True(t, gutiResolves(oldGuti), "the 5G-GUTI the UE holds no longer resolves")
	require.False(t, gutiResolves(unacknowledgedGuti), "the 5G-GUTI the UE never received is still allocated")
}

// A paged UE whose downlink data or signaling is pending gets one SERVICE ACCEPT, then the CONFIGURATION UPDATE
// COMMAND with the new 5G-GUTI, after the 5GSM message when there is one (TS 24.501 5.4.4.1).
func TestPagedServiceRequestWithPendingMessageGetsNewGuti(t *testing.T) {
	const pduSessionID = 5
	snssai := models.Snssai{Sst: 1, Sd: "010203"}
	for name, tc := range map[string]struct {
		request models.N1N2MessageTransferRequestBody
		want    []nasMessage.Message // before the CONFIGURATION UPDATE COMMAND
	}{
		"N2 SM information": {
			request: models.N1N2MessageTransferRequestBody{
				JsonData: &models.Amf_Comm_N1N2MessageTransferReqData{
					PduSessionId: pduSessionID,
					N2InfoContainer: &models.Amf_Comm_N2InfoContainer{
						N2InformationClass: models.Amf_Comm_N2InformationClass_SM,
						SmInfo: &models.Amf_Comm_N2SmInformation{
							PduSessionId:  pduSessionID,
							SNssai:        &snssai,
							N2InfoContent: &models.Amf_Comm_N2InfoContent{NgapIeType: models.Amf_Comm_NgapIeType_PDU_RES_SETUP_REQ},
						},
					},
				},
				BinaryDataN2Information: &multipart.RelatedContent{Content: []byte{0x00}},
			},
			want: []nasMessage.Message{&nasMessage.SvcAccept{}},
		},
		"5GSM message only": {
			request: models.N1N2MessageTransferRequestBody{
				JsonData: &models.Amf_Comm_N1N2MessageTransferReqData{
					PduSessionId: pduSessionID,
					N1MessageContainer: &models.Amf_Comm_N1MessageContainer{
						N1MessageClass: models.Amf_Comm_N1MessageClass_SM,
					},
				},
				// A PDU SESSION RELEASE COMMAND, cause #36 regular deactivation.
				BinaryDataN1Message: &multipart.RelatedContent{Content: []byte{0x2e, pduSessionID, 0x01, 0xd3, 0x24}},
			},
			want: []nasMessage.Message{&nasMessage.SvcAccept{}, &nasMessage.DLNASTransport{}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			ue, conn := newGutiPagedTestUe(t)
			pagedGuti := ue.Guti
			ue.AllowedNssai[models.AccessType_3_GPP_ACCESS] = []models.Nssf_NSSel_AllowedSnssai{{AllowedSnssai: &snssai}}
			ue.AccessAndMobilitySubscriptionData = &models.Udm_SDM_AccessAndMobilitySubscriptionData{
				SubscribedUeAmbr: &models.AmbrRm{Uplink: "1 Gbps", Downlink: "1 Gbps"},
			}
			smContext := context.NewSmContext(pduSessionID)
			smContext.SetAccessType(models.AccessType_3_GPP_ACCESS)
			ue.StoreSmContext(pduSessionID, smContext)
			ue.N1N2Message = &context.N1N2Message{Request: tc.request}

			gutiPagingServiceRequest(t, ue, ie.SvcType_MobileTermSvc, ue.Tmsi)

			require.NotEqual(t, pagedGuti, ue.Guti, "no new 5G-GUTI after the paged service request")
			sent := pagingTestNas(t, conn.MsgList)
			require.Len(t, sent, len(tc.want)+1)
			for i, want := range tc.want {
				require.IsType(t, want, sent[i])
			}
			requireNewGutiCommand(t, ue, sent[len(tc.want)])
		})
	}
}

// TS 24.501 5.3.3 c): the new 5G-GUTI follows a successful service request. A paged UE whose service request is
// rejected, or is for signaling only and gets no CONFIGURATION UPDATE COMMAND, keeps the 5G-GUTI it was paged with,
// and its next service request, which answers no paging, gets no CONFIGURATION UPDATE COMMAND either.
func TestPagedServiceRequestWithoutCommandKeepsGuti(t *testing.T) {
	for name, tc := range map[string]struct {
		serviceType ie.ConstSvcType
		want        nasMessage.Message
	}{
		"emergency services, rejected": {ie.SvcType_EmergSvc, &nasMessage.SvcRej{}},
		"signaling":                    {ie.SvcType_Signalling, &nasMessage.SvcAccept{}}, //nolint:misspell // NAS API name
	} {
		t.Run(name, func(t *testing.T) {
			ue, conn := newGutiPagedTestUe(t)
			pagedGuti := ue.Guti

			gutiPagingServiceRequest(t, ue, tc.serviceType, ue.Tmsi)

			sent := pagingTestNas(t, conn.MsgList)
			require.Len(t, sent, 1)
			require.IsType(t, tc.want, sent[0])
			require.Equal(t, pagedGuti, ue.Guti, "the 5G-GUTI changed but was not sent to the UE")
			require.Empty(t, ue.OldGuti)

			conn.MsgList = nil
			gutiPagingServiceRequest(t, ue, ie.SvcType_Data, ue.Tmsi)

			sent = pagingTestNas(t, conn.MsgList)
			require.Len(t, sent, 1, "a SERVICE ACCEPT only")
			require.IsType(t, &nasMessage.SvcAccept{}, sent[0])
			require.Equal(t, pagedGuti, ue.Guti)
		})
	}
}

// A service request that does not answer a paging keeps the UE's 5G-GUTI.
func TestUnpagedServiceRequestKeepsGuti(t *testing.T) {
	ue := newGutiTestUe(t, true)
	guti := ue.Guti
	ue.ConfigurationUpdateCommandFlags = nil
	conn := ue.GetRanUe(models.AccessType_3_GPP_ACCESS).Ran.Conn.(*ngaptesting.SctpConnStub)
	conn.MsgList = nil

	gutiPagingServiceRequest(t, ue, ie.SvcType_Data, ue.Tmsi)

	require.Equal(t, guti, ue.Guti)
	sent := pagingTestNas(t, conn.MsgList)
	require.Len(t, sent, 1)
	require.IsType(t, &nasMessage.SvcAccept{}, sent[0])
}
