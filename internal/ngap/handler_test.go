package ngap

import (
	"encoding/hex"
	"net"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	nastesting "github.com/free5gc/amf/internal/nas/testing"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	"github.com/free5gc/ngap/aper"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

func NewAmfRan(conn net.Conn) *amf_context.AmfRan {
	return &amf_context.AmfRan{
		RanPresent: 1,
		RanId: &models.GlobalRanNodeId{
			PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"},
			GNbId:  &models.GNbId{BitLength: 24, GNBValue: "000102"},
		},
		Name:   "free5gc",
		AnType: models.AccessType_3_GPP_ACCESS,
		Conn:   conn,
		SupportedTAList: []amf_context.SupportedTAI{{
			Tai: models.Tai{
				PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"},
				Tac:    "000001",
			},
			SNssaiList: []models.Snssai{{Sst: 1, Sd: "010203"}},
		}},
		Log: logger.NgapLog.WithField(logger.FieldRanAddr, "127.0.0.1"),
	}
}

func NewAmfContext(amfCtx *amf_context.AMFContext) {
	*amfCtx = amf_context.AMFContext{
		NfId:         uuid.New().String(),
		NgapIpList:   []string{"127.0.0.1"},
		NgapPort:     38412,
		UriScheme:    "http",
		RegisterIPv4: "127.0.0.18",
		BindingIPv4:  "127.0.0.18",
		SBIPort:      8000,
		ServedGuamiList: []models.Guami{{
			PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"},
			AmfId:  "cafe00",
		}},
		SupportTaiLists: []models.Tai{{
			PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"},
			Tac:    "000001",
		}},
		PlmnSupportList: []factory.PlmnSupportItem{{
			PlmnId: &models.PlmnId{Mcc: "208", Mnc: "93"},
			SNssaiList: []models.Snssai{
				{Sst: 1, Sd: "010203"},
				{Sst: 1, Sd: "112233"},
			},
		}},
		SupportDnnLists: []string{"internet"},
		NrfUri:          "http://127.0.0.10:8000",
		SecurityAlgorithm: amf_context.SecurityAlgorithm{
			IntegrityOrder: []uint8{0x02},
			CipheringOrder: []uint8{0x00},
		},
		NetworkName:            factory.NetworkName{Full: "free5GC", Short: "free"},
		T3502Value:             720,
		T3512Value:             3600,
		Non3gppDeregTimerValue: 3240,
		T3513Cfg: factory.TimerValue{
			Enable: true, ExpireTime: 6000000000, MaxRetryTimes: 4,
		},
		T3522Cfg: factory.TimerValue{
			Enable: true, ExpireTime: 6000000000, MaxRetryTimes: 4,
		},
		T3550Cfg: factory.TimerValue{
			Enable: true, ExpireTime: 6000000000, MaxRetryTimes: 4,
		},
		T3560Cfg: factory.TimerValue{
			Enable: true, ExpireTime: 6000000000, MaxRetryTimes: 4,
		},
		T3565Cfg: factory.TimerValue{
			Enable: true, ExpireTime: 6000000000, MaxRetryTimes: 4,
		},
	}
}

func TestHandlePathSwitchRequestKeepsStoredUESecurityCapabilityOnMismatch(t *testing.T) {
	amfSelf := amf_context.GetSelf()
	NewAmfContext(amfSelf)

	sourceRan := NewAmfRan(nil)
	sourceRan.AnType = "3GPP_ACCESS"
	ranUe := &amf_context.RanUe{
		Ran:         sourceRan,
		RanUeNgapId: 1,
		AmfUeNgapId: 1,
		Log:         sourceRan.Log,
	}
	sourceRan.RanUeList.Store(ranUe.RanUeNgapId, ranUe)
	amfSelf.RanUePool.Store(ranUe.AmfUeNgapId, ranUe)

	amfUe := amfSelf.NewAmfUe("imsi-208930000007487")
	amfUe.SecurityContextAvailable = true
	amfUe.NgKsi.Ksi = 1
	amfUe.Kamf = strings.Repeat("11", 32)
	amfUe.NH = []byte(strings.Repeat("\x22", 32))
	amfUe.UESecurityCapability = ie.UESecCapability{
		Length:     2,
		IA2_128_5G: true,
	}

	ranUe.SetAmfUe(amfUe)
	amfUe.RanUe["3GPP_ACCESS"] = ranUe

	targetRan := NewAmfRan(nil)
	targetRan.AnType = "3GPP_ACCESS"
	sourceAMFUeNgapID := ngapType.AMFUENGAPID{Value: ranUe.AmfUeNgapId}
	ranUeNgapID := ngapType.RANUENGAPID{Value: 2}
	received := &ngapType.UESecurityCapabilities{
		NRencryptionAlgorithms: &ngapType.NRencryptionAlgorithms{Value: aper.BitString{
			Bytes: []byte{0x00, 0x00}, BitLength: 16,
		}},
		NRintegrityProtectionAlgorithms: &ngapType.NRintegrityProtectionAlgorithms{Value: aper.BitString{
			Bytes: []byte{0x00, 0x00}, BitLength: 16,
		}},
	}

	handlePathSwitchRequestMain(targetRan, &ranUeNgapID, &sourceAMFUeNgapID, nil, received, nil, nil)

	require.True(t, amfUe.UESecurityCapability.IA2_128_5G)
	require.False(t, amfUe.UESecurityCapability.IA1_128_5G)
	require.False(t, amfUe.UESecurityCapability.IA3_128_5G)
}

func BuildInitialUEMessage(
	t *testing.T,
	ranUeNgapID int64,
	nasPdu []byte,
	fiveGSTmsi string,
) *ngapMessage.InitialUEMessage {
	t.Helper()
	plmn := aper.OctetString{0x02, 0xf8, 0x39}
	message := &ngapMessage.InitialUEMessage{
		RANUENGAPID: &ngapType.RANUENGAPID{Value: ranUeNgapID},
		NASPDU:      &ngapType.NASPDU{Value: aper.OctetString(nasPdu)},
		UserLocationInformation: &ngapType.UserLocationInformation{
			Choice: &ngapType.UserLocationInformationNR{
				NRCGI: &ngapType.NRCGI{
					PLMNIdentity: &ngapType.PLMNIdentity{Value: plmn},
					NRCellIdentity: &ngapType.NRCellIdentity{Value: aper.BitString{
						Bytes: []byte{0, 0, 0, 0, 0x10}, BitLength: 36,
					}},
				},
				TAI: &ngapType.TAI{
					PLMNIdentity: &ngapType.PLMNIdentity{Value: plmn},
					TAC:          &ngapType.TAC{Value: aper.OctetString{0, 0, 1}},
				},
			},
		},
		RRCEstablishmentCause: &ngapType.RRCEstablishmentCause{
			Value: ngapType.RRCEstablishmentCausePresentMtAccess,
		},
	}

	if fiveGSTmsi != "" {
		require.Len(t, fiveGSTmsi, 12)
		amfSetID, err := hex.DecodeString(fiveGSTmsi[:4])
		require.NoError(t, err)
		amfPointer, err := hex.DecodeString(fiveGSTmsi[2:4])
		require.NoError(t, err)
		tmsi, err := hex.DecodeString(fiveGSTmsi[4:])
		require.NoError(t, err)
		message.FiveGSTMSI = &ngapType.FiveGSTMSI{
			AMFSetID:   &ngapType.AMFSetID{Value: aper.BitString{Bytes: amfSetID, BitLength: 10}},
			AMFPointer: &ngapType.AMFPointer{Value: aper.BitString{Bytes: amfPointer, BitLength: 6}},
			FiveGTMSI:  &ngapType.FiveGTMSI{Value: aper.OctetString(tmsi)},
		}
	}
	return message
}

func TestHandleInitialUEMessage(t *testing.T) {
	const ranUeNgapID int64 = 1
	const fiveGSTmsi = "fe0000000001"

	testCases := []struct {
		name             string
		amfUENGAPID      int64
		nasPdu           []byte
		expectedResponse aper.OctetString
	}{
		{
			name:             "unrecognized service request",
			amfUENGAPID:      1,
			nasPdu:           nastesting.GetServiceRequest(uint8(ie.SvcType_Data)),
			expectedResponse: aper.OctetString{0x7e, 0x00, 0x4d, 0x0a},
		},
		{
			name:        "unrecognized periodic registration",
			amfUENGAPID: 2,
			nasPdu: nastesting.GetRegistrationRequest(
				ie.RegType_PeriodicRegUpdating,
				mobileIdentity5GSFromBytes([]uint8{
					0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0, 0, 0, 0, 0x47, 0x78,
				}),
				nil, nil, nil, nil, nil,
			),
			expectedResponse: aper.OctetString{0x7e, 0x00, 0x44, 0x0a, 0x16, 0x01, 0x2c},
		},
		{
			name:        "unrecognized mobility registration",
			amfUENGAPID: 3,
			nasPdu: nastesting.GetRegistrationRequest(
				ie.RegType_MobilityRegUpdating,
				mobileIdentity5GSFromBytes([]uint8{
					0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0, 0, 0, 0, 0x47, 0x78,
				}),
				nil, nil, nil, nil, nil,
			),
			expectedResponse: aper.OctetString{0x7e, 0x00, 0x44, 0x0a, 0x16, 0x01, 0x2c},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			connStub := new(ngaptesting.SctpConnStub)
			NewAmfContext(amf_context.GetSelf())
			ran := NewAmfRan(connStub)
			message := BuildInitialUEMessage(t, ranUeNgapID, test.nasPdu, fiveGSTmsi)
			encoded, err := message.MarshalBinary()
			require.NoError(t, err)

			handleInitialUEMessageMain(
				ran, encoded, message.RANUENGAPID, message.NASPDU,
				message.UserLocationInformation, message.RRCEstablishmentCause,
				message.FiveGSTMSI, message.UEContextRequest,
			)
			require.Len(t, connStub.MsgList, 2)

			decoded, err := ngapMessage.Parse(connStub.MsgList[0])
			require.NoError(t, err)
			downlink, ok := decoded.(*ngapMessage.DownlinkNASTransport)
			require.True(t, ok)
			require.Equal(t, test.amfUENGAPID, downlink.AMFUENGAPID.Value)
			require.Equal(t, ranUeNgapID, downlink.RANUENGAPID.Value)
			require.Equal(t, test.expectedResponse, downlink.NASPDU.Value)

			decoded, err = ngapMessage.Parse(connStub.MsgList[1])
			require.NoError(t, err)
			release, ok := decoded.(*ngapMessage.UEContextReleaseCommand)
			require.True(t, ok)
			pair, ok := release.UENGAPIDs.Choice.(*ngapType.UENGAPIDPair)
			require.True(t, ok)
			require.Equal(t, test.amfUENGAPID, pair.AMFUENGAPID.Value)
			require.Equal(t, ranUeNgapID, pair.RANUENGAPID.Value)
			cause, ok := release.Cause.Choice.(*ngapType.CauseNas)
			require.True(t, ok)
			require.Equal(t, ngapType.CauseNasPresentNormalRelease, cause.Value)
		})
	}
}

func mobileIdentity5GSFromBytes(data []byte) ie.MobileId5GS {
	var identity ie.MobileId5GS
	if err := identity.UnmarshalBinary(data); err != nil {
		panic(err)
	}
	return identity
}
