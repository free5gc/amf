package gmm

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	gmm_message "github.com/free5gc/amf/internal/gmm/message"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/fsm"
)

// TestAssignLadnInfoDnn verifies LADN assignment with the migrated OpenAPI DNN type.
func TestAssignLadnInfoDnn(t *testing.T) {
	tests := []struct {
		name string
		dnn  string
	}{
		{name: "valid string DNN is handled normally", dnn: "internet"},
		{name: "empty DNN is handled normally", dnn: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ue := &context.AmfUe{}
			ue.GmmLog = logger.GmmLog
			// LADNIndication left nil so control reaches the else-if
			// SmfSelectionData branch containing the reported sink.
			ue.RegistrationRequest = &nasMessage.RegReq{}
			ue.SmfSelectionData = &models.Udm_SDM_SmfSelectionSubscriptionData{
				SubscribedSnssaiInfos: map[string]models.Udm_SDM_SnssaiInfo{
					"01010203": {
						DnnInfos: []models.Udm_SDM_DnnInfo{{Dnn: tc.dnn}},
					},
				},
			}

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("assignLadnInfo panicked on DNN %v (%T): %v", tc.dnn, tc.dnn, r)
				}
			}()

			assignLadnInfo(ue, models.AccessType_3_GPP_ACCESS)
		})
	}
}

// TS 24.501 5.4.4.6 c), d): a DEREGISTRATION REQUEST or a REGISTRATION REQUEST received before the CONFIGURATION
// UPDATE COMPLETE aborts the generic UE configuration update procedure, so T3555 is stopped and the CONFIGURATION
// UPDATE COMMAND is not sent again.
func TestRequestBeforeConfigurationUpdateCompleteStopsT3555(t *testing.T) {
	amfSelf := context.GetSelf()
	accessType := models.AccessType_3_GPP_ACCESS
	savedT3555 := amfSelf.T3555Cfg
	amfSelf.T3555Cfg = factory.TimerValue{Enable: true, ExpireTime: time.Hour, MaxRetryTimes: 4}
	t.Cleanup(func() { amfSelf.T3555Cfg = savedT3555 })

	registration := func(registrationType uint8) func(*context.AmfUe) error {
		return func(ue *context.AmfUe) error {
			guti := new(ie.MobileId5GS)
			if err := guti.FromGUTIStr(ue.Guti); err != nil {
				return err
			}
			return HandleRegistrationRequest(ue, accessType, 0, &nasMessage.RegReq{
				RegType5GS:      &ie.RegType5GS{Value: registrationType},
				Ngksi:           &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 1},
				MobileId5GS:     guti,
				UESecCapability: &ie.UESecCapability{EA05G: true, IA2_128_5G: true},
			})
		}
	}
	tests := []struct {
		name    string
		request func(*context.AmfUe) error
	}{
		{"initial registration", registration(ie.RegType_InitialReg)},
		{"mobility registration", registration(ie.RegType_MobilityRegUpdating)},
		{"periodic registration", registration(ie.RegType_PeriodicRegUpdating)},
		{"de-registration", func(ue *context.AmfUe) error {
			return GmmFSM.SendEvent(ue.State[accessType], GmmMessageEvent, fsm.ArgsType{
				ArgAmfUe:         ue,
				ArgAccessType:    accessType,
				ArgProcedureCode: int64(0),
				ArgNASMessage:    &nasMessage.DeregReqUEOrig{DeregType: &ie.DeregType{AccessType: ie.AccessType_3gpp}},
			}, logger.GmmLog)
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ue, _ := newNssaiTestUe(t)
			ue.State[accessType].Set(context.Registered)
			ue.SecurityContextAvailable = true // with 5G-EA0 and 5G-IA0
			gmm_message.SendConfigurationUpdateCommand(ue, accessType,
				&context.ConfigurationUpdateCommandFlags{NeedGUTI: true})
			require.NotNil(t, ue.T3555)

			require.NoError(t, test.request(ue))
			require.Nil(t, ue.T3555)
		})
	}
}
