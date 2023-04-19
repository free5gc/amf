package nas_test

import (
	"testing"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	amf_nas "github.com/free5gc/amf/internal/nas"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/openapi/models"
	"github.com/stretchr/testify/require"
)

func FuzzHandleNAS(f *testing.F) {
	amfSelf := amf_context.AMF_Self()
	amfSelf.ServedGuamiList = []models.Guami{{
		PlmnId: &models.PlmnId{
			Mcc: "208",
			Mnc: "93",
		},
		AmfId: "cafe00",
	}}
	tai := models.Tai{
		PlmnId: &models.PlmnId{
			Mcc: "208",
			Mnc: "93",
		},
		Tac: "1",
	}
	amfSelf.SupportTaiLists = []models.Tai{tai}

	msg := nas.NewMessage()
	msg.GmmMessage = nas.NewGmmMessage()
	msg.GmmMessage.GmmHeader.SetMessageType(nas.MsgTypeRegistrationRequest)
	msg.GmmMessage.RegistrationRequest = nasMessage.NewRegistrationRequest(nas.MsgTypeRegistrationRequest)
	reg := msg.GmmMessage.RegistrationRequest
	reg.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	reg.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	reg.RegistrationRequestMessageIdentity.SetMessageType(nas.MsgTypeRegistrationRequest)
	reg.NgksiAndRegistrationType5GS.SetTSC(nasMessage.TypeOfSecurityContextFlagNative)
	reg.NgksiAndRegistrationType5GS.SetNasKeySetIdentifiler(7)
	reg.NgksiAndRegistrationType5GS.SetFOR(1)
	reg.NgksiAndRegistrationType5GS.SetRegistrationType5GS(nasMessage.RegistrationType5GSInitialRegistration)
	id := []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}
	reg.MobileIdentity5GS.SetLen(uint16(len(id)))
	reg.MobileIdentity5GS.SetMobileIdentity5GSContents(id)
	reg.UESecurityCapability = nasType.NewUESecurityCapability(nasMessage.RegistrationRequestUESecurityCapabilityType)
	reg.UESecurityCapability.SetLen(2)
	reg.UESecurityCapability.SetEA0_5G(1)
	reg.UESecurityCapability.SetIA2_128_5G(1)
	buf, err := msg.PlainNasEncode()
	require.NoError(f, err)
	f.Add(buf)

	msg = nas.NewMessage()
	msg.GmmMessage = nas.NewGmmMessage()
	msg.GmmMessage.GmmHeader.SetMessageType(nas.MsgTypeDeregistrationRequestUEOriginatingDeregistration)
	msg.GmmMessage.DeregistrationRequestUEOriginatingDeregistration = nasMessage.NewDeregistrationRequestUEOriginatingDeregistration(nas.MsgTypeDeregistrationRequestUEOriginatingDeregistration)
	deReg := msg.GmmMessage.DeregistrationRequestUEOriginatingDeregistration
	deReg.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	deReg.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	deReg.DeregistrationRequestMessageIdentity.SetMessageType(nas.MsgTypeDeregistrationRequestUEOriginatingDeregistration)
	deReg.NgksiAndDeregistrationType.SetTSC(nasMessage.TypeOfSecurityContextFlagNative)
	deReg.NgksiAndDeregistrationType.SetNasKeySetIdentifiler(7)
	deReg.NgksiAndDeregistrationType.SetSwitchOff(0)
	deReg.NgksiAndDeregistrationType.SetAccessType(nasMessage.AccessType3GPP)
	deReg.MobileIdentity5GS.SetLen(uint16(len(id)))
	deReg.MobileIdentity5GS.SetMobileIdentity5GSContents(id)
	buf, err = msg.PlainNasEncode()
	require.NoError(f, err)
	f.Add(buf)

	msg = nas.NewMessage()
	msg.GmmMessage = nas.NewGmmMessage()
	msg.GmmMessage.GmmHeader.SetMessageType(nas.MsgTypeServiceRequest)
	msg.GmmMessage.ServiceRequest = nasMessage.NewServiceRequest(nas.MsgTypeServiceRequest)
	sr := msg.GmmMessage.ServiceRequest
	sr.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	sr.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	sr.ServiceRequestMessageIdentity.SetMessageType(nas.MsgTypeServiceRequest)
	sr.ServiceTypeAndNgksi.SetTSC(nasMessage.TypeOfSecurityContextFlagNative)
	sr.ServiceTypeAndNgksi.SetNasKeySetIdentifiler(0)
	sr.ServiceTypeAndNgksi.SetServiceTypeValue(nasMessage.ServiceTypeSignalling)
	sr.TMSI5GS.SetLen(7)
	buf, err = msg.PlainNasEncode()
	require.NoError(f, err)
	buf = append([]uint8{
		nasMessage.Epd5GSMobilityManagementMessage,
		nas.SecurityHeaderTypeIntegrityProtected,
		0, 0, 0, 0, 0},
		buf...)
	f.Add(buf)

	f.Fuzz(func(t *testing.T, d []byte) {
		ue := new(amf_context.RanUe)
		ue.Ran = new(amf_context.AmfRan)
		ue.Ran.AnType = models.AccessType__3_GPP_ACCESS
		ue.Log = logger.NgapLog
		ue.Tai = tai
		amf_nas.HandleNAS(ue, ngapType.ProcedureCodeInitialUEMessage, d, true)
	})
}
