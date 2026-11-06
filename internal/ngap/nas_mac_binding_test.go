package ngap

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	nas_message "github.com/free5gc/nas/message"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

var (
	bindingKnasEnc = [16]byte{1, 2, 3, 4}
	bindingKnasInt = [16]byte{5, 6, 7, 8}
	// 5G-GUTI 208-93-cafe00-00000001, its 5G-S-TMSI and the null-scheme SUCI of imsi-208930000000001.
	bindingGuti = mobileIdentity5GSFromBytes([]uint8{0xf2, 0x02, 0xf8, 0x39, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x01})
	bindingTmsi = mobileIdentity5GSFromBytes([]uint8{0xf4, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x01})
	bindingSuci = mobileIdentity5GSFromBytes([]uint8{
		0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
	})
)

const (
	bindingFiveGSTmsi = "fe0000000001"

	sentICS     = "InitialContextSetupRequest"
	sentRelease = "UEContextReleaseCommand"
	sentDLNAS   = "DownlinkNASTransport"
	sentErrInd  = "ErrorIndication"
)

// bindingVictim is a registered, CM-IDLE UE with a 5G NAS security context (if secured) that has
// accepted uplink NAS COUNT 4 and is being paged (T3513 running).
func bindingVictim(t *testing.T, secured bool) *amf_context.AmfUe {
	t.Helper()
	amfSelf := amf_context.GetSelf()
	amfUe := amfSelf.NewAmfUe("imsi-208930000000001")
	amfUe.Guti = "20893cafe0000000001"
	amfUe.Suci = bindingSuci.IdStr()
	amfUe.State[models.AccessType_3_GPP_ACCESS].Set(amf_context.Registered)
	amfUe.SecurityContextAvailable = secured
	amfUe.NgKsi = models.Amf_Comm_NgKsi{Tsc: models.Amf_Comm_ScType_NATIVE, Ksi: 1}
	amfUe.CipheringAlg = uint8(nas_message.AlgCiphering128NEA2)
	amfUe.IntegrityAlg = uint8(nas_message.AlgIntegrity128NIA2)
	amfUe.KnasEnc = bindingKnasEnc
	amfUe.KnasInt = bindingKnasInt
	amfUe.AllowedNssai[models.AccessType_3_GPP_ACCESS] = []models.Nssf_NSSel_AllowedSnssai{
		{AllowedSnssai: &models.Snssai{Sst: 1, Sd: "010203"}},
	}
	amfUe.ULCount.Set(0, 4)
	amfUe.T3513 = amf_context.NewTimer(time.Hour, 1, func(int32) {}, func() {})
	t.Cleanup(amfUe.StopT3513)
	return amfUe
}

func bindingUESecurity() *nas_message.SecCtx {
	return nas_message.NewSecCtx(nas_message.UESide, nas_message.Bearer3GPP,
		nas_message.AlgCiphering128NEA2, nas_message.AlgIntegrity128NIA2, bindingKnasEnc[:], bindingKnasInt[:])
}

// bindingNas encodes msg as the UE does, integrity protected at uplink COUNT 5 (forged: with a
// wrong MAC; ciphered: also ciphered, which an initial NAS message never is), or plain.
func bindingNas(t *testing.T, msg nas_message.Message, security string) []byte {
	t.Helper()
	if security == "plain" {
		b, err := msg.MarshalBinary()
		require.NoError(t, err)
		return b
	}
	ueSecurity := bindingUESecurity()
	ueSecurity.UplinkCount.Set(0, 5)
	headerType := nas_message.SecHdrTypeIntegrityProtected
	if security == "ciphered" {
		headerType = nas_message.SecHdrTypeIntegrityProtectedAndCiphered
	}
	b, err := nas_message.Marshal(msg, ueSecurity, headerType)
	require.NoError(t, err)
	if security == "forged" {
		b[2] ^= 0xff
	}
	return b
}

func bindingServiceRequest() nas_message.Message {
	tmsi := bindingTmsi
	return &nas_message.SvcReq{
		Ngksi: &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 1},
		// This spelling is the name exported by the NAS API.
		SvcType: &ie.SvcType{Value: ie.SvcType_Signalling}, //nolint:misspell
		TMSI5GS: &tmsi,
	}
}

func bindingRegistrationRequest(registrationType uint8, identity ie.MobileId5GS) nas_message.Message {
	return &nas_message.RegReq{
		RegType5GS:      &ie.RegType5GS{Value: registrationType},
		Ngksi:           &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 1},
		MobileId5GS:     &identity,
		UESecCapability: &ie.UESecCapability{Length: 2, EA05G: true, IA2_128_5G: true},
	}
}

func bindingDeregistrationRequest() nas_message.Message {
	return &nas_message.DeregReqUEOrig{
		DeregType:   &ie.DeregType{AccessType: 1},
		Ngksi:       &ie.NASKeySetId{Tsc: ie.SecCtxTypeNative, Ksi: 1},
		MobileId5GS: &bindingGuti,
	}
}

type bindingSent struct {
	ngap []string
	nas  []nas_message.Message
}

func bindingSentMessages(t *testing.T, conn *ngaptesting.SctpConnStub) bindingSent {
	t.Helper()
	var sent bindingSent
	addNas := func(nasPdu []byte) {
		var security *nas_message.SecCtx
		if nas_message.GetSecHdrType(nasPdu) != nas_message.SecHdrTypePlainNas {
			security = bindingUESecurity()
		}
		nasMsg, nasErr := nas_message.Parse(nasPdu, security)
		require.NoError(t, nasErr)
		sent.nas = append(sent.nas, nasMsg)
	}
	for _, raw := range conn.MsgList {
		decoded, err := ngapMessage.Parse(raw)
		require.NoError(t, err)
		switch m := decoded.(type) {
		case *ngapMessage.InitialContextSetupRequest:
			sent.ngap = append(sent.ngap, sentICS)
			if m.NASPDU != nil {
				addNas(m.NASPDU.Value)
			}
		case *ngapMessage.UEContextReleaseCommand:
			sent.ngap = append(sent.ngap, sentRelease)
		case *ngapMessage.ErrorIndication:
			sent.ngap = append(sent.ngap, sentErrInd)
		case *ngapMessage.DownlinkNASTransport:
			sent.ngap = append(sent.ngap, sentDLNAS)
			addNas(m.NASPDU.Value)
		default:
			sent.ngap = append(sent.ngap, "other")
		}
	}
	return sent
}

// TS 24.501 4.4.4.3: an initial NAS message for a UE context found by the 5G-S-TMSI, the 5G-GUTI or
// the SUCI is attached to that context only if its MAC verifies against the context's 5G NAS
// security context. Otherwise the message is still answered, without touching the context: a
// SERVICE REQUEST gets SERVICE REJECT #9, a REGISTRATION REQUEST is authenticated on a new context
// linked to the found one (TestUnverifiedRegistrationAuthenticatesBeforeTheFoundContext follows it)
// and a DEREGISTRATION REQUEST is ignored. The pre-binding check does not consume the uplink NAS COUNT.
// Without the NGAP 5G-S-TMSI (TS 38.413 9.2.5.1), the 5G-GUTI of a REGISTRATION REQUEST or the
// 5G-S-TMSI of a SERVICE REQUEST finds the context; any other message gets ERROR INDICATION.
func TestHandleInitialUEMessageVerifiesMACBeforeBinding(t *testing.T) {
	previousConfig := factory.AmfConfig
	factory.AmfConfig = &factory.Config{Configuration: &factory.Configuration{}}
	t.Cleanup(func() { factory.AmfConfig = previousConfig })
	// No NRF is reachable: an authentication that is started ends in REGISTRATION REJECT.
	_, err := consumer.NewConsumer(nil)
	require.NoError(t, err)

	testCases := []struct {
		name       string
		nas        func(t *testing.T) []byte
		noTmsi     bool
		anType     models.AccessType
		unsecured  bool
		registered bool // the found context has the subscription data and AN key of registeredVictim
		bound      bool
		linked     bool
		ngap       []string
		nasType    nas_message.MsgType
		cause5GMM  uint8
		countAfter uint32
	}{
		{
			name:  "valid MAC SERVICE REQUEST is bound and accepted once",
			nas:   func(t *testing.T) []byte { return bindingNas(t, bindingServiceRequest(), "protected") },
			bound: true, ngap: []string{sentICS}, countAfter: 5,
		},
		{
			name:    "forged MAC SERVICE REQUEST gets SERVICE REJECT #9 without binding",
			nas:     func(t *testing.T) []byte { return bindingNas(t, bindingServiceRequest(), "forged") },
			ngap:    []string{sentDLNAS, sentRelease},
			nasType: nas_message.MsgTypeSvcRej, cause5GMM: ie.Cause5GMM_UEIdCannotBeDerivedByTheNw, countAfter: 4,
		},
		{
			name:    "plain SERVICE REQUEST gets SERVICE REJECT #9 without binding",
			nas:     func(t *testing.T) []byte { return bindingNas(t, bindingServiceRequest(), "plain") },
			ngap:    []string{sentDLNAS, sentRelease},
			nasType: nas_message.MsgTypeSvcRej, cause5GMM: ie.Cause5GMM_UEIdCannotBeDerivedByTheNw, countAfter: 4,
		},
		{
			name: "forged MAC mobility REGISTRATION REQUEST is authenticated on a new context",
			nas: func(t *testing.T) []byte {
				return bindingNas(t, bindingRegistrationRequest(ie.RegType_MobilityRegUpdating, bindingGuti), "forged")
			},
			linked: true, ngap: []string{sentDLNAS}, nasType: nas_message.MsgTypeIdReq, countAfter: 4,
		},
		{
			name: "plain mobility REGISTRATION REQUEST is authenticated on a new context (PR 267)",
			nas: func(t *testing.T) []byte {
				return bindingNas(t, bindingRegistrationRequest(ie.RegType_MobilityRegUpdating, bindingGuti), "plain")
			},
			linked: true, ngap: []string{sentDLNAS}, nasType: nas_message.MsgTypeIdReq, countAfter: 4,
		},
		{
			name: "plain periodic REGISTRATION REQUEST is authenticated on a new context",
			nas: func(t *testing.T) []byte {
				return bindingNas(t, bindingRegistrationRequest(ie.RegType_PeriodicRegUpdating, bindingGuti), "plain")
			},
			linked: true, ngap: []string{sentDLNAS}, nasType: nas_message.MsgTypeIdReq, countAfter: 4,
		},
		{
			name: "forged MAC mobility REGISTRATION REQUEST found by the NAS 5G-GUTI is authenticated on a new context",
			nas: func(t *testing.T) []byte {
				return bindingNas(t, bindingRegistrationRequest(ie.RegType_MobilityRegUpdating, bindingGuti), "forged")
			},
			noTmsi: true, linked: true, ngap: []string{sentDLNAS}, nasType: nas_message.MsgTypeIdReq, countAfter: 4,
		},
		{
			name: "forged MAC initial REGISTRATION REQUEST is authenticated on a new context",
			nas: func(t *testing.T) []byte {
				return bindingNas(t, bindingRegistrationRequest(ie.RegType_InitialReg, bindingGuti), "forged")
			},
			linked: true, ngap: []string{sentDLNAS}, nasType: nas_message.MsgTypeIdReq, countAfter: 4,
		},
		{
			name: "valid MAC initial REGISTRATION REQUEST named by the NAS 5G-GUTI is not bound, as before",
			nas: func(t *testing.T) []byte {
				return bindingNas(t, bindingRegistrationRequest(ie.RegType_InitialReg, bindingGuti), "protected")
			},
			noTmsi: true, linked: true, ngap: []string{sentDLNAS}, nasType: nas_message.MsgTypeIdReq, countAfter: 4,
		},
		{
			name: "valid MAC initial REGISTRATION REQUEST of the subscriber is bound",
			nas: func(t *testing.T) []byte {
				return bindingNas(t, bindingRegistrationRequest(ie.RegType_InitialReg, bindingGuti), "protected")
			},
			bound: true, countAfter: 5,
		},
		{
			name: "plain initial REGISTRATION REQUEST naming the SUCI is authenticated on a new context (PR 259)",
			nas: func(t *testing.T) []byte {
				return bindingNas(t, bindingRegistrationRequest(ie.RegType_InitialReg, bindingSuci), "plain")
			},
			noTmsi: true, linked: true, countAfter: 4,
		},
		{
			name: "plain non-3GPP initial REGISTRATION REQUEST naming the SUCI is authenticated on a new context (PR 274)",
			nas: func(t *testing.T) []byte {
				return bindingNas(t, bindingRegistrationRequest(ie.RegType_InitialReg, bindingSuci), "plain")
			},
			noTmsi: true, linked: true, anType: models.AccessType_NON_3_GPP_ACCESS, countAfter: 4,
		},
		{
			name:       "forged MAC DEREGISTRATION REQUEST is ignored",
			nas:        func(t *testing.T) []byte { return bindingNas(t, bindingDeregistrationRequest(), "forged") },
			ngap:       []string{sentRelease},
			countAfter: 4,
		},
		{
			name: "valid MAC mobility REGISTRATION REQUEST found by the NAS 5G-GUTI is bound and accepted",
			nas: func(t *testing.T) []byte {
				return bindingNas(t, unverifiedRegistrationRequest(ie.RegType_MobilityRegUpdating, bindingGuti), "protected")
			},
			noTmsi: true, registered: true, bound: true,
			ngap: []string{sentICS}, nasType: nas_message.MsgTypeRegAccept, countAfter: 5,
		},
		{
			name: "valid MAC periodic REGISTRATION REQUEST found by the NAS 5G-GUTI is bound and accepted",
			nas: func(t *testing.T) []byte {
				request := unverifiedRegistrationRequest(ie.RegType_PeriodicRegUpdating, bindingGuti)
				request.UESecCapability = nil // TS 24.501 8.2.6.4
				return bindingNas(t, request, "protected")
			},
			noTmsi: true, registered: true, bound: true,
			ngap: []string{sentICS}, nasType: nas_message.MsgTypeRegAccept, countAfter: 5,
		},
		{
			name:   "valid MAC SERVICE REQUEST found by the NAS 5G-S-TMSI is bound and accepted once",
			nas:    func(t *testing.T) []byte { return bindingNas(t, bindingServiceRequest(), "protected") },
			noTmsi: true, bound: true, ngap: []string{sentICS}, countAfter: 5,
		},
		{
			name: "plain mobility REGISTRATION REQUEST found by the NAS 5G-GUTI is authenticated on a new context",
			nas: func(t *testing.T) []byte {
				return bindingNas(t, bindingRegistrationRequest(ie.RegType_MobilityRegUpdating, bindingGuti), "plain")
			},
			noTmsi: true, linked: true, ngap: []string{sentDLNAS}, nasType: nas_message.MsgTypeIdReq, countAfter: 4,
		},
		{
			name:    "plain SERVICE REQUEST found by the NAS 5G-S-TMSI gets SERVICE REJECT #9 without binding",
			nas:     func(t *testing.T) []byte { return bindingNas(t, bindingServiceRequest(), "plain") },
			noTmsi:  true,
			ngap:    []string{sentDLNAS, sentRelease},
			nasType: nas_message.MsgTypeSvcRej, cause5GMM: ie.Cause5GMM_UEIdCannotBeDerivedByTheNw, countAfter: 4,
		},
		{
			name: "mobility REGISTRATION REQUEST naming the SUCI without NGAP 5G-S-TMSI gets ERROR INDICATION",
			nas: func(t *testing.T) []byte {
				return bindingNas(t, bindingRegistrationRequest(ie.RegType_MobilityRegUpdating, bindingSuci), "plain")
			},
			noTmsi: true, ngap: []string{sentErrInd, sentRelease}, countAfter: 4,
		},
		{
			name: "ciphered mobility REGISTRATION REQUEST without NGAP 5G-S-TMSI gets ERROR INDICATION",
			nas: func(t *testing.T) []byte {
				return bindingNas(t, bindingRegistrationRequest(ie.RegType_MobilityRegUpdating, bindingGuti), "ciphered")
			},
			noTmsi: true, ngap: []string{sentErrInd, sentRelease}, countAfter: 4,
		},
		{
			name:   "valid MAC DEREGISTRATION REQUEST without NGAP 5G-S-TMSI gets ERROR INDICATION, as before",
			nas:    func(t *testing.T) []byte { return bindingNas(t, bindingDeregistrationRequest(), "protected") },
			noTmsi: true, ngap: []string{sentErrInd, sentRelease}, countAfter: 4,
		},
		{
			name:      "a found context without a security context is bound as before",
			nas:       func(t *testing.T) []byte { return bindingNas(t, bindingServiceRequest(), "protected") },
			unsecured: true, bound: true,
			ngap:    []string{sentDLNAS, sentRelease},
			nasType: nas_message.MsgTypeSvcRej, cause5GMM: ie.Cause5GMM_UEIdCannotBeDerivedByTheNw, countAfter: 4,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			amfSelf := amf_context.GetSelf()
			NewAmfContext(amfSelf)
			connStub := new(ngaptesting.SctpConnStub)
			ran := NewAmfRan(connStub)
			if test.anType != "" {
				ran.AnType = test.anType
			}
			var victim *amf_context.AmfUe
			var peers *corePeers
			if test.registered {
				peers = newCorePeers(t, victimSupi)
				amfSelf.NrfUri = peers.URL
				victim = registeredVictim(t, peers)
				victim.Kamf = strings.Repeat("ab", 32)
				victim.UpdateSecurityContext(ran.AnType)
			} else {
				victim = bindingVictim(t, !test.unsecured)
			}

			fiveGSTmsi := bindingFiveGSTmsi
			if test.noTmsi {
				fiveGSTmsi = ""
			}
			initialUEMessage := BuildInitialUEMessage(t, 1, test.nas(t), fiveGSTmsi)
			initialUEMessage.UEContextRequest = &ngapType.UEContextRequest{
				Value: ngapType.UEContextRequestPresentRequested,
			}
			encoded, marshalErr := initialUEMessage.MarshalBinary()
			require.NoError(t, marshalErr)
			handleInitialUEMessageMain(
				ran, encoded, initialUEMessage.RANUENGAPID, initialUEMessage.NASPDU,
				initialUEMessage.UserLocationInformation, initialUEMessage.RRCEstablishmentCause,
				initialUEMessage.FiveGSTMSI, initialUEMessage.UEContextRequest,
			)

			ranUe := ran.RanUeFindByRanUeNgapID(1)
			require.NotNil(t, ranUe)
			require.Equal(t, test.bound, ranUe.AmfUe == victim, "bound to the found context")
			if test.linked {
				require.NotNil(t, ranUe.AmfUe)
				require.Same(t, victim, ranUe.AmfUe.AuthenticatingFor, "new context not linked to the found one")
			} else if !test.bound {
				require.Nil(t, ranUe.AmfUe)
			}
			require.Equal(t, test.countAfter, victim.ULCount.Get())
			if !test.bound {
				// The found context is untouched: still registered, with its security context,
				// CM-IDLE and still paged.
				require.True(t, victim.SecurityContextAvailable)
				require.True(t, victim.State[models.AccessType_3_GPP_ACCESS].Is(amf_context.Registered))
				require.Empty(t, victim.RanUe)
				require.NotNil(t, victim.T3513)
			}

			sent := bindingSentMessages(t, connStub)
			if test.ngap != nil {
				require.Equal(t, test.ngap, sent.ngap)
			} else {
				require.NotContains(t, sent.ngap, sentErrInd)
			}
			if peers != nil {
				// Accepted on the stored 5G NAS security context: no authentication, no other NF.
				require.Empty(t, peers.allRequests())
			}
			if test.nasType != 0 {
				require.NotEmpty(t, sent.nas)
				require.Equal(t, test.nasType, sent.nas[0].MsgType())
				switch m := sent.nas[0].(type) {
				case *nas_message.SvcRej:
					require.Equal(t, test.cause5GMM, m.Cause5GMM.Value)
				case *nas_message.RegRej:
					require.Equal(t, test.cause5GMM, m.Cause5GMM.Value)
				}
			}
		})
	}
}
