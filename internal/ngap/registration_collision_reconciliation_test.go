package ngap

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/nas/ie"
	nas_message "github.com/free5gc/nas/message"
	ngapType "github.com/free5gc/ngap/ie"
	ngapMessage "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
)

// Start an actual initial registration on the stored subscriber, then send a
// second request on another connection. No GMM state is forced to ContextSetup.
func TestAuthenticatedInitialRegistrationCollision(t *testing.T) {
	previousConfig := factory.AmfConfig
	factory.AmfConfig = &factory.Config{Configuration: &factory.Configuration{}}
	t.Cleanup(func() { factory.AmfConfig = previousConfig })
	_, err := consumer.NewConsumer(nil)
	require.NoError(t, err)
	const access = models.AccessType_3_GPP_ACCESS
	for _, scenario := range []struct {
		name         string
		beforeAccept bool
		identical    bool
		withoutTimer bool
		control      string
	}{
		{name: "different request before accept", beforeAccept: true},
		{name: "identical request before accept", beforeAccept: true, identical: true},
		{name: "different request after accept"},
		{name: "identical request after accept", identical: true},
		{name: "identical request before accept without timer", beforeAccept: true, identical: true, withoutTimer: true},
		{name: "identical request after accept without timer", identical: true, withoutTimer: true},
		{name: "failed authentication", control: "authentication"},
		{name: "invalid security mode MAC", control: "MAC"},
		{name: "different authenticated SUPI", control: "SUPI"},
		{name: "N2 handover remains protected", control: "handover"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			peers := newCorePeers(t, victimSupi)
			self := amf_context.GetSelf()
			NewAmfContext(self)
			self.NrfUri = peers.URL
			timer := factory.TimerValue{Enable: !scenario.withoutTimer, ExpireTime: time.Hour, MaxRetryTimes: 4}
			self.T3550Cfg, self.T3570Cfg = timer, timer
			stored := registeredVictim(t, peers)
			if scenario.beforeAccept {
				stored.Pei = ""
			}
			request := unverifiedRegistrationRequest(ie.RegType_InitialReg, bindingSuci)
			request.Ngksi.Ksi = ie.NASKeyNA
			request.PDUSessStatus = nil
			completeSecurity := func(a *air, req *nas_message.RegReq, invalidMAC bool) {
				t.Helper()
				a.ueSec.UplinkCount.Set(0, 0)
				pdu := a.protected(&nas_message.SecModeComplete{
					NASMsgCntr: &ie.NASMsgCntr{Contents: plainNas(t, req)},
				}, nas_message.SecHdrTypeIntegrityProtectedAndCipheredWithNew5gNasSecCtx)
				if invalidMAC {
					pdu[2] ^= 0xff
				}
				a.uplink(pdu)
			}
			older := newAir(t, access)
			older.initialUEMessage(plainNas(t, request), "", false)
			firstProvisional := older.ranUe.GetAmfUe()
			t.Cleanup(firstProvisional.Remove)
			older.authenticate(akaResStar)
			completeSecurity(older, request, false)
			require.Same(t, stored, older.ranUe.GetAmfUe())
			require.True(t, stored.State[access].Is(amf_context.ContextSetup))
			_, firstMessages := older.sent()
			require.Len(t, firstMessages, 1)
			if scenario.beforeAccept {
				require.IsType(t, &nas_message.IdReq{}, firstMessages[0])
				require.Equal(t, ie.IdType_5GS_IMEI, stored.RequestIdentityType)
			} else {
				require.IsType(t, &nas_message.RegAccept{}, firstMessages[0])
			}
			originalGuti, originalKeys := stored.GetGuti(), stored.KnasInt
			initialRequests := len(peers.beyondAuthentication())
			oldT3550, oldT3570 := stored.T3550, stored.T3570

			nextRequest := unverifiedRegistrationRequest(ie.RegType_InitialReg, bindingSuci)
			nextRequest.Ngksi.Ksi = ie.NASKeyNA
			nextRequest.PDUSessStatus = nil
			if !scenario.identical {
				nextRequest.RegType5GS.FOR_Pending = true
			}
			if scenario.control == "handover" {
				stored.SetOnGoing(access, &amf_context.OnGoing{Procedure: amf_context.OnGoingProcedureN2Handover})
			}
			if scenario.control == "SUPI" {
				peers.supi = otherSupi
			}
			newer := newAir(t, access)
			newer.initialUEMessage(plainNas(t, nextRequest), "", false)
			provisional := newer.ranUe.GetAmfUe()
			t.Cleanup(provisional.Remove)
			require.NotSame(t, stored, provisional)
			assertUnchanged := func() {
				t.Helper()
				require.Same(t, older.ranUe, stored.GetRanUe(access))
				require.Equal(t, originalGuti, stored.GetGuti())
				require.Equal(t, originalKeys, stored.KnasInt)
				require.Same(t, oldT3550, stored.T3550)
				require.Same(t, oldT3570, stored.T3570)
				require.True(t, stored.State[access].Is(amf_context.ContextSetup))
				_, messages := older.sent()
				require.Empty(t, messages)
			}
			assertUnchanged()
			response := akaResStar
			if scenario.control == "authentication" {
				response = bytes.Repeat([]byte{0xff}, 16)
			}
			newer.authenticate(response)
			assertUnchanged()
			if scenario.control == "authentication" {
				return
			}
			completeSecurity(newer, nextRequest, scenario.control == "MAC")
			if scenario.control != "" {
				assertUnchanged()
				if scenario.control == "handover" {
					_, messages := newer.sent()
					require.Len(t, messages, 1)
					rejected, ok := messages[0].(*nas_message.RegRej)
					require.True(t, ok)
					require.Equal(t, ie.Cause5GMM_Congestion, rejected.Cause5GMM.Value)
				}
				return
			}

			require.Same(t, stored, newer.ranUe.GetAmfUe(), "authenticated collision must resume on the stored context")
			require.True(t, provisional.State[access].Is(amf_context.Deregistered))
			require.Nil(t, older.ranUe.GetAmfUe())
			procedures, oldMessages := older.sent()
			require.Equal(t, []string{sentRelease}, procedures)
			require.Empty(t, oldMessages)
			_, messages := newer.sent()
			require.Len(t, messages, 1)
			if scenario.beforeAccept {
				require.IsType(t, &nas_message.IdReq{}, messages[0])
				require.Equal(t, initialRequests, len(peers.beyondAuthentication()))
				imei := mobileIdentity5GSFromBytes([]byte{0x4b, 0x73, 0x80, 0x61, 0x21, 0x85, 0x16, 0x15})
				newer.uplink(newer.protected(&nas_message.IdRsp{MobileId: &imei},
					nas_message.SecHdrTypeIntegrityProtectedAndCiphered))
				_, messages = newer.sent()
				require.Len(t, messages, 1)
			} else if scenario.identical {
				require.Equal(t, originalGuti, stored.GetGuti(), "resending Accept must keep its GUTI")
				require.Equal(t, initialRequests, len(peers.beyondAuthentication()),
					"duplicate request must not rerun registration")
			}
			require.IsType(t, &nas_message.RegAccept{}, messages[0])
			require.Equal(t, !scenario.withoutTimer, stored.HasT3550())
			newer.uplink(newer.protected(&nas_message.RegComplete{}, nas_message.SecHdrTypeIntegrityProtectedAndCiphered))
			require.True(t, stored.State[access].Is(amf_context.Registered))
			require.False(t, stored.HasT3550())
			dispatchMain(older.ran, &ngapMessage.UEContextReleaseComplete{
				AMFUENGAPID: &ngapType.AMFUENGAPID{Value: older.ranUe.AmfUeNgapId},
				RANUENGAPID: &ngapType.RANUENGAPID{Value: older.ranUe.RanUeNgapId},
			}, nil)
			require.Nil(t, self.RanUeFindByAmfUeNgapID(older.ranUe.AmfUeNgapId))
			found, exists := self.AmfUeFindBySupi(victimSupi)
			require.True(t, exists)
			require.Same(t, stored, found)
			require.Same(t, newer.ranUe, stored.GetRanUe(access))
		})
	}
}
