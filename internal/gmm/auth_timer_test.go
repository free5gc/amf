package gmm

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

func newAuthTimerTestUe(t *testing.T) *context.AmfUe {
	t.Helper()
	amfSelf := context.GetSelf()
	amfSelf.ServedGuamiList = []models.Guami{{PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"}, AmfId: "cafe00"}}
	ue := amfSelf.NewAmfUe("")
	t.Cleanup(ue.Remove)
	return ue
}

func authTimerTestSuci(t *testing.T, value []byte) *ie.MobileId5GS {
	t.Helper()
	suci := &ie.MobileId5GS{}
	require.NoError(t, suci.UnmarshalBinary(value))
	return suci
}

// TS 24.501 5.4.3.4, 5.4.3.6 b): an IDENTITY RESPONSE the AMF cannot use (here a
// SUCI with SUPI format NAI, which carries no PLMN) does not complete the
// identification procedure, so T3570 keeps running and can retransmit the
// IDENTITY REQUEST or abort the procedure.
func TestIdentityResponseUnusableSuciKeepsT3570(t *testing.T) {
	ue := newAuthTimerTestUe(t)
	ue.RequestIdentityType = ie.IdType_5GS_SUCI
	ue.T3570 = context.NewTimer(time.Hour, 4, func(int32) {}, func() {})

	err := HandleIdentityResponse(ue, &nasMessage.IdRsp{MobileId: authTimerTestSuci(t, []byte{0x11})})

	require.Error(t, err)
	require.NotNil(t, ue.T3570, "an unusable IDENTITY RESPONSE stopped T3570")
	require.Empty(t, ue.Suci)
}

func TestIdentityResponseValidSuciStopsT3570(t *testing.T) {
	ue := newAuthTimerTestUe(t)
	ue.RequestIdentityType = ie.IdType_5GS_SUCI
	ue.T3570 = context.NewTimer(time.Hour, 4, func(int32) {}, func() {})
	suci := authTimerTestSuci(t, []byte{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0, 0, 0, 0, 0x47, 0x78})

	require.NoError(t, HandleIdentityResponse(ue, &nasMessage.IdRsp{MobileId: suci}))

	require.Nil(t, ue.T3570)
	require.Equal(t, suci.SUCIStr(), ue.Suci)
}

func authTimerTestStartChallenge(ue *context.AmfUe, rand []byte, res []byte) {
	hResStar := sha256.Sum256(append(append([]byte{}, rand...), res...))
	ue.AuthenticationCtx = &models.Ausf_UEAU_UEAuthenticationCtx{
		AuthType: models.Ausf_UEAU_AuthType_5_G_AKA,
		Var5gAuthData: map[string]interface{}{
			"rand":      hex.EncodeToString(rand),
			"autn":      hex.EncodeToString(make([]byte, 16)),
			"hxresStar": hex.EncodeToString(hResStar[16:]),
		},
	}
	ue.T3560 = context.NewTimer(time.Hour, 4, func(int32) {}, func() {})
}

// TS 24.501 8.2.2.2 and 7.7.2: in 5G AKA the AUTHENTICATION RESPONSE carries RES*.
// A response without it is ignored, so T3560 keeps supervising the challenge
// (5.4.1.3.7 b) instead of leaving the procedure without a timer.
func TestAuthenticationResponseWithoutResStarKeepsT3560(t *testing.T) {
	ue := newAuthTimerTestUe(t)
	authTimerTestStartChallenge(ue, make([]byte, 16), make([]byte, 16))

	err := HandleAuthenticationResponse(ue, models.AccessType_3_GPP_ACCESS, &nasMessage.AuthRsp{})

	require.Error(t, err)
	require.NotNil(t, ue.T3560, "an AUTHENTICATION RESPONSE without RES* stopped T3560")
}

// TS 24.501 5.4.1.3.4: an AUTHENTICATION RESPONSE with RES* stops T3560 before
// RES* is checked; a wrong RES* is handled by 5.4.1.3.5, not by the timer.
func TestAuthenticationResponseWithResStarStopsT3560(t *testing.T) {
	ue := newAuthTimerTestUe(t)
	authTimerTestStartChallenge(ue, make([]byte, 16), make([]byte, 16))
	ue.IdentityTypeUsedForRegistration = ie.IdType_5GS_GUTI

	wrongRes := make([]byte, 16)
	wrongRes[0] = 1
	err := HandleAuthenticationResponse(ue, models.AccessType_3_GPP_ACCESS,
		&nasMessage.AuthRsp{AuthRspParam: &ie.AuthRspParam{Res: wrongRes}})

	require.NoError(t, err)
	require.Nil(t, ue.T3560)
	require.Equal(t, 1, ue.IdentityRequestSendTimes, "a wrong RES* for a 5G-GUTI starts identification")
}
