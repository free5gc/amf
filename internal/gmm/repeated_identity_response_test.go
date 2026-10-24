package gmm

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/amf/internal/context"
	"github.com/free5gc/nas/ie"
	nasMessage "github.com/free5gc/nas/message"
	"github.com/free5gc/openapi/models"
)

func newIdentificationTestUe(t *testing.T) *context.AmfUe {
	t.Helper()
	amfSelf := context.GetSelf()
	amfSelf.ServedGuamiList = []models.Guami{{PlmnId: &models.PlmnIdNid{Mcc: "208", Mnc: "93"}, AmfId: "cafe00"}}
	ue := amfSelf.NewAmfUe("")
	t.Cleanup(ue.Remove)
	return ue
}

func identificationTestIdentity(t *testing.T, value []byte) *ie.MobileId5GS {
	t.Helper()
	identity := &ie.MobileId5GS{}
	require.NoError(t, identity.UnmarshalBinary(value))
	return identity
}

// TS 24.501 5.4.3.4: the first IDENTITY RESPONSE completes the identification.
// A second one, e.g. the UE's answer to an IDENTITY REQUEST retransmitted by
// T3570, is not accepted, so the Authentication state does not restart the
// authentication with a new challenge and a second T3560.
func TestRepeatedIdentityResponseIsIgnored(t *testing.T) {
	ue := newIdentificationTestUe(t)
	ue.RequestIdentityType = ie.IdType_5GS_SUCI
	suci := identificationTestIdentity(t, []byte{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0, 0, 0, 0, 0x47, 0x78})

	require.NoError(t, HandleIdentityResponse(ue, &nasMessage.IdRsp{MobileId: suci}))
	require.Equal(t, suci.SUCIStr(), ue.Suci)

	require.Error(t, HandleIdentityResponse(ue, &nasMessage.IdRsp{MobileId: suci}),
		"a repeated IDENTITY RESPONSE was accepted and would restart authentication")
}

// An IDENTITY RESPONSE is accepted only while an IDENTITY REQUEST is outstanding,
// whatever identity type it carries.
func TestIdentityResponseWithoutRequestIsIgnored(t *testing.T) {
	ue := newIdentificationTestUe(t)

	err := HandleIdentityResponse(ue, &nasMessage.IdRsp{MobileId: identificationTestIdentity(t, []byte{0x00})})

	require.Error(t, err, "an unsolicited IDENTITY RESPONSE was accepted and would restart authentication")
}

// A response that cannot be used does not complete the identification, so the
// UE's corrected response to the same IDENTITY REQUEST is still accepted.
func TestIdentityResponseAfterUnusableResponseIsAccepted(t *testing.T) {
	ue := newIdentificationTestUe(t)
	ue.RequestIdentityType = ie.IdType_5GS_SUCI

	require.Error(t, HandleIdentityResponse(ue,
		&nasMessage.IdRsp{MobileId: identificationTestIdentity(t, []byte{0x11})}))
	require.NoError(t, HandleIdentityResponse(ue, &nasMessage.IdRsp{MobileId: identificationTestIdentity(t,
		[]byte{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0, 0, 0, 0, 0x47, 0x78})}))
}
