package ngap

import (
	"testing"

	"github.com/stretchr/testify/require"

	amf_context "github.com/free5gc/amf/internal/context"
	ngaptesting "github.com/free5gc/amf/internal/ngap/testing"
	"github.com/free5gc/ngap/aper"
	ngapMessage "github.com/free5gc/ngap/message"
)

// TS 24.501 5.5.1.2.8 b) and 5.5.1.3.8 b): a REGISTRATION REQUEST received with a
// protocol error is answered with a REGISTRATION REJECT.
func TestRegistrationRequestWithAProtocolErrorIsRejected(t *testing.T) {
	testCases := []struct {
		name       string
		nasPDU     []byte
		fiveGSTmsi string
	}{
		// EPD 5GMM, plain, REGISTRATION REQUEST, ngKSI 7 and its registration type, and no
		// 5GS mobile identity.
		{"initial registration", []byte{0x7e, 0x00, 0x41, 0x79}, ""},
		{"mobility registration updating", []byte{0x7e, 0x00, 0x41, 0x7a}, ""},
		{"mobility registration updating with a 5G-S-TMSI", []byte{0x7e, 0x00, 0x41, 0x7a}, "fe0000000001"},
		// The same plain message in an integrity protected one, as an initial NAS message
		// of a UE with a security context is (TS 24.501 4.4.6).
		{"integrity protected", []byte{0x7e, 0x01, 0x11, 0x22, 0x33, 0x44, 0x00, 0x7e, 0x00, 0x41, 0x7a}, ""},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			NewAmfContext(amf_context.GetSelf())
			conn := new(ngaptesting.SctpConnStub)
			ran := NewAmfRan(conn)

			dispatchMain(ran, BuildInitialUEMessage(t, 1, tc.nasPDU, tc.fiveGSTmsi), nil)

			var rejects []aper.OctetString
			released := false
			for _, msg := range conn.MsgList {
				decoded, err := ngapMessage.Parse(msg)
				require.NoError(t, err)
				switch m := decoded.(type) {
				case *ngapMessage.ErrorIndication:
					t.Fatalf("an Error Indication: %+v", m)
				case *ngapMessage.DownlinkNASTransport:
					rejects = append(rejects, m.NASPDU.Value)
				case *ngapMessage.UEContextReleaseCommand:
					released = true
				}
			}
			// A plain REGISTRATION REJECT with 5GMM cause #96 "invalid mandatory information"
			// and T3502.
			require.Equal(t, []aper.OctetString{{0x7e, 0x00, 0x44, 0x60, 0x16, 0x01, 0x2c}}, rejects)
			require.True(t, released)
		})
	}
}
