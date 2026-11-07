package gmm

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/free5gc/nas/ie"
)

// TS 24.501 9.11.3.47: the network interprets the unused value 0, and "MA PDU request" when it does not support MA
// PDU sessions, as "initial request"; it keeps the other values.
func TestInterpretRequestType(t *testing.T) {
	for value, expected := range map[ie.ConstReqType]ie.ConstReqType{
		0:                               ie.ReqType_InitialReq,
		ie.ReqType_InitialReq:           ie.ReqType_InitialReq,
		ie.ReqType_ExistingPDUSess:      ie.ReqType_ExistingPDUSess,
		ie.ReqType_InitialEmergReq:      ie.ReqType_InitialEmergReq,
		ie.ReqType_ExistingEmergPDUSess: ie.ReqType_ExistingEmergPDUSess,
		ie.ReqType_ModReq:               ie.ReqType_ModReq,
		ie.ReqType_MAPDUReq:             ie.ReqType_InitialReq,
		ie.ReqType_Reserved:             ie.ReqType_Reserved,
	} {
		requestType := &ie.ReqType{Value: value}
		interpretRequestType(requestType)
		require.Equal(t, expected, requestType.Value, "request type %d", value)
	}
	interpretRequestType(nil)
}
