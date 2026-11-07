package common

import "github.com/free5gc/nas/ie"

// RegistrationType returns the 5GS registration type of a REGISTRATION REQUEST as the network
// interprets it: TS 24.501 9.11.3.7, the unused value is interpreted as "initial registration".
func RegistrationType(value uint8) uint8 {
	if value == 0 {
		return ie.RegType_InitialReg
	}
	return value
}
