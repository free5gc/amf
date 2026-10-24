package common

import (
	"github.com/free5gc/amf/internal/context"
)

// StopAll5GSMMTimers stops every 5GMM timer of the UE; see
// context.AmfUe.StopAll5GSMMTimers.
func StopAll5GSMMTimers(ue *context.AmfUe) {
	ue.StopAll5GSMMTimers()
}
