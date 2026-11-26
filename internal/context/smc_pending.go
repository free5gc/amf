package context

import "github.com/free5gc/nas/ie"

// BeginSMC marks the newly derived NAS security context as pending. The context
// can still be used to encode SMC and decode SMC Complete, but must not be
// considered established for normal NAS procedures such as Service Request.
// Call after SecurityModeCommand was encoded successfully and before it is sent.
func (ue *AmfUe) BeginSMC() {
	ue.smcPendingMu.Lock()
	defer ue.smcPendingMu.Unlock()
	ue.SMCPending = true
}

// IsSMCPending reports whether a newly derived context is awaiting SMC outcome.
func (ue *AmfUe) IsSMCPending() bool {
	ue.smcPendingMu.RLock()
	defer ue.smcPendingMu.RUnlock()
	return ue.SMCPending
}

// CompleteSMC commits the context for ordinary NAS procedures. It is invoked by
// the SecurityModeSuccessEvent callback, after the SMC Complete message has
// passed NAS integrity and semantic processing.
func (ue *AmfUe) CompleteSMC() {
	ue.smcPendingMu.Lock()
	defer ue.smcPendingMu.Unlock()
	ue.SMCPending = false
}

// AbortSMC invalidates the new context when the Security Mode Control fails.
// Do not call this unconditionally outside SMC: older established contexts may
// exist elsewhere or require an explicit restoration policy.
func (ue *AmfUe) AbortSMC() {
	ue.smcPendingMu.Lock()
	defer ue.smcPendingMu.Unlock()
	if ue.SMCPending {
		ue.SecurityContextAvailable = false
	}
	ue.SMCPending = false
}

// SecurityContextForSMCCompleteIsValid checks whether the locally derived keys
// may be used by the SMC Complete handler. Pending is intentionally allowed
// here: the new keys must verify SHT=4 before SMC can succeed.
func (ue *AmfUe) SecurityContextForSMCCompleteIsValid() bool {
	return ue.SecurityContextAvailable &&
		ue.NgKsi.Ksi != int32(ie.NASKeyNA) &&
		!ue.MacFailed
}
