package amf_message

type Event int

const (
	EventNGAPMessage Event = iota
	EventNGAPAcceptConn
	EventNGAPCloseConn
	EventProvideLocationInfo
	EventSmContextStatusNotify
	EventGMMT3513
	EventGMMT3565
	EventGMMT3560ForAuthenticationRequest
	EventGMMT3560ForSecurityModeCommand
	EventGMMT3550
	EventGMMT3522
	EventAmPolicyControlUpdateNotifyUpdate
	EventAmPolicyControlUpdateNotifyTerminate
	EventOAMRegisteredUEContext
	EventN1MessageNotify
)
