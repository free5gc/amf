package amf_message

type Event int

const (
	EventNGAPMessage Event = iota
	EventNGAPAcceptConn
	EventNGAPCloseConn
	EventSmContextStatusNotify
	EventGMMT3513
	EventGMMT3565
	EventGMMT3560ForAuthenticationRequest
	EventGMMT3560ForSecurityModeCommand
	EventGMMT3550
	EventGMMT3522
	EventAmPolicyControlUpdateNotifyTerminate
	EventN1MessageNotify
)
