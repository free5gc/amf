package amf_message

type Event int

const (
	EventNGAPMessage Event = iota
	EventNGAPAcceptConn
	EventNGAPCloseConn
	EventGMMT3513
	EventGMMT3565
	EventGMMT3560ForAuthenticationRequest
	EventGMMT3560ForSecurityModeCommand
	EventGMMT3550
	EventGMMT3522
)
