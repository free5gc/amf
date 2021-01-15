package util

import (
	"free5gc/src/amf/context"
	"free5gc/src/amf/logger"
)

func StopT3513(ue *context.AmfUe) {
	if ue == nil {
		logger.UtilLog.Errorln("AmfUe is nil")
		return
	}

	if ue.T3513 != nil {
		ue.T3513.Stop()
		ue.T3513 = nil
	}
	ue.T3513RetryTimes = 0
}

func StopT3522(ue *context.AmfUe) {
	if ue == nil {
		logger.UtilLog.Errorln("AmfUe is nil")
		return
	}

	if ue.T3522 != nil {
		ue.T3522.Stop()
		ue.T3522 = nil
	}
	ue.T3522RetryTimes = 0
}

func StopT3550(ue *context.AmfUe) {
	if ue == nil {
		logger.UtilLog.Errorln("AmfUe is nil")
		return
	}

	if ue.T3550 != nil {
		ue.T3550.Stop()
		ue.T3550 = nil
	}
	ue.T3550RetryTimes = 0
}

func StopT3560(ue *context.AmfUe) {
	if ue == nil {
		logger.UtilLog.Errorln("AmfUe is nil")
		return
	}

	if ue.T3560 != nil {
		ue.T3560.Stop()
		ue.T3560 = nil
	}
	ue.T3560RetryTimes = 0
}

func StopT3565(ue *context.AmfUe) {
	if ue == nil {
		logger.UtilLog.Errorln("AmfUe is nil")
		return
	}

	if ue.T3565 != nil {
		ue.T3565.Stop()
		ue.T3565 = nil
	}
	ue.T3565RetryTimes = 0
}
