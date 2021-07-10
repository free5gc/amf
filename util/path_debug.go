//+build debug

package util

import (
	"github.com/free5gc/path_util"
)

var (
	AmfLogPath           = path_util.Free5gcPath("free5gc/amfsslkey.log")
	AmfPemPath           = path_util.Free5gcPath("free5gc/support/TLS/_debug.pem")
	AmfKeyPath           = path_util.Free5gcPath("free5gc/support/TLS/_debug.key")
	DefaultAmfConfigPath = path_util.Free5gcPath("free5gc/config/amfcfg.yaml")
)
