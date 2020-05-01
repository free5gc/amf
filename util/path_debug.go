//+build debug

package util

import (
	"free5gc/lib/path_util"
)

var AmfLogPath = path_util.Gofree5gcPath("free5gc/amfsslkey.log")
var AmfPemPath = path_util.Gofree5gcPath("free5gc/support/TLS/_debug.pem")
var AmfKeyPath = path_util.Gofree5gcPath("free5gc/support/TLS/_debug.key")
var DefaultAmfConfigPath = path_util.Gofree5gcPath("free5gc/config/amfcfg.conf")
