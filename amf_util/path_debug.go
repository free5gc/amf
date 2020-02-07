//+build debug

package amf_util

import (
	"gofree5gc/lib/path_util"
)

var AmfLogPath = path_util.Gofree5gcPath("gofree5gc/amfsslkey.log")
var AmfPemPath = path_util.Gofree5gcPath("gofree5gc/support/TLS/_debug.pem")
var AmfKeyPath = path_util.Gofree5gcPath("gofree5gc/support/TLS/_debug.key")
var DefaultAmfConfigPath = path_util.Gofree5gcPath("gofree5gc/config/amfcfg.conf")
