package gmm_test

import (
	"free5gc/lib/fsm"
	"free5gc/src/amf/gmm"
	"testing"
)

func TestGmmFSM(t *testing.T) {
	fsm.ExportDot(gmm.GmmFSM, "gmm")
}
