package Namf_OAM_test

import (
	"encoding/json"
	"flag"
	"github.com/urfave/cli"
	"gofree5gc/lib/CommonConsumerTestData/AMF/TestAmf"
	"gofree5gc/lib/openapi/models"
	"gofree5gc/src/amf/amf_context"
	"gofree5gc/src/amf/amf_service"
	"gofree5gc/src/amf/gmm/gmm_state"
	"gofree5gc/src/nrf/nrf_service"
	"net/http"
	"testing"
	"time"
)

func nrfInit() {
	flags := flag.FlagSet{}
	c := cli.NewContext(nil, &flags, nil)
	nrf := &nrf_service.NRF{}
	nrf.Initialize(c)
	go nrf.Start()
	time.Sleep(100 * time.Millisecond)
}

func init() {
	nrfInit()
}

type PduSession struct {
	PduSessionId int32
	Snssai       models.Snssai
	Dnn          string
}

type UEInfo struct {
	AccessType  models.AccessType
	Supi        string
	Guti        string
	Tai         models.Tai
	PduSessions []PduSession
	CmState     models.CmState
}

func TestRegisteredUEContext(t *testing.T) {
	flags := flag.FlagSet{}
	c := cli.NewContext(nil, &flags, nil)
	amf := &amf_service.AMF{}
	amf.Initialize(c)
	go amf.Start()

	TestAmf.AmfInit()
	testUe := TestAmf.TestAmf.UePool["imsi-2089300007487"]
	testUe.Sm[models.AccessType__3_GPP_ACCESS].Transfer(gmm_state.REGISTERED, nil)
	smContext := amf_context.SmContext{
		PduSessionContext: &models.PduSessionContext{
			AccessType:   models.AccessType__3_GPP_ACCESS,
			PduSessionId: 1,
			SNssai: &models.Snssai{
				Sst: 1,
				Sd:  "010203",
			},
			Dnn: "internet",
		},
	}
	testUe.SmContextList[1] = &smContext
	amfSelf := amf_context.AMF_Self()
	amfSelf.AddAmfUeToUePool(testUe, "imsi-2089300007487")
	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get("https://localhost:29518/namf-oam/v1/registered-ue-context")
	if err != nil {
		t.Error(err)
	} else {
		var body []UEInfo
		json.NewDecoder(resp.Body).Decode(&body)
		t.Logf("response body: %+v", body)
		resp.Body.Close()
	}
}
