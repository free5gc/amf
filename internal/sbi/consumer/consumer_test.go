package consumer

import (
	"testing"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/openapi/models"
)

// fakeApp satisfies ConsumerAmf. pkg/app/mock.go is generated from an older
// interface and no longer implements app.App, so the consumer tests carry their
// own stub instead.
type fakeApp struct {
	ctx *amf_context.AMFContext
	cfg *factory.Config
}

func (f *fakeApp) SetLogEnable(bool)                {}
func (f *fakeApp) SetLogLevel(string)               {}
func (f *fakeApp) SetReportCaller(bool)             {}
func (f *fakeApp) Start()                           {}
func (f *fakeApp) Terminate()                       {}
func (f *fakeApp) Context() *amf_context.AMFContext { return f.ctx }
func (f *fakeApp) Config() *factory.Config          { return f.cfg }

// newTestAmfContext returns the smallest AMF context buildNFInstance accepts: a
// served GUAMI, a supported TAI and a registration address.
func newTestAmfContext() *amf_context.AMFContext {
	plmnId := models.PlmnId{Mcc: "208", Mnc: "93"}
	return &amf_context.AMFContext{
		NfId:         testNfId,
		NrfUri:       testNrfUri,
		UriScheme:    models.UriScheme_HTTP,
		RegisterIPv4: "127.0.0.18",
		SBIPort:      8000,
		ServedGuamiList: []models.Guami{
			{PlmnId: &models.PlmnIdNid{Mcc: plmnId.Mcc, Mnc: plmnId.Mnc}, AmfId: "cafe00"},
		},
		SupportTaiLists: []models.Tai{
			{PlmnId: &plmnId, Tac: "000001"},
		},
	}
}

func newTestConsumer(t *testing.T, ctx *amf_context.AMFContext) *Consumer {
	t.Helper()

	testConsumer, err := NewConsumer(&fakeApp{
		ctx: ctx,
		cfg: &factory.Config{Configuration: &factory.Configuration{}},
	})
	if err != nil {
		t.Fatalf("NewConsumer: %v", err)
	}

	return testConsumer
}
