package service

import (
	"context"
	"os"
	"testing"
	"time"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/sbi"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/internal/sbi/processor"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
  "github.com/free5gc/openapi/models"
)

func TestSetLogLevel(t *testing.T) {
	config := &factory.Config{}
	app := &AmfApp{cfg: config}

	app.SetLogLevel("debug")
	assert.Equal(t, "debug", app.cfg.GetLogLevel())

	app.SetLogLevel("invalid") // should warn, but not panic
}

func TestSetLogEnable(t *testing.T) {
	config := &factory.Config{}
	app := &AmfApp{cfg: config}

	app.SetLogEnable(true)

	app.SetLogEnable(false)
	assert.False(t, app.cfg.GetLogEnable())
}

func TestSetReportCaller(t *testing.T) {
	config := &factory.Config{}
	app := &AmfApp{cfg: config}

	app.SetReportCaller(true)
	assert.True(t, app.cfg.GetLogReportCaller())

	app.SetReportCaller(false)
	assert.False(t, app.cfg.GetLogReportCaller())
}

func TestSetLogFilePath(t *testing.T) {
	config := &factory.Config{}
	app := &AmfApp{cfg: config}

	logFilePath := "/tmp/test_amf_log.log"
	f, err := os.Create(logFilePath)
	assert.NoError(t, err)
	defer f.Close()
	defer os.Remove(logFilePath)

	app.SetLogFilePath(f)
	assert.Equal(t, logFilePath, f.Name())
}

func TestTerminate(t *testing.T) {
	config := &factory.Config{}
	ctx, cancel := context.WithCancel(context.Background())
	app := &AmfApp{cfg: config, ctx: ctx}
	app.ctx, app.cancel = ctx, cancel

	done := make(chan struct{})
	go func() {
		app.Terminate()
		close(done)
	}()

	<-done
}

func TestCancelContext(t *testing.T) {
	ctx := context.Background()
	app := &AmfApp{
		ctx: ctx,
	}
	assert.Equal(t, ctx, app.CancelContext())
}
func TestWaitRoutineStopped(t *testing.T) {
	app := &AmfApp{}
	app.wg.Add(1)
	go func() {
		time.Sleep(10 * time.Millisecond)
		app.wg.Done()
	}()
	app.WaitRoutineStopped()
}

func TestGetters(t *testing.T) {
	cfg := &factory.Config{}
	app := &AmfApp{
		cfg:       cfg,
		amfCtx:    &amf_context.AMFContext{},
		consumer:  &consumer.Consumer{},
		processor: &processor.Processor{},
	}
	assert.Equal(t, cfg, app.Config())
	assert.NotNil(t, app.Context())
	assert.NotNil(t, app.Consumer())
	assert.NotNil(t, app.Processor())
}
func TestNewApp(t *testing.T) {

	tmpLog := "/tmp/amf_test.log"
	_ = os.WriteFile(tmpLog, []byte{}, 0644)
	defer os.Remove(tmpLog)

	cfg := &factory.Config{
		Configuration: &factory.Configuration{
			ServiceNameList: []string{
				string(models.ServiceName_NAMF_COMM),
				string(models.ServiceName_NAMF_EVTS),
				string(models.ServiceName_NAMF_MT),
				string(models.ServiceName_NAMF_LOC),
				string(models.ServiceName_NAMF_OAM),
			},
		},
	}
	factory.AmfConfig = cfg
	app, err := NewApp(context.Background(), cfg, "")
	assert.NoError(t, err)
	assert.NotNil(t, app)
}
 

type MockServerAmf struct {
	mock.Mock

	Ctx  *amf_context.AMFContext
	Cfg  *factory.Config
	Cons *consumer.Consumer
	Proc *processor.Processor
}

func (m *MockServerAmf) Init() {}

func (m *MockServerAmf) Run() error {
	return nil
}

func (m *MockServerAmf) Terminate() {}

func (m *MockServerAmf) Context() *amf_context.AMFContext {
	amfCtx := amf_context.GetSelf()
	amfCtx.NrfUri = "http://nrf.example.com"
	m.Ctx = amfCtx
	return m.Ctx
}

func (m *MockServerAmf) Config() *factory.Config {
	return m.Cfg
}

// Wrap the mock inside a dummy real consumer
func (m *MockServerAmf) Consumer() *consumer.Consumer {
	c, err := consumer.NewConsumer(AMF)
	if err != nil {
		panic("failed to create consumer: " + err.Error()) // fail fast in tests
	}
	m.Cons = c
	return m.Cons
}
func (m *MockServerAmf) Processor() *processor.Processor {
	return m.Proc
}
func (m *MockServerAmf) SetLogEnable(enable bool)          {}
func (m *MockServerAmf) SetLogLevel(level string)          {}
func (m *MockServerAmf) SetReportCaller(reportCaller bool) {}
func (m *MockServerAmf) Start()                            {}

// In package consumer
type DummySCTPListener struct{}

func (d *DummySCTPListener) Close() error {
	// Pretend to close without doing anything
	return nil
}
func TestListenShutdownEvent_TriggersTerminate(t *testing.T) {

	cfg := &factory.Config{
		Configuration: &factory.Configuration{
			NgapIpList:           []string{"127.0.0.1"},
			NgapPort:             38412,
			ServedGumaiList:      []models.Guami{},
			NrfUri:               "http://nrf.example.com",
			SCTP:                 &factory.Sctp{},
		},
	}
	factory.AmfConfig = cfg
	amfCtx := amf_context.GetSelf()
	amfCtx.NrfUri = "http://nrf.example.com"
	c, err := consumer.NewConsumer(&MockServerAmf{})
	assert.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())

	app := &AmfApp{
		cfg:       cfg,
		ctx:       ctx,
		cancel:    cancel,
		amfCtx:    amfCtx,
		consumer:  c,
		processor: &processor.Processor{}, // Can mock if needed
		sbiServer: &sbi.Server{},          // Optional
	}

	app.wg.Add(1)

	go app.listenShutdownEvent()

	// trigger shutdown
	cancel()
	// wait for termination to complete
	app.wg.Wait()
}

 

