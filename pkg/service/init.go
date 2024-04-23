package service

import (
	"context"
	"io"
	"os"

	"github.com/sirupsen/logrus"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/pkg/factory"
)

type AmfApp struct {
	cfg    *factory.Config
	amfCtx *amf_context.AMFContext
	ctx    context.Context
	cancel context.CancelFunc

	consumer *consumer.Consumer

	// ngap
	start func(*AmfApp)
	stop  func(*AmfApp)
}

var AMF *AmfApp

func GetApp() *AmfApp {
	return AMF
}

func NewApp(cfg *factory.Config, funcs []func(*AmfApp)) (*AmfApp, error) {
	amf := &AmfApp{
		cfg:   cfg,
		start: funcs[0],
		stop:  funcs[1],
	}
	amf.SetLogEnable(cfg.GetLogEnable())
	amf.SetLogLevel(cfg.GetLogLevel())
	amf.SetReportCaller(cfg.GetLogReportCaller())

	amf.amfCtx = amf_context.GetSelf()
	amf_context.InitAmfContext(amf.amfCtx)

	consumer, err := consumer.NewConsumer(amf)
	if err != nil {
		return amf, err
	}
	amf.consumer = consumer

	AMF = amf

	return amf, nil
}

func (a *AmfApp) SetLogEnable(enable bool) {
	logger.MainLog.Infof("Log enable is set to [%v]", enable)
	if enable && logger.Log.Out == os.Stderr {
		return
	} else if !enable && logger.Log.Out == io.Discard {
		return
	}

	a.cfg.SetLogEnable(enable)
	if enable {
		logger.Log.SetOutput(os.Stderr)
	} else {
		logger.Log.SetOutput(io.Discard)
	}
}

func (a *AmfApp) SetLogLevel(level string) {
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		logger.MainLog.Warnf("Log level [%s] is invalid", level)
		return
	}

	logger.MainLog.Infof("Log level is set to [%s]", level)
	if lvl == logger.Log.GetLevel() {
		return
	}

	a.cfg.SetLogLevel(level)
	logger.Log.SetLevel(lvl)
}

func (a *AmfApp) SetReportCaller(reportCaller bool) {
	logger.MainLog.Infof("Report Caller is set to [%v]", reportCaller)
	if reportCaller == logger.Log.ReportCaller {
		return
	}

	a.cfg.SetLogReportCaller(reportCaller)
	logger.Log.SetReportCaller(reportCaller)
}

func (a *AmfApp) Start(tlsKeyLogPath string) {
	logger.InitLog.Infoln("Server started")

	a.start(a)
}

// Used in AMF planned removal procedure
func (a *AmfApp) Terminate() {
	logger.InitLog.Infof("Terminating AMF...")
	a.cancel()
	a.stop(a)
	logger.InitLog.Infof("AMF terminated")
}

func (a *AmfApp) Config() *factory.Config {
	return a.cfg
}

func (a *AmfApp) Context() *amf_context.AMFContext {
	return a.amfCtx
}

func (a *AmfApp) CancelContext() context.Context {
	return a.ctx
}

func (a *AmfApp) Consumer() *consumer.Consumer {
	return a.consumer
}
