package logger

import (
	"os"
	"time"

	formatter "github.com/antonfisher/nested-logrus-formatter"
	"github.com/sirupsen/logrus"

	aperLogger "github.com/free5gc/aper/logger"
	nasLogger "github.com/free5gc/nas/logger"
	ngapLogger "github.com/free5gc/ngap/logger"
	fsmLogger "github.com/free5gc/util/fsm/logger"
	logger_util "github.com/free5gc/util/logger"
)

var (
	log         *logrus.Logger
	AppLog      *logrus.Entry
	InitLog     *logrus.Entry
	CfgLog      *logrus.Entry
	ContextLog  *logrus.Entry
	NgapLog     *logrus.Entry
	HandlerLog  *logrus.Entry
	HttpLog     *logrus.Entry
	GmmLog      *logrus.Entry
	MtLog       *logrus.Entry
	ProducerLog *logrus.Entry
	LocationLog *logrus.Entry
	CommLog     *logrus.Entry
	CallbackLog *logrus.Entry
	UtilLog     *logrus.Entry
	NasLog      *logrus.Entry
	ConsumerLog *logrus.Entry
	EeLog       *logrus.Entry
	GinLog      *logrus.Entry
)

const (
	FieldRanAddr     string = "ran_addr"
	FieldAmfUeNgapID string = "amf_ue_ngap_id"
	FieldSupi        string = "supi"
)

func init() {
	log = logrus.New()
	log.SetReportCaller(false)

	log.Formatter = &formatter.Formatter{
		TimestampFormat: time.RFC3339,
		TrimMessages:    true,
		NoFieldsSpace:   true,
		HideKeys:        true,
		FieldsOrder:     []string{"component", "category", FieldRanAddr, FieldAmfUeNgapID, FieldSupi},
	}

	AppLog = log.WithFields(logrus.Fields{"component": "AMF", "category": "App"})
	InitLog = log.WithFields(logrus.Fields{"component": "AMF", "category": "Init"})
	CfgLog = log.WithFields(logrus.Fields{"component": "AMF", "category": "CFG"})
	ContextLog = log.WithFields(logrus.Fields{"component": "AMF", "category": "Context"})
	NgapLog = log.WithFields(logrus.Fields{"component": "AMF", "category": "NGAP"})
	HandlerLog = log.WithFields(logrus.Fields{"component": "AMF", "category": "Handler"})
	HttpLog = log.WithFields(logrus.Fields{"component": "AMF", "category": "HTTP"})
	GmmLog = log.WithFields(logrus.Fields{"component": "AMF", "category": "GMM"})
	MtLog = log.WithFields(logrus.Fields{"component": "AMF", "category": "MT"})
	ProducerLog = log.WithFields(logrus.Fields{"component": "AMF", "category": "Producer"})
	LocationLog = log.WithFields(logrus.Fields{"component": "AMF", "category": "LocInfo"})
	CommLog = log.WithFields(logrus.Fields{"component": "AMF", "category": "Comm"})
	CallbackLog = log.WithFields(logrus.Fields{"component": "AMF", "category": "Callback"})
	UtilLog = log.WithFields(logrus.Fields{"component": "AMF", "category": "Util"})
	NasLog = log.WithFields(logrus.Fields{"component": "AMF", "category": "NAS"})
	ConsumerLog = log.WithFields(logrus.Fields{"component": "AMF", "category": "Consumer"})
	EeLog = log.WithFields(logrus.Fields{"component": "AMF", "category": "EventExposure"})
	GinLog = log.WithFields(logrus.Fields{"component": "AMF", "category": "GIN"})
}

func LogFileHook(logNfPath string, log5gcPath string) error {
	if fullPath, err := logger_util.CreateFree5gcLogFile(log5gcPath); err == nil {
		if fullPath != "" {
			free5gcLogHook, hookErr := logger_util.NewFileHook(fullPath, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o666)
			if err != nil {
				return hookErr
			}
			log.Hooks.Add(free5gcLogHook)
			aperLogger.GetLogger().Hooks.Add(free5gcLogHook)
			ngapLogger.GetLogger().Hooks.Add(free5gcLogHook)
			nasLogger.GetLogger().Hooks.Add(free5gcLogHook)
			fsmLogger.GetLogger().Hooks.Add(free5gcLogHook)
		}
	} else {
		return err
	}

	if fullPath, err := logger_util.CreateNfLogFile(logNfPath, "amf.log"); err == nil {
		selfLogHook, hookErr := logger_util.NewFileHook(fullPath, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o666)
		if err != nil {
			return hookErr
		}
		log.Hooks.Add(selfLogHook)
		aperLogger.GetLogger().Hooks.Add(selfLogHook)
		ngapLogger.GetLogger().Hooks.Add(selfLogHook)
		nasLogger.GetLogger().Hooks.Add(selfLogHook)
		fsmLogger.GetLogger().Hooks.Add(selfLogHook)
	} else {
		return err
	}

	return nil
}

func SetLogLevel(level logrus.Level) {
	log.SetLevel(level)
}

func SetReportCaller(set bool) {
	log.SetReportCaller(set)
}
