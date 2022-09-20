//go:build cfgmgr
// +build cfgmgr

package factory

import (
	"net"
	"strings"
	"time"

	"github.com/coreswitch/cmd"
	"github.com/free5gc/amf/internal/logger"
	aperLogger "github.com/free5gc/aper/logger"
	nasLogger "github.com/free5gc/nas/logger"
	ngapLogger "github.com/free5gc/ngap/logger"
	"github.com/free5gc/openapi/models"
	fsmLogger "github.com/free5gc/util/fsm/logger"
	logger_util "github.com/free5gc/util/logger"
	"github.com/sirupsen/logrus"
)

var parser *cmd.Node

func validate() error {
	if _, err := AmfConfig.Validate(); err != nil {
		return err
	}
	if initSyncCh != nil {
		close(initSyncCh)
		initSyncCh = nil
	}
	return nil
}

func amfName(com int, args cmd.Args) int {
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.AmfName = args[0].(string)
	case cmd.Delete:
		AmfConfig.Configuration.AmfName = ""
	}
	return cmd.Success
}

func ngapIpList(com int, args cmd.Args) int {
	addr := args[0].(net.IP)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.NgapIpList = append(AmfConfig.Configuration.NgapIpList, addr.String())
	case cmd.Delete:
		// TODO
	}
	return cmd.Success
}

func sbiConfigEnsure() {
	if AmfConfig.Configuration.Sbi == nil {
		AmfConfig.Configuration.Sbi = &Sbi{}
	}
}

func sbiScheme(com int, args cmd.Args) int {
	sbiConfigEnsure()
	scheme := args[0].(string)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.Sbi.Scheme = scheme
	case cmd.Delete:
		AmfConfig.Configuration.Sbi.Scheme = ""
	}
	return cmd.Success
}

func sbiRegisterIpv4(com int, args cmd.Args) int {
	sbiConfigEnsure()
	addr := args[0].(net.IP)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.Sbi.RegisterIPv4 = addr.String()
	case cmd.Delete:
		AmfConfig.Configuration.Sbi.RegisterIPv4 = ""
	}
	return cmd.Success
}

func sbiBindingIpv4(com int, args cmd.Args) int {
	sbiConfigEnsure()
	addr := args[0].(net.IP)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.Sbi.BindingIPv4 = addr.String()
	case cmd.Delete:
		AmfConfig.Configuration.Sbi.BindingIPv4 = ""
	}
	return cmd.Success
}

func sbiPort(com int, args cmd.Args) int {
	sbiConfigEnsure()
	port := args[0].(uint64)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.Sbi.Port = int(port)
	case cmd.Delete:
		AmfConfig.Configuration.Sbi.Port = 0
	}
	return cmd.Success
}

func serviceNameList(com int, args cmd.Args) int {
	serviceName := args[0].(string)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.ServiceNameList = append(AmfConfig.Configuration.ServiceNameList, serviceName)
	case cmd.Delete:
		// TODO
	}
	return cmd.Success
}

var servedGuamiMap = map[string]*models.Guami{}

func servedGuamiSet(guami *models.Guami) {
	if guami.AmfId == "" {
		return
	}
	if guami.PlmnId.Mcc == "" || guami.PlmnId.Mnc == "" {
		return
	}
	// commandSync() does this for now.
	// AmfConfig.Configuration.ServedGumaiList = append(AmfConfig.Configuration.ServedGumaiList, *guami)
}

func servedGuamiGet(name string) *models.Guami {
	if guami, ok := servedGuamiMap[name]; ok {
		return guami
	} else {
		guami = &models.Guami{}
		guami.PlmnId = &models.PlmnId{}
		servedGuamiMap[name] = guami
		return guami
	}
}

func servedGuamiList(com int, args cmd.Args) int {
	name := args[0].(string)
	switch com {
	case cmd.Set:
		servedGuamiGet(name)
	case cmd.Delete:
	}
	return cmd.Success
}

func servedGuamiListPlmnidMcc(com int, args cmd.Args) int {
	name := args[0].(string)
	mcc := args[1].(string)
	guami := servedGuamiGet(name)
	switch com {
	case cmd.Set:
		guami.PlmnId.Mcc = mcc
		servedGuamiSet(guami)
	case cmd.Delete:
		guami.PlmnId.Mcc = ""
	}
	return cmd.Success
}

func servedGuamiListPlmnidMnc(com int, args cmd.Args) int {
	name := args[0].(string)
	mnc := args[1].(string)
	guami := servedGuamiGet(name)
	switch com {
	case cmd.Set:
		guami.PlmnId.Mnc = mnc
		servedGuamiSet(guami)
	case cmd.Delete:
		guami.PlmnId.Mnc = ""
	}
	return cmd.Success
}

func servedGuamiListAmfId(com int, args cmd.Args) int {
	name := args[0].(string)
	amfId := args[1].(string)
	guami := servedGuamiGet(name)
	switch com {
	case cmd.Set:
		guami.AmfId = amfId
		servedGuamiSet(guami)
	case cmd.Delete:
		guami.AmfId = ""
	}
	return cmd.Success
}

var supportTaiMap = map[string]*models.Tai{}

func supportTaiSet(tai *models.Tai) {
	if tai.Tac == "" {
		return
	}
	if tai.PlmnId.Mcc == "" || tai.PlmnId.Mnc == "" {
		return
	}
	// commandSync() does this for now.
	// AmfConfig.Configuration.SupportTAIList = append(AmfConfig.Configuration.SupportTAIList, *tai)
}

func supportTaiGet(name string) *models.Tai {
	if tai, ok := supportTaiMap[name]; ok {
		return tai
	} else {
		tai = &models.Tai{}
		tai.PlmnId = &models.PlmnId{}
		supportTaiMap[name] = tai
		return tai
	}
}

func supportTaiList(com int, args cmd.Args) int {
	name := args[0].(string)
	switch com {
	case cmd.Set:
		supportTaiGet(name)
	case cmd.Delete:
	}
	return cmd.Success
}

func supportTaiListPlmnidMcc(com int, args cmd.Args) int {
	name := args[0].(string)
	mcc := args[1].(string)
	tai := supportTaiGet(name)
	switch com {
	case cmd.Set:
		tai.PlmnId.Mcc = mcc
		supportTaiSet(tai)
	case cmd.Delete:
		tai.PlmnId.Mcc = ""
	}
	return cmd.Success
}

func supportTaiListPlmnidMnc(com int, args cmd.Args) int {
	name := args[0].(string)
	mnc := args[1].(string)
	tai := supportTaiGet(name)
	switch com {
	case cmd.Set:
		tai.PlmnId.Mnc = mnc
		supportTaiSet(tai)
	case cmd.Delete:
		tai.PlmnId.Mnc = ""
	}
	return cmd.Success
}

func supportTaiListTac(com int, args cmd.Args) int {
	name := args[0].(string)
	tac := args[1].(string)
	tai := supportTaiGet(name)
	switch com {
	case cmd.Set:
		tai.Tac = tac
		supportTaiSet(tai)
	case cmd.Delete:
		tai.Tac = ""
	}
	return cmd.Success
}

var plmnSupportMap = map[string]*PlmnSupportItem{}

func plmnSupportGet(name string) *PlmnSupportItem {
	if plmn, ok := plmnSupportMap[name]; ok {
		return plmn
	} else {
		plmn = &PlmnSupportItem{
			PlmnId: &models.PlmnId{},
		}
		plmnSupportMap[name] = plmn
		return plmn
	}
}

func plmnSupportList(com int, args cmd.Args) int {
	name := args[0].(string)
	switch com {
	case cmd.Set:
		plmnSupportGet(name)
	case cmd.Delete:
	}
	return cmd.Success
}

func plmnSupportListPlmnidMcc(com int, args cmd.Args) int {
	name := args[0].(string)
	mcc := args[1].(string)
	plmn := plmnSupportGet(name)
	switch com {
	case cmd.Set:
		plmn.PlmnId.Mcc = mcc
	case cmd.Delete:
		plmn.PlmnId.Mcc = ""
	}
	return cmd.Success
}

func plmnSupportListPlmnidMnc(com int, args cmd.Args) int {
	name := args[0].(string)
	mnc := args[1].(string)
	plmn := plmnSupportGet(name)
	switch com {
	case cmd.Set:
		plmn.PlmnId.Mnc = mnc
	case cmd.Delete:
		plmn.PlmnId.Mnc = ""
	}
	return cmd.Success
}

func plmnSupportListSnssaiList(com int, args cmd.Args) int {
	name := args[0].(string)
	plmn := plmnSupportGet(name)
	switch com {
	case cmd.Set:
		plmn.SNssaiList = append(plmn.SNssaiList, models.Snssai{})
	case cmd.Delete:
	}
	return cmd.Success
}

func plmnSupportListSnssaiListSst(com int, args cmd.Args) int {
	name := args[0].(string)
	plmn := plmnSupportGet(name)
	sst := args[2].(uint64)
	switch com {
	case cmd.Set:
		i := len(plmn.SNssaiList)
		plmn.SNssaiList[i-1].Sst = int32(sst)
	case cmd.Delete:
	}
	return cmd.Success
}

func plmnSupportListSnssaiListSd(com int, args cmd.Args) int {
	name := args[0].(string)
	plmn := plmnSupportGet(name)
	sd := args[2].(string)
	switch com {
	case cmd.Set:
		i := len(plmn.SNssaiList)
		plmn.SNssaiList[i-1].Sd = sd
	case cmd.Delete:
	}
	return cmd.Success
}

func supportDnnList(com int, args cmd.Args) int {
	dnn := args[0].(string)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.SupportDnnList = append(AmfConfig.Configuration.SupportDnnList, dnn)
	case cmd.Delete:
		// TODO
	}
	return cmd.Success
}

func securityIntegrityOrder(com int, args cmd.Args) int {
	secStr := args[0].(string)
	secs := strings.Split(secStr, " ")
	if AmfConfig.Configuration.Security == nil {
		AmfConfig.Configuration.Security = &Security{}
	}
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.Security.IntegrityOrder = secs
	case cmd.Delete:
		AmfConfig.Configuration.Security.IntegrityOrder = nil
	}
	return cmd.Success
}

func securityCipheringOrder(com int, args cmd.Args) int {
	secStr := args[0].(string)
	secs := strings.Split(secStr, " ")
	if AmfConfig.Configuration.Security == nil {
		AmfConfig.Configuration.Security = &Security{}
	}
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.Security.CipheringOrder = secs
	case cmd.Delete:
		AmfConfig.Configuration.Security.CipheringOrder = nil
	}
	return cmd.Success
}

func networkNameFull(com int, args cmd.Args) int {
	name := args[0].(string)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.NetworkName.Full = name
	case cmd.Delete:
		AmfConfig.Configuration.NetworkName.Full = ""
	}
	return cmd.Success
}

func networkNameShort(com int, args cmd.Args) int {
	name := args[0].(string)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.NetworkName.Short = name
	case cmd.Delete:
		AmfConfig.Configuration.NetworkName.Short = ""
	}
	return cmd.Success
}

func booleanParse(str string) bool {
	if str == "true" {
		return true
	} else {
		return false
	}
}

func ensure5gs() {
	if AmfConfig.Configuration.NetworkFeatureSupport5GS == nil {
		AmfConfig.Configuration.NetworkFeatureSupport5GS = &NetworkFeatureSupport5GS{}
	}
}

func network5gsEnable(com int, args cmd.Args) int {
	str := args[0].(string)
	enable := booleanParse(str)
	ensure5gs()
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.NetworkFeatureSupport5GS.Enable = enable
	case cmd.Delete:
		AmfConfig.Configuration.NetworkFeatureSupport5GS.Enable = false
	}
	return cmd.Success
}

func network5gsLength(com int, args cmd.Args) int {
	val := args[0].(uint64)
	ensure5gs()
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.NetworkFeatureSupport5GS.Length = uint8(val)
	case cmd.Delete:
		AmfConfig.Configuration.NetworkFeatureSupport5GS.Length = 0
	}
	return cmd.Success
}

func network5gsImsVoPS(com int, args cmd.Args) int {
	val := args[0].(uint64)
	ensure5gs()
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.NetworkFeatureSupport5GS.ImsVoPS = uint8(val)
	case cmd.Delete:
		AmfConfig.Configuration.NetworkFeatureSupport5GS.ImsVoPS = 0
	}
	return cmd.Success
}

func network5gsEmc(com int, args cmd.Args) int {
	val := args[0].(uint64)
	ensure5gs()
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.NetworkFeatureSupport5GS.Emc = uint8(val)
	case cmd.Delete:
		AmfConfig.Configuration.NetworkFeatureSupport5GS.Emc = 0
	}
	return cmd.Success
}

func network5gsEmf(com int, args cmd.Args) int {
	val := args[0].(uint64)
	ensure5gs()
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.NetworkFeatureSupport5GS.Emf = uint8(val)
	case cmd.Delete:
		AmfConfig.Configuration.NetworkFeatureSupport5GS.Emf = 0
	}
	return cmd.Success
}

func network5gsIwkN26(com int, args cmd.Args) int {
	val := args[0].(uint64)
	ensure5gs()
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.NetworkFeatureSupport5GS.IwkN26 = uint8(val)
	case cmd.Delete:
		AmfConfig.Configuration.NetworkFeatureSupport5GS.IwkN26 = 0
	}
	return cmd.Success
}

func network5gsMpsi(com int, args cmd.Args) int {
	val := args[0].(uint64)
	ensure5gs()
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.NetworkFeatureSupport5GS.Mpsi = uint8(val)
	case cmd.Delete:
		AmfConfig.Configuration.NetworkFeatureSupport5GS.Mpsi = 0
	}
	return cmd.Success
}

func network5gsEmcN3(com int, args cmd.Args) int {
	val := args[0].(uint64)
	ensure5gs()
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.NetworkFeatureSupport5GS.EmcN3 = uint8(val)
	case cmd.Delete:
		AmfConfig.Configuration.NetworkFeatureSupport5GS.EmcN3 = 0
	}
	return cmd.Success
}

func network5gsMcsi(com int, args cmd.Args) int {
	val := args[0].(uint64)
	ensure5gs()
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.NetworkFeatureSupport5GS.Mcsi = uint8(val)
	case cmd.Delete:
		AmfConfig.Configuration.NetworkFeatureSupport5GS.Mcsi = 0
	}
	return cmd.Success
}

func t3502Value(com int, args cmd.Args) int {
	val := args[0].(uint64)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.T3502Value = int(val)
	case cmd.Delete:
		AmfConfig.Configuration.T3502Value = 0
	}
	return cmd.Success
}

func t3512Value(com int, args cmd.Args) int {
	val := args[0].(uint64)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.T3512Value = int(val)
	case cmd.Delete:
		AmfConfig.Configuration.T3512Value = 0
	}
	return cmd.Success
}

func non3gppDeregistrationTimerValue(com int, args cmd.Args) int {
	val := args[0].(uint64)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.Non3gppDeregistrationTimerValue = int(val)
	case cmd.Delete:
		AmfConfig.Configuration.Non3gppDeregistrationTimerValue = 0
	}
	return cmd.Success
}

func t3513Enable(com int, args cmd.Args) int {
	str := args[0].(string)
	enable := booleanParse(str)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.T3513.Enable = enable
	case cmd.Delete:
		AmfConfig.Configuration.T3513.Enable = false
	}
	return cmd.Success
}

func t3513ExpireTime(com int, args cmd.Args) int {
	val := args[0].(uint64)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.T3513.ExpireTime = time.Duration(time.Second * time.Duration(val))
	case cmd.Delete:
		AmfConfig.Configuration.T3513.ExpireTime = time.Duration(0)
	}
	return cmd.Success
}

func t3513MaxRetryTimes(com int, args cmd.Args) int {
	val := args[0].(uint64)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.T3513.MaxRetryTimes = int(val)
	case cmd.Delete:
		AmfConfig.Configuration.T3513.MaxRetryTimes = 0
	}
	return cmd.Success
}

func t3522Enable(com int, args cmd.Args) int {
	str := args[0].(string)
	enable := booleanParse(str)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.T3522.Enable = enable
	case cmd.Delete:
		AmfConfig.Configuration.T3522.Enable = false
	}
	return cmd.Success
}

func t3522ExpireTime(com int, args cmd.Args) int {
	val := args[0].(uint64)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.T3522.ExpireTime = time.Duration(time.Second * time.Duration(val))
	case cmd.Delete:
		AmfConfig.Configuration.T3522.ExpireTime = time.Duration(0)
	}
	return cmd.Success
}

func t3522MaxRetryTimes(com int, args cmd.Args) int {
	val := args[0].(uint64)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.T3522.MaxRetryTimes = int(val)
	case cmd.Delete:
		AmfConfig.Configuration.T3522.MaxRetryTimes = 0
	}
	return cmd.Success
}

func t3550Enable(com int, args cmd.Args) int {
	str := args[0].(string)
	enable := booleanParse(str)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.T3550.Enable = enable
	case cmd.Delete:
		AmfConfig.Configuration.T3550.Enable = false
	}
	return cmd.Success
}

func t3550ExpireTime(com int, args cmd.Args) int {
	val := args[0].(uint64)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.T3550.ExpireTime = time.Duration(time.Second * time.Duration(val))
	case cmd.Delete:
		AmfConfig.Configuration.T3550.ExpireTime = time.Duration(0)
	}
	return cmd.Success
}

func t3550MaxRetryTimes(com int, args cmd.Args) int {
	val := args[0].(uint64)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.T3550.MaxRetryTimes = int(val)
	case cmd.Delete:
		AmfConfig.Configuration.T3550.MaxRetryTimes = 0
	}
	return cmd.Success
}

func t3560Enable(com int, args cmd.Args) int {
	str := args[0].(string)
	enable := booleanParse(str)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.T3560.Enable = enable
	case cmd.Delete:
		AmfConfig.Configuration.T3560.Enable = false
	}
	return cmd.Success
}

func t3560ExpireTime(com int, args cmd.Args) int {
	val := args[0].(uint64)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.T3560.ExpireTime = time.Duration(time.Second * time.Duration(val))
	case cmd.Delete:
		AmfConfig.Configuration.T3560.ExpireTime = time.Duration(0)
	}
	return cmd.Success
}

func t3560MaxRetryTimes(com int, args cmd.Args) int {
	val := args[0].(uint64)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.T3560.MaxRetryTimes = int(val)
	case cmd.Delete:
		AmfConfig.Configuration.T3560.MaxRetryTimes = 0
	}
	return cmd.Success
}

func t3565Enable(com int, args cmd.Args) int {
	str := args[0].(string)
	enable := booleanParse(str)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.T3565.Enable = enable
	case cmd.Delete:
		AmfConfig.Configuration.T3565.Enable = false
	}
	return cmd.Success
}

func t3565ExpireTime(com int, args cmd.Args) int {
	val := args[0].(uint64)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.T3565.ExpireTime = time.Duration(time.Second * time.Duration(val))
	case cmd.Delete:
		AmfConfig.Configuration.T3565.ExpireTime = time.Duration(0)
	}
	return cmd.Success
}

func t3565MaxRetryTimes(com int, args cmd.Args) int {
	val := args[0].(uint64)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.T3565.MaxRetryTimes = int(val)
	case cmd.Delete:
		AmfConfig.Configuration.T3565.MaxRetryTimes = 0
	}
	return cmd.Success
}

func t3570Enable(com int, args cmd.Args) int {
	str := args[0].(string)
	enable := booleanParse(str)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.T3570.Enable = enable
	case cmd.Delete:
		AmfConfig.Configuration.T3570.Enable = false
	}
	return cmd.Success
}

func t3570ExpireTime(com int, args cmd.Args) int {
	val := args[0].(uint64)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.T3570.ExpireTime = time.Duration(time.Second * time.Duration(val))
	case cmd.Delete:
		AmfConfig.Configuration.T3570.ExpireTime = time.Duration(0)
	}
	return cmd.Success
}

func t3570MaxRetryTimes(com int, args cmd.Args) int {
	val := args[0].(uint64)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.T3570.MaxRetryTimes = int(val)
	case cmd.Delete:
		AmfConfig.Configuration.T3570.MaxRetryTimes = 0
	}
	return cmd.Success
}

func ensureLogger() {
	AmfConfig.Logger.AMF = &logger_util.LogSetting{}
	AmfConfig.Logger.NAS = &logger_util.LogSetting{}
	AmfConfig.Logger.FSM = &logger_util.LogSetting{}
	AmfConfig.Logger.NGAP = &logger_util.LogSetting{}
	AmfConfig.Logger.Aper = &logger_util.LogSetting{}
}

func setLogLevel() {
	if AmfConfig.Logger == nil {
		logger.InitLog.Warnln("AMF config without log level setting!!!")
		return
	}

	if AmfConfig.Logger.AMF != nil {
		if AmfConfig.Logger.AMF.DebugLevel != "" {
			if level, err := logrus.ParseLevel(AmfConfig.Logger.AMF.DebugLevel); err != nil {
				logger.InitLog.Warnf("AMF Log level [%s] is invalid, set to [info] level",
					AmfConfig.Logger.AMF.DebugLevel)
				logger.SetLogLevel(logrus.InfoLevel)
			} else {
				logger.InitLog.Infof("AMF Log level is set to [%s] level", level)
				logger.SetLogLevel(level)
			}
		} else {
			logger.InitLog.Warnln("AMF Log level not set. Default set to [info] level")
			logger.SetLogLevel(logrus.InfoLevel)
		}
		logger.SetReportCaller(AmfConfig.Logger.AMF.ReportCaller)
	}

	if AmfConfig.Logger.NAS != nil {
		if AmfConfig.Logger.NAS.DebugLevel != "" {
			if level, err := logrus.ParseLevel(AmfConfig.Logger.NAS.DebugLevel); err != nil {
				nasLogger.NasLog.Warnf("NAS Log level [%s] is invalid, set to [info] level",
					AmfConfig.Logger.NAS.DebugLevel)
				logger.SetLogLevel(logrus.InfoLevel)
			} else {
				nasLogger.SetLogLevel(level)
			}
		} else {
			nasLogger.NasLog.Warnln("NAS Log level not set. Default set to [info] level")
			nasLogger.SetLogLevel(logrus.InfoLevel)
		}
		nasLogger.SetReportCaller(AmfConfig.Logger.NAS.ReportCaller)
	}

	if AmfConfig.Logger.NGAP != nil {
		if AmfConfig.Logger.NGAP.DebugLevel != "" {
			if level, err := logrus.ParseLevel(AmfConfig.Logger.NGAP.DebugLevel); err != nil {
				ngapLogger.NgapLog.Warnf("NGAP Log level [%s] is invalid, set to [info] level",
					AmfConfig.Logger.NGAP.DebugLevel)
				ngapLogger.SetLogLevel(logrus.InfoLevel)
			} else {
				ngapLogger.SetLogLevel(level)
			}
		} else {
			ngapLogger.NgapLog.Warnln("NGAP Log level not set. Default set to [info] level")
			ngapLogger.SetLogLevel(logrus.InfoLevel)
		}
		ngapLogger.SetReportCaller(AmfConfig.Logger.NGAP.ReportCaller)
	}

	if AmfConfig.Logger.FSM != nil {
		if AmfConfig.Logger.FSM.DebugLevel != "" {
			if level, err := logrus.ParseLevel(AmfConfig.Logger.FSM.DebugLevel); err != nil {
				fsmLogger.FsmLog.Warnf("FSM Log level [%s] is invalid, set to [info] level",
					AmfConfig.Logger.FSM.DebugLevel)
				fsmLogger.SetLogLevel(logrus.InfoLevel)
			} else {
				fsmLogger.SetLogLevel(level)
			}
		} else {
			fsmLogger.FsmLog.Warnln("FSM Log level not set. Default set to [info] level")
			fsmLogger.SetLogLevel(logrus.InfoLevel)
		}
		fsmLogger.SetReportCaller(AmfConfig.Logger.FSM.ReportCaller)
	}

	if AmfConfig.Logger.Aper != nil {
		if AmfConfig.Logger.Aper.DebugLevel != "" {
			if level, err := logrus.ParseLevel(AmfConfig.Logger.Aper.DebugLevel); err != nil {
				aperLogger.AperLog.Warnf("Aper Log level [%s] is invalid, set to [info] level",
					AmfConfig.Logger.Aper.DebugLevel)
				aperLogger.SetLogLevel(logrus.InfoLevel)
			} else {
				aperLogger.SetLogLevel(level)
			}
		} else {
			aperLogger.AperLog.Warnln("Aper Log level not set. Default set to [info] level")
			aperLogger.SetLogLevel(logrus.InfoLevel)
		}
		aperLogger.SetReportCaller(AmfConfig.Logger.Aper.ReportCaller)
	}
}

func loggerAmfDebugLevel(com int, args cmd.Args) int {
	level := args[0].(string)
	switch com {
	case cmd.Set:
		AmfConfig.Logger.AMF.DebugLevel = level
	case cmd.Delete:
		AmfConfig.Logger.AMF.DebugLevel = ""
	}
	setLogLevel()
	return cmd.Success
}

func loggerAmfReportCaller(com int, args cmd.Args) int {
	str := args[0].(string)
	enable := booleanParse(str)
	switch com {
	case cmd.Set:
		AmfConfig.Logger.AMF.ReportCaller = enable
	case cmd.Delete:
		AmfConfig.Logger.AMF.ReportCaller = false
	}
	setLogLevel()
	return cmd.Success
}

func loggerNasDebugLevel(com int, args cmd.Args) int {
	level := args[0].(string)
	switch com {
	case cmd.Set:
		AmfConfig.Logger.NAS.DebugLevel = level
	case cmd.Delete:
		AmfConfig.Logger.NAS.DebugLevel = ""
	}
	setLogLevel()
	return cmd.Success
}

func loggerNasReportCaller(com int, args cmd.Args) int {
	str := args[0].(string)
	enable := booleanParse(str)
	switch com {
	case cmd.Set:
		AmfConfig.Logger.NAS.ReportCaller = enable
	case cmd.Delete:
		AmfConfig.Logger.NAS.ReportCaller = false
	}
	setLogLevel()
	return cmd.Success
}

func loggerFsmDebugLevel(com int, args cmd.Args) int {
	level := args[0].(string)
	switch com {
	case cmd.Set:
		AmfConfig.Logger.FSM.DebugLevel = level
	case cmd.Delete:
		AmfConfig.Logger.FSM.DebugLevel = ""
	}
	setLogLevel()
	return cmd.Success
}

func loggerFsmReportCaller(com int, args cmd.Args) int {
	str := args[0].(string)
	enable := booleanParse(str)
	switch com {
	case cmd.Set:
		AmfConfig.Logger.FSM.ReportCaller = enable
	case cmd.Delete:
		AmfConfig.Logger.FSM.ReportCaller = false
	}
	setLogLevel()
	return cmd.Success
}

func loggerNgapDebugLevel(com int, args cmd.Args) int {
	level := args[0].(string)
	switch com {
	case cmd.Set:
		AmfConfig.Logger.NGAP.DebugLevel = level
	case cmd.Delete:
		AmfConfig.Logger.NGAP.DebugLevel = ""
	}
	setLogLevel()
	return cmd.Success
}

func loggerNgapReportCaller(com int, args cmd.Args) int {
	str := args[0].(string)
	enable := booleanParse(str)
	switch com {
	case cmd.Set:
		AmfConfig.Logger.NGAP.ReportCaller = enable
	case cmd.Delete:
		AmfConfig.Logger.NGAP.ReportCaller = false
	}
	setLogLevel()
	return cmd.Success
}

func loggerAperDebugLevel(com int, args cmd.Args) int {
	level := args[0].(string)
	switch com {
	case cmd.Set:
		AmfConfig.Logger.Aper.DebugLevel = level
	case cmd.Delete:
		AmfConfig.Logger.Aper.DebugLevel = ""
	}
	setLogLevel()
	return cmd.Success
}

func loggerAperReportCaller(com int, args cmd.Args) int {
	str := args[0].(string)
	enable := booleanParse(str)
	switch com {
	case cmd.Set:
		AmfConfig.Logger.Aper.ReportCaller = enable
	case cmd.Delete:
		AmfConfig.Logger.Aper.ReportCaller = false
	}
	setLogLevel()
	return cmd.Success
}

func nrfUri(com int, args cmd.Args) int {
	uri := args[0].(string)
	switch com {
	case cmd.Set:
		AmfConfig.Configuration.NrfUri = uri
	case cmd.Delete:
		AmfConfig.Configuration.NrfUri = ""
	}
	return cmd.Success
}

func commandSync() {
	for _, guami := range servedGuamiMap {
		AmfConfig.Configuration.ServedGumaiList = append(AmfConfig.Configuration.ServedGumaiList, *guami)
	}
	for _, tai := range supportTaiMap {
		AmfConfig.Configuration.SupportTAIList = append(AmfConfig.Configuration.SupportTAIList, *tai)
	}
	for _, plmn := range plmnSupportMap {
		AmfConfig.Configuration.PlmnSupportList = append(AmfConfig.Configuration.PlmnSupportList, *plmn)
	}
}

func commandInit() {
	AmfConfig = Config{}
	AmfConfig.Info = &Info{
		Version:     "1.0.3",
		Description: "Config from configuration manager",
	}
	AmfConfig.Configuration = &Configuration{}
	AmfConfig.Logger = &logger_util.Logger{}
	ensureLogger()

	parser = cmd.NewParser()
	parser.InstallCmd([]string{"amf", "name", "WORD"}, amfName)
	parser.InstallCmd([]string{"amf", "ngap-ip-list", "A.B.C.D"}, ngapIpList)
	parser.InstallCmd([]string{"amf", "sbi", "scheme", "WORD"}, sbiScheme)
	parser.InstallCmd([]string{"amf", "sbi", "register-ipv4", "A.B.C.D"}, sbiRegisterIpv4)
	parser.InstallCmd([]string{"amf", "sbi", "binding-ipv4", "A.B.C.D"}, sbiBindingIpv4)
	parser.InstallCmd([]string{"amf", "sbi", "port", "<0-65535>"}, sbiPort)
	parser.InstallCmd([]string{"amf", "service-name-list", "WORD"}, serviceNameList)
	parser.InstallCmd([]string{"amf", "served-guami-list", "WORD"}, servedGuamiList)
	parser.InstallCmd([]string{"amf", "served-guami-list", "WORD", "plmnid", "mcc", "WORD"}, servedGuamiListPlmnidMcc)
	parser.InstallCmd([]string{"amf", "served-guami-list", "WORD", "plmnid", "mnc", "WORD"}, servedGuamiListPlmnidMnc)
	parser.InstallCmd([]string{"amf", "served-guami-list", "WORD", "amfid", "WORD"}, servedGuamiListAmfId)
	parser.InstallCmd([]string{"amf", "support-tai-list", "WORD"}, supportTaiList)
	parser.InstallCmd([]string{"amf", "support-tai-list", "WORD", "plmnid", "mcc", "WORD"}, supportTaiListPlmnidMcc)
	parser.InstallCmd([]string{"amf", "support-tai-list", "WORD", "plmnid", "mnc", "WORD"}, supportTaiListPlmnidMnc)
	parser.InstallCmd([]string{"amf", "support-tai-list", "WORD", "tac", "WORD"}, supportTaiListTac)
	parser.InstallCmd([]string{"amf", "plmn-support-list", "WORD"}, plmnSupportList)
	parser.InstallCmd([]string{"amf", "plmn-support-list", "WORD", "plmnid", "mcc", "WORD"}, plmnSupportListPlmnidMcc)
	parser.InstallCmd([]string{"amf", "plmn-support-list", "WORD", "plmnid", "mnc", "WORD"}, plmnSupportListPlmnidMnc)
	parser.InstallCmd([]string{"amf", "plmn-support-list", "WORD", "snssai-list", "WORD"}, plmnSupportListSnssaiList)
	parser.InstallCmd([]string{"amf", "plmn-support-list", "WORD", "snssai-list", "WORD", "sst", "<0-255>"}, plmnSupportListSnssaiListSst)
	parser.InstallCmd([]string{"amf", "plmn-support-list", "WORD", "snssai-list", "WORD", "sd", "WORD"}, plmnSupportListSnssaiListSd)
	parser.InstallCmd([]string{"amf", "support-dnn-list", "WORD"}, supportDnnList)

	parser.InstallCmd([]string{"amf", "security", "integrity-order", "LINE"}, securityIntegrityOrder)
	parser.InstallCmd([]string{"amf", "security", "ciphering-order", "LINE"}, securityCipheringOrder)

	parser.InstallCmd([]string{"amf", "network-name", "full", "WORD"}, networkNameFull)
	parser.InstallCmd([]string{"amf", "network-name", "short", "WORD"}, networkNameShort)

	parser.InstallCmd([]string{"amf", "network-feature-support-5gs", "enable", "WORD"}, network5gsEnable)
	parser.InstallCmd([]string{"amf", "network-feature-support-5gs", "length", "<1-3>"}, network5gsLength)
	parser.InstallCmd([]string{"amf", "network-feature-support-5gs", "ims-vops", "<0-255>"}, network5gsImsVoPS)
	parser.InstallCmd([]string{"amf", "network-feature-support-5gs", "emc", "<0-255>"}, network5gsEmc)
	parser.InstallCmd([]string{"amf", "network-feature-support-5gs", "emf", "<0-255>"}, network5gsEmf)
	parser.InstallCmd([]string{"amf", "network-feature-support-5gs", "iwk-n26", "<0-255>"}, network5gsIwkN26)
	parser.InstallCmd([]string{"amf", "network-feature-support-5gs", "mpsi", "<0-255>"}, network5gsMpsi)
	parser.InstallCmd([]string{"amf", "network-feature-support-5gs", "emc-n3", "<0-255>"}, network5gsEmcN3)
	parser.InstallCmd([]string{"amf", "network-feature-support-5gs", "mcsi", "<0-255>"}, network5gsMcsi)

	parser.InstallCmd([]string{"amf", "t3502-value", "<0-4294967295>"}, t3502Value)
	parser.InstallCmd([]string{"amf", "t3512-value", "<0-4294967295>"}, t3512Value)
	parser.InstallCmd([]string{"amf", "non3gpp-deregistration-timer-value", "<0-4294967295>"}, non3gppDeregistrationTimerValue)

	parser.InstallCmd([]string{"amf", "t3513", "enable", "WORD"}, t3513Enable)
	parser.InstallCmd([]string{"amf", "t3513", "expire-time", "<0-4294967295>"}, t3513ExpireTime)
	parser.InstallCmd([]string{"amf", "t3513", "max-retry-times", "<0-4294967295>"}, t3513MaxRetryTimes)

	parser.InstallCmd([]string{"amf", "t3522", "enable", "WORD"}, t3522Enable)
	parser.InstallCmd([]string{"amf", "t3522", "expire-time", "<0-4294967295>"}, t3522ExpireTime)
	parser.InstallCmd([]string{"amf", "t3522", "max-retry-times", "<0-4294967295>"}, t3522MaxRetryTimes)

	parser.InstallCmd([]string{"amf", "t3550", "enable", "WORD"}, t3550Enable)
	parser.InstallCmd([]string{"amf", "t3550", "expire-time", "<0-4294967295>"}, t3550ExpireTime)
	parser.InstallCmd([]string{"amf", "t3550", "max-retry-times", "<0-4294967295>"}, t3550MaxRetryTimes)

	parser.InstallCmd([]string{"amf", "t3560", "enable", "WORD"}, t3560Enable)
	parser.InstallCmd([]string{"amf", "t3560", "expire-time", "<0-4294967295>"}, t3560ExpireTime)
	parser.InstallCmd([]string{"amf", "t3560", "max-retry-times", "<0-4294967295>"}, t3560MaxRetryTimes)

	parser.InstallCmd([]string{"amf", "t3565", "enable", "WORD"}, t3565Enable)
	parser.InstallCmd([]string{"amf", "t3565", "expire-time", "<0-4294967295>"}, t3565ExpireTime)
	parser.InstallCmd([]string{"amf", "t3565", "max-retry-times", "<0-4294967295>"}, t3565MaxRetryTimes)

	parser.InstallCmd([]string{"amf", "t3570", "enable", "WORD"}, t3570Enable)
	parser.InstallCmd([]string{"amf", "t3570", "expire-time", "<0-4294967295>"}, t3570ExpireTime)
	parser.InstallCmd([]string{"amf", "t3570", "max-retry-times", "<0-4294967295>"}, t3570MaxRetryTimes)

	parser.InstallCmd([]string{"amf", "logger", "amf", "debug-level", "WORD"}, loggerAmfDebugLevel)
	parser.InstallCmd([]string{"amf", "logger", "amf", "report-caller", "WORD"}, loggerAmfReportCaller)

	parser.InstallCmd([]string{"amf", "logger", "nas", "debug-level", "WORD"}, loggerNasDebugLevel)
	parser.InstallCmd([]string{"amf", "logger", "nas", "report-caller", "WORD"}, loggerNasReportCaller)

	parser.InstallCmd([]string{"amf", "logger", "fsm", "debug-level", "WORD"}, loggerFsmDebugLevel)
	parser.InstallCmd([]string{"amf", "logger", "fsm", "report-caller", "WORD"}, loggerFsmReportCaller)

	parser.InstallCmd([]string{"amf", "logger", "ngap", "debug-level", "WORD"}, loggerNgapDebugLevel)
	parser.InstallCmd([]string{"amf", "logger", "ngap", "report-caller", "WORD"}, loggerNgapReportCaller)

	parser.InstallCmd([]string{"amf", "logger", "aper", "debug-level", "WORD"}, loggerAperDebugLevel)
	parser.InstallCmd([]string{"amf", "logger", "aper", "report-caller", "WORD"}, loggerAperReportCaller)

	parser.InstallCmd([]string{"nrf-uri", "WORD"}, nrfUri)
}
