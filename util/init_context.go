package util

import (
	"fmt"
	"os"

	"github.com/google/uuid"

	"free5gc/lib/nas/security"
	"free5gc/lib/openapi/models"
	"free5gc/src/amf/context"
	"free5gc/src/amf/factory"
	"free5gc/src/amf/logger"
)

func InitAmfContext(context *context.AMFContext) {
	config := factory.AmfConfig
	logger.UtilLog.Infof("amfconfig Info: Version[%s] Description[%s]", config.Info.Version, config.Info.Description)
	configuration := config.Configuration
	context.NfId = uuid.New().String()
	if configuration.AmfName != "" {
		context.Name = configuration.AmfName
	}
	if configuration.NgapIpList != nil {
		context.NgapIpList = configuration.NgapIpList
	} else {
		context.NgapIpList = []string{"127.0.0.1"} // default localhost
	}
	sbi := configuration.Sbi
	if sbi.Scheme != "" {
		context.UriScheme = models.UriScheme(sbi.Scheme)
	} else {
		logger.UtilLog.Warnln("SBI Scheme has not been set. Using http as default")
		context.UriScheme = "http"
	}
	context.RegisterIPv4 = "127.0.0.1" // default localhost
	context.SBIPort = 29518            // default port
	if sbi != nil {
		if sbi.RegisterIPv4 != "" {
			context.RegisterIPv4 = sbi.RegisterIPv4
		}
		if sbi.Port != 0 {
			context.SBIPort = sbi.Port
		}
		context.BindingIPv4 = os.Getenv(sbi.BindingIPv4)
		if context.BindingIPv4 != "" {
			logger.UtilLog.Info("Parsing ServerIPv4 address from ENV Variable.")
		} else {
			context.BindingIPv4 = sbi.BindingIPv4
			if context.BindingIPv4 == "" {
				logger.UtilLog.Warn("Error parsing ServerIPv4 address from string. Using the 0.0.0.0 as default.")
				context.BindingIPv4 = "0.0.0.0"
			}
		}
	}
	serviceNameList := configuration.ServiceNameList
	context.InitNFService(serviceNameList, config.Info.Version)
	context.ServedGuamiList = configuration.ServedGumaiList
	context.SupportTaiLists = configuration.SupportTAIList
	for i := range context.SupportTaiLists {
		context.SupportTaiLists[i].Tac = TACConfigToModels(context.SupportTaiLists[i].Tac)
	}
	context.PlmnSupportList = configuration.PlmnSupportList
	context.SupportDnnLists = configuration.SupportDnnList
	if configuration.NrfUri != "" {
		context.NrfUri = configuration.NrfUri
	} else {
		logger.UtilLog.Warn("NRF Uri is empty! Using localhost as NRF IPv4 address.")
		context.NrfUri = fmt.Sprintf("%s://%s:%d", context.UriScheme, "127.0.0.1", 29510)
	}
	security := configuration.Security
	if security != nil {
		context.SecurityAlgorithm.IntegrityOrder = getIntAlgOrder(security.IntegrityOrder)
		context.SecurityAlgorithm.CipheringOrder = getEncAlgOrder(security.CipheringOrder)
	}
	context.NetworkName = configuration.NetworkName
	context.T3502Value = configuration.T3502
	context.T3512Value = configuration.T3512
	context.Non3gppDeregistrationTimerValue = configuration.Non3gppDeregistrationTimer
}

func getIntAlgOrder(integrityOrder []string) (intOrder []uint8) {
	for _, intAlg := range integrityOrder {
		switch intAlg {
		case "NIA0":
			intOrder = append(intOrder, security.AlgIntegrity128NIA0)
		case "NIA1":
			intOrder = append(intOrder, security.AlgIntegrity128NIA1)
		case "NIA2":
			intOrder = append(intOrder, security.AlgIntegrity128NIA2)
		case "NIA3":
			intOrder = append(intOrder, security.AlgIntegrity128NIA3)
		default:
			logger.UtilLog.Errorf("Unsupported algorithm: %s", intAlg)
		}
	}
	return
}
func getEncAlgOrder(cipheringOrder []string) (encOrder []uint8) {
	for _, encAlg := range cipheringOrder {
		switch encAlg {
		case "NEA0":
			encOrder = append(encOrder, security.AlgCiphering128NEA0)
		case "NEA1":
			encOrder = append(encOrder, security.AlgCiphering128NEA1)
		case "NEA2":
			encOrder = append(encOrder, security.AlgCiphering128NEA2)
		case "NEA3":
			encOrder = append(encOrder, security.AlgCiphering128NEA3)
		default:
			logger.UtilLog.Errorf("Unsupported algorithm: %s", encAlg)
		}
	}
	return
}
