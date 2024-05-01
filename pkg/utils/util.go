package utils

import (
	"fmt"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/amf/internal/ngap"
	ngap_message "github.com/free5gc/amf/internal/ngap/message"
	ngap_service "github.com/free5gc/amf/internal/ngap/service"
	"github.com/free5gc/amf/internal/sbi/communication"
	"github.com/free5gc/amf/internal/sbi/eventexposure"
	"github.com/free5gc/amf/internal/sbi/httpcallback"
	"github.com/free5gc/amf/internal/sbi/location"
	"github.com/free5gc/amf/internal/sbi/mt"
	"github.com/free5gc/amf/internal/sbi/oam"
	"github.com/free5gc/amf/internal/sbi/producer/callback"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/amf/pkg/service"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/httpwrapper"
	logger_util "github.com/free5gc/util/logger"
)

var (
	appStart func(a *service.AmfApp)
	appStop  func(a *service.AmfApp)
)

func InitFunc(tlsKeyLogPath string) (func(a *service.AmfApp), func(a *service.AmfApp)) {
	appStart = func(a *service.AmfApp) {
		router := logger_util.NewGinWithLogrus(logger.GinLog)
		httpcallback.AddService(router)
		oam.AddService(router)
		for _, serviceName := range factory.AmfConfig.Configuration.ServiceNameList {
			switch models.ServiceName(serviceName) {
			case models.ServiceName_NAMF_COMM:
				communication.AddService(router)
			case models.ServiceName_NAMF_EVTS:
				eventexposure.AddService(router)
			case models.ServiceName_NAMF_MT:
				mt.AddService(router)
			case models.ServiceName_NAMF_LOC:
				location.AddService(router)
			}
		}

		pemPath := factory.AmfDefaultCertPemPath
		keyPath := factory.AmfDefaultPrivateKeyPath
		sbi := factory.AmfConfig.Configuration.Sbi
		if sbi.Tls != nil {
			pemPath = sbi.Tls.Pem
			keyPath = sbi.Tls.Key
		}

		self := a.Context()
		amf_context.InitAmfContext(self)

		addr := fmt.Sprintf("%s:%d", self.BindingIPv4, self.SBIPort)

		// Register to NRF
		var profile models.NfProfile
		if profileTmp, err1 := service.GetApp().Consumer().BuildNFInstance(a.Context()); err1 != nil {
			logger.InitLog.Error("Build AMF Profile Error")
		} else {
			profile = profileTmp
		}
		_, nfId, err_reg := service.GetApp().Consumer().SendRegisterNFInstance(a.Context().NrfUri, a.Context().NfId, profile)
		if err_reg != nil {
			logger.InitLog.Warnf("Send Register NF Instance failed: %+v", err_reg)
		} else {
			a.Context().NfId = nfId
		}

		// ngap
		ngapHandler := ngap_service.NGAPHandler{
			HandleMessage:         ngap.Dispatch,
			HandleNotification:    ngap.HandleSCTPNotification,
			HandleConnectionError: ngap.HandleSCTPConnError,
		}

		sctpConfig := ngap_service.NewSctpConfig(factory.AmfConfig.GetSctpConfig())
		ngap_service.Run(a.Context().NgapIpList, a.Context().NgapPort, ngapHandler, sctpConfig)

		server, err_http := httpwrapper.NewHttp2Server(addr, tlsKeyLogPath, router)

		if server == nil {
			logger.InitLog.Errorf("Initialize HTTP server failed: %+v", err_http)
			return
		}

		if err_http != nil {
			logger.InitLog.Warnf("Initialize HTTP server: %+v", err_http)
		}

		var err error

		serverScheme := factory.AmfConfig.GetSbiScheme()
		if serverScheme == "http" {
			err = server.ListenAndServe()
		} else if serverScheme == "https" {
			err = server.ListenAndServeTLS(pemPath, keyPath)
		}

		if err != nil {
			logger.InitLog.Fatalf("HTTP server setup failed: %+v", err)
		}
	}

	appStop = func(a *service.AmfApp) {
		// deregister with NRF
		problemDetails, err_deg := service.GetApp().Consumer().SendDeregisterNFInstance()
		if problemDetails != nil {
			logger.InitLog.Errorf("Deregister NF instance Failed Problem[%+v]", problemDetails)
		} else if err_deg != nil {
			logger.InitLog.Errorf("Deregister NF instance Error[%+v]", err_deg)
		} else {
			logger.InitLog.Infof("[AMF] Deregister from NRF successfully")
		}
		// TODO: forward registered UE contexts to target AMF in the same AMF set if there is one

		// ngap
		// send AMF status indication to ran to notify ran that this AMF will be unavailable
		logger.InitLog.Infof("Send AMF Status Indication to Notify RANs due to AMF terminating")
		amfSelf := a.Context()
		unavailableGuamiList := ngap_message.BuildUnavailableGUAMIList(amfSelf.ServedGuamiList)
		amfSelf.AmfRanPool.Range(func(key, value interface{}) bool {
			ran := value.(*amf_context.AmfRan)
			ngap_message.SendAMFStatusIndication(ran, unavailableGuamiList)
			return true
		})
		ngap_service.Stop()
		callback.SendAmfStatusChangeNotify((string)(models.StatusChange_UNAVAILABLE), amfSelf.ServedGuamiList)

	}
	return appStart, appStop
}
