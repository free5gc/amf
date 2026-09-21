package consumer

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/amf/internal/util"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	Nnrf_NFDiscovery "github.com/free5gc/openapi/nrf/NFDisc"
	Nnrf_NFManagement "github.com/free5gc/openapi/nrf/NFMgmt"
	sbi_metrics "github.com/free5gc/util/metrics/sbi"
	"github.com/free5gc/util/nfheartbeat"
)

// registerRetryInterval is the wait between two NFRegister attempts while the NRF
// is unreachable.
const registerRetryInterval = 2 * time.Second

type nnrfService struct {
	consumer *Consumer

	nfMngmntMu sync.RWMutex
	nfDiscMu   sync.RWMutex

	nfMngmntClients map[string]*Nnrf_NFManagement.APIClient
	nfDiscClients   map[string]*Nnrf_NFDiscovery.APIClient

	heartbeat *nfheartbeat.Runner

	// heartbeatTimer is the interval in seconds last assigned in a registration
	// response; PATCH-adopted values live in the Runner. Set by the startup
	// registration before the heartbeat goroutine starts, then only rewritten
	// from re-registrations on that same goroutine.
	heartbeatTimer int32
}

func (s *nnrfService) getNFManagementClient(uri string) *Nnrf_NFManagement.APIClient {
	if uri == "" {
		return nil
	}
	s.nfMngmntMu.RLock()
	client, ok := s.nfMngmntClients[uri]
	if ok {
		s.nfMngmntMu.RUnlock()
		return client
	}

	configuration := Nnrf_NFManagement.NewConfiguration()
	configuration.SetBasePath(uri)
	configuration.SetMetrics(sbi_metrics.SbiMetricHook)
	client = Nnrf_NFManagement.NewAPIClient(configuration)

	s.nfMngmntMu.RUnlock()
	s.nfMngmntMu.Lock()
	defer s.nfMngmntMu.Unlock()
	s.nfMngmntClients[uri] = client
	return client
}

func (s *nnrfService) getNFDiscClient(uri string) *Nnrf_NFDiscovery.APIClient {
	if uri == "" {
		return nil
	}
	s.nfDiscMu.RLock()
	client, ok := s.nfDiscClients[uri]
	if ok {
		s.nfDiscMu.RUnlock()
		return client
	}

	configuration := Nnrf_NFDiscovery.NewConfiguration()
	configuration.SetBasePath(uri)
	configuration.SetMetrics(sbi_metrics.SbiMetricHook)
	client = Nnrf_NFDiscovery.NewAPIClient(configuration)

	s.nfDiscMu.RUnlock()
	s.nfDiscMu.Lock()
	defer s.nfDiscMu.Unlock()
	s.nfDiscClients[uri] = client
	return client
}

func (s *nnrfService) SendSearchNFInstances(nrfUri string, targetNfType, requestNfType models.Nrf_NFMgmt_NFType,
	param *Nnrf_NFDiscovery.SearchNFInstancesRequest,
) (*models.Nrf_NFDisc_SearchResult, error) {
	// Set client and set url
	param.TargetNfType = &targetNfType
	param.RequesterNfType = &requestNfType
	client := s.getNFDiscClient(nrfUri)
	if client == nil {
		return nil, openapi.ReportError("nrf not found")
	}

	ctx, _, err := amf_context.GetSelf().GetTokenCtx(models.Nrf_NFMgmt_ServiceName_NNRF_DISC, models.Nrf_NFMgmt_NFType_NRF)
	if err != nil {
		return nil, err
	}
	res, err := client.NFInstancesStoreApi.SearchNFInstances(ctx, param)
	var result *models.Nrf_NFDisc_SearchResult
	if err != nil {
		logger.ConsumerLog.Errorf("SearchNFInstances failed: %+v", err)
	}
	if res != nil {
		result = res.Nrf_NFDisc_SearchResult
	}
	return result, err
}

func (s *nnrfService) SearchUdmSdmInstance(
	ue *amf_context.AmfUe, nrfUri string, targetNfType, requestNfType models.Nrf_NFMgmt_NFType,
	param *Nnrf_NFDiscovery.SearchNFInstancesRequest,
) error {
	resp, localErr := s.SendSearchNFInstances(nrfUri, targetNfType, requestNfType, param)
	if localErr != nil {
		return localErr
	}

	// select the first UDM_SDM, TODO: select base on other info
	var sdmUri string
	for index := range resp.NfInstances {
		ue.UdmId = resp.NfInstances[index].NfInstanceId
		sdmUri = util.SearchNFServiceUri(&resp.NfInstances[index], models.Nrf_NFMgmt_ServiceName_NUDM_SDM,
			models.Nrf_NFMgmt_NFServiceStatus_REGISTERED)
		if sdmUri != "" {
			break
		}
	}
	ue.NudmSDMUri = sdmUri
	if ue.NudmSDMUri == "" {
		err := fmt.Errorf("AMF can not select an UDM by NRF")
		logger.ConsumerLog.Error(err)
		return err
	}
	return nil
}

func (s *nnrfService) SearchNssfNSSelectionInstance(
	ue *amf_context.AmfUe, nrfUri string, targetNfType, requestNfType models.Nrf_NFMgmt_NFType,
	param *Nnrf_NFDiscovery.SearchNFInstancesRequest,
) error {
	resp, localErr := s.SendSearchNFInstances(nrfUri, targetNfType, requestNfType, param)
	if localErr != nil {
		return localErr
	}

	// select the first NSSF, TODO: select base on other info
	var nssfUri string
	for index := range resp.NfInstances {
		ue.NssfId = resp.NfInstances[index].NfInstanceId
		nssfUri = util.SearchNFServiceUri(&resp.NfInstances[index], models.Nrf_NFMgmt_ServiceName_NNSSF_NSSELECTION,
			models.Nrf_NFMgmt_NFServiceStatus_REGISTERED)
		if nssfUri != "" {
			break
		}
	}
	ue.NssfUri = nssfUri
	if ue.NssfUri == "" {
		return fmt.Errorf("AMF can not select an NSSF by NRF")
	}
	return nil
}

func (s *nnrfService) SearchAmfCommunicationInstance(ue *amf_context.AmfUe, nrfUri string, targetNfType,
	requestNfType models.Nrf_NFMgmt_NFType, param *Nnrf_NFDiscovery.SearchNFInstancesRequest,
) (err error) {
	resp, localErr := s.SendSearchNFInstances(nrfUri, targetNfType, requestNfType, param)
	if localErr != nil {
		err = localErr
		return
	}

	// select the first AMF, TODO: select base on other info
	var amfUri string
	for index := range resp.NfInstances {
		if resp.NfInstances[index].NfInstanceId == amf_context.GetSelf().NfId {
			continue
		}
		ue.TargetAmfProfile = &resp.NfInstances[index]
		amfUri = util.SearchNFServiceUri(&resp.NfInstances[index], models.Nrf_NFMgmt_ServiceName_NAMF_COMM,
			models.Nrf_NFMgmt_NFServiceStatus_REGISTERED)
		if amfUri != "" {
			break
		}
	}
	ue.TargetAmfUri = amfUri
	if ue.TargetAmfUri == "" {
		err = fmt.Errorf("AMF can not select an target AMF by NRF")
	}
	return
}

func (s *nnrfService) buildNFInstance(context *amf_context.AMFContext) (
	profile models.Nrf_NFMgmt_NFProfile, err error,
) {
	profile.NfInstanceId = context.NfId
	profile.NfType = models.Nrf_NFMgmt_NFType_AMF
	profile.NfStatus = models.Nrf_NFMgmt_NFStatus_REGISTERED
	var plmns []models.PlmnId
	for _, plmnItem := range context.PlmnSupportList {
		plmns = append(plmns, *plmnItem.PlmnId)
	}
	if len(plmns) > 0 {
		profile.PlmnList = plmns
		// TODO: change to Per Plmn Support Snssai List
		var SnssaiList []models.ExtSnssai
		for _, snssaiItem := range context.PlmnSupportList[0].SNssaiList {
			SnssaiList = append(SnssaiList, util.SnssaiModelsToExtSnssai(snssaiItem))
		}
		profile.SNssais = SnssaiList
	}
	amfInfo := models.Nrf_NFMgmt_AmfInfo{}
	if len(context.ServedGuamiList) == 0 {
		err = fmt.Errorf("gumai List is Empty in AMF")
		return profile, err
	}
	regionId, setId, _, err1 := util.SeperateAmfId(context.ServedGuamiList[0].AmfId)
	if err1 != nil {
		err = err1
		return profile, err
	}
	amfInfo.AmfRegionId = regionId
	amfInfo.AmfSetId = setId
	amfInfo.GuamiList = context.ServedGuamiList
	if len(context.SupportTaiLists) == 0 {
		err = fmt.Errorf("SupportTaiList is Empty in AMF")
		return profile, err
	}
	amfInfo.TaiList = context.SupportTaiLists
	profile.AmfInfo = &amfInfo
	if context.RegisterIPv4 == "" {
		err = fmt.Errorf("AMF Address is empty")
		return profile, err
	}
	profile.Ipv4Addresses = append(profile.Ipv4Addresses, context.RegisterIPv4)
	service := []models.Nrf_NFMgmt_NFService{}
	for _, nfService := range context.NfService {
		service = append(service, nfService)
	}
	if len(service) > 0 {
		profile.NfServices = service
	}

	defaultNotificationSubscription := models.Nrf_NFMgmt_DefaultNotificationSubscription{
		CallbackUri:      fmt.Sprintf("%s"+factory.AmfCallbackResUriPrefix+"/n1-message-notify", context.GetIPv4Uri()),
		NotificationType: models.Nrf_NFMgmt_NotificationType_N1_MESSAGES,
		N1MessageClass:   models.Amf_Comm_N1MessageClass_5_GMM,
	}
	profile.DefaultNotificationSubscriptions = append(profile.DefaultNotificationSubscriptions,
		defaultNotificationSubscription)
	return profile, err
}

// SendRegisterNFInstance registers the NF profile with the NRF, retrying until it
// succeeds or ctx is canceled. applyOAuth2 must be true only for the startup
// registration: it writes OAuth2Required, which SBI handlers read concurrently
// once the server is running.
//
// The profile is rebuilt on every attempt so a re-registration carries the
// current GUAMI and TAI lists. It keeps amfContext.NfId: NFRegister is a PUT on
// the instance ID the AMF chose, per 3GPP TS 29.510 clause 6.1.3.2.2.
func (s *nnrfService) SendRegisterNFInstance(ctx context.Context, applyOAuth2 bool) error {
	amfContext := s.consumer.Context()
	client := s.getNFManagementClient(amfContext.NrfUri)
	if client == nil {
		return openapi.ReportError("nrf not found")
	}

	profile, err := s.buildNFInstance(amfContext)
	if err != nil {
		return fmt.Errorf("SendRegisterNFInstance buildNFInstance(): %w", err)
	}

	var res *Nnrf_NFManagement.RegisterNFInstanceResponse
	registerNFInstanceRequest := &Nnrf_NFManagement.RegisterNFInstanceRequest{
		NfInstanceID: &amfContext.NfId,
		RequestBody:  &profile,
	}
	for ctx.Err() == nil {
		res, err = client.NFInstanceIDDocumentApi.RegisterNFInstance(ctx, registerNFInstanceRequest)
		if err == nil && res != nil {
			s.processRegisterResponse(amfContext, res.Nrf_NFMgmt_NFProfile, applyOAuth2)
			return nil
		}
		logger.ConsumerLog.Errorf("AMF register to NRF Error[%v]", err)
		select {
		case <-ctx.Done():
		case <-time.After(registerRetryInterval):
		}
	}
	return fmt.Errorf("context done before SendRegisterNFInstance")
}

// processRegisterResponse adopts what the NRF answered to the NFRegister PUT: the
// heartbeat interval and the oauth2 custom info. A nil profile is a legal answer.
func (s *nnrfService) processRegisterResponse(
	amfContext *amf_context.AMFContext,
	nf *models.Nrf_NFMgmt_NFProfile,
	applyOAuth2 bool,
) {
	if nf == nil {
		nf = &models.Nrf_NFMgmt_NFProfile{}
	}
	s.heartbeatTimer = nf.HeartBeatTimer

	oauth2 := false
	if customInfo, ok := nf.CustomInfo.(map[string]interface{}); ok {
		if v, isBool := customInfo["oauth2"].(bool); isBool {
			oauth2 = v
			logger.MainLog.Infoln("OAuth2 setting receive from NRF:", oauth2)
		}
	}
	if applyOAuth2 {
		amfContext.OAuth2Required = oauth2
		if oauth2 && amfContext.NrfCertPem == "" {
			logger.CfgLog.Error("OAuth2 enable but no nrfCertPem provided in config.")
		}
	} else if oauth2 != amfContext.OAuth2Required {
		logger.ConsumerLog.Warnf("NRF OAuth2 setting changed to %v, restart AMF to apply it", oauth2)
	}
}

// SendUpdateNFInstance sends an NFUpdate PATCH to the NRF, honoring ctx. The
// raw err comes back alongside any ProblemDetails so callers can read its
// GenericOpenAPIError status.
func (s *nnrfService) SendUpdateNFInstance(ctx context.Context, patchItem []models.PatchItem) (
	nf models.Nrf_NFMgmt_NFProfile, problemDetails *models.ProblemDetails, err error,
) {
	amfContext := s.consumer.Context()
	tokCtx, pd, err := amfContext.GetTokenCtx(
		models.Nrf_NFMgmt_ServiceName_NNRF_NFM,
		models.Nrf_NFMgmt_NFType_NRF,
	)
	if err != nil {
		return nf, pd, err
	}
	// GetTokenCtx takes no parent, so the token request stays uncancellable;
	// transplanting the token lets at least the PATCH honor ctx.
	if tok := tokCtx.Value(openapi.ContextOAuth2); tok != nil {
		ctx = context.WithValue(ctx, openapi.ContextOAuth2, tok)
	}

	client := s.getNFManagementClient(amfContext.NrfUri)
	if client == nil {
		return nf, nil, openapi.ReportError("nrf not found")
	}

	request := &Nnrf_NFManagement.UpdateNFInstanceRequest{
		NfInstanceID: &amfContext.NfId,
		RequestBody:  patchItem,
	}

	res, err := client.NFInstanceIDDocumentApi.UpdateNFInstance(ctx, request)
	if err != nil {
		var apiErr openapi.GenericOpenAPIError
		if errors.As(err, &apiErr) {
			if updateErr, okModel := apiErr.Model().(Nnrf_NFManagement.UpdateNFInstanceError); okModel {
				return nf, updateErr.ProblemDetails, err
			}
		}
		return nf, nil, err
	}
	if res == nil {
		return nf, nil, openapi.ReportError("empty NFUpdate response")
	}
	if res.Nrf_NFMgmt_NFProfile != nil {
		nf = *res.Nrf_NFMgmt_NFProfile
	}
	return nf, nil, nil
}

func (s *nnrfService) SendDeregisterNFInstance() (problemDetails *models.ProblemDetails, err error) {
	logger.ConsumerLog.Infof("[AMF] Send Deregister NFInstance")
	amfContext := s.consumer.Context()

	client := s.getNFManagementClient(amfContext.NrfUri)
	if client == nil {
		return nil, openapi.ReportError("nrf not found")
	}

	ctx, pd, err := amf_context.GetSelf().GetTokenCtx(models.Nrf_NFMgmt_ServiceName_NNRF_NFM, models.Nrf_NFMgmt_NFType_NRF)
	if err != nil {
		return pd, err
	}

	request := &Nnrf_NFManagement.DeregisterNFInstanceRequest{
		NfInstanceID: &amfContext.NfId,
	}

	_, err = client.NFInstanceIDDocumentApi.DeregisterNFInstance(ctx, request)
	if err != nil {
		switch apiErr := err.(type) {
		// API error
		case openapi.GenericOpenAPIError:
			switch errModel := apiErr.Model().(type) {
			case Nnrf_NFManagement.DeregisterNFInstanceError:
				problemDetails = errModel.ProblemDetails
			case error:
				problemDetails = openapi.ProblemDetailsSystemFailure(errModel.Error())
			default:
				err = openapi.ReportError("openapi error")
			}
		case error:
			problemDetails = openapi.ProblemDetailsSystemFailure(apiErr.Error())
		default:
			err = openapi.ReportError("server no response")
		}
	}

	return problemDetails, err
}
