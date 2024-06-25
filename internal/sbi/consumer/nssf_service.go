package consumer

import (
	"encoding/json"
	"sync"

	"github.com/antihax/optional"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/Nnssf_NSSelection"
	"github.com/free5gc/openapi/models"
)

type nssfService struct {
	consumer *Consumer

	NSSelectionMu sync.RWMutex

	NSSelectionClients map[string]*Nnssf_NSSelection.APIClient
}

func (s *nssfService) getNSSelectionClient(uri string) *Nnssf_NSSelection.APIClient {
	if uri == "" {
		return nil
	}
	s.NSSelectionMu.RLock()
	client, ok := s.NSSelectionClients[uri]
	if ok {
		s.NSSelectionMu.RUnlock()
		return client
	}

	configuration := Nnssf_NSSelection.NewConfiguration()
	configuration.SetBasePath(uri)
	client = Nnssf_NSSelection.NewAPIClient(configuration)

	s.NSSelectionMu.RUnlock()
	s.NSSelectionMu.Lock()
	defer s.NSSelectionMu.Unlock()
	s.NSSelectionClients[uri] = client
	return client
}

func (s *nssfService) NSSelectionGetForRegistration(ue *amf_context.AmfUe, requestedNssai []models.MappingOfSnssai) (
	*models.ProblemDetails, error,
) {
	client := s.getNSSelectionClient(ue.NssfUri)
	if client == nil {
		return nil, openapi.ReportError("nssf not found")
	}

	amfSelf := amf_context.GetSelf()
	ctx, _, err := amf_context.GetSelf().GetTokenCtx(models.ServiceName_NNSSF_NSSELECTION, models.NfType_NSSF)
	if err != nil {
		return nil, err
	}
	sliceInfo := models.SliceInfoForRegistration{
		SubscribedNssai: ue.SubscribedNssai,
	}

	for _, snssai := range requestedNssai {
		sliceInfo.RequestedNssai = append(sliceInfo.RequestedNssai, *snssai.ServingSnssai)
		if snssai.HomeSnssai != nil {
			sliceInfo.MappingOfNssai = append(sliceInfo.MappingOfNssai, snssai)
		}
	}

	var paramOpt Nnssf_NSSelection.NSSelectionGetParamOpts
	if e, errsliceinfo := json.Marshal(sliceInfo); errsliceinfo != nil {
		logger.ConsumerLog.Warnf("slice json marshal failed: %+v", errsliceinfo)
	} else {
		tai, taierr := json.Marshal(ue.Tai)
		if taierr != nil {
			logger.ConsumerLog.Warnf("tai json marshal failed: %+v", taierr)
		}
		paramOpt = Nnssf_NSSelection.NSSelectionGetParamOpts{
			SliceInfoRequestForRegistration: optional.NewInterface(string(e)),
			Tai:                             optional.NewInterface(string(tai)), // TS 29.531 R15.3 6.1.3.2.3.1
		}
	}

	res, httpResp, localErr := client.NetworkSliceInformationDocumentApi.NSSelectionGet(ctx,
		models.NfType_AMF, amfSelf.NfId, &paramOpt)
	defer func() {
		if httpResp != nil {
			if rspCloseErr := httpResp.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("NSSelectionGet response body cannot close: %+v",
					rspCloseErr)
			}
		}
	}()
	if localErr == nil {
		ue.NetworkSliceInfo = &res
		for _, allowedNssai := range res.AllowedNssaiList {
			ue.AllowedNssai[allowedNssai.AccessType] = allowedNssai.AllowedSnssaiList
		}
		ue.ConfiguredNssai = res.ConfiguredNssai
	} else if httpResp != nil {
		if httpResp.Status != localErr.Error() {
			errlocal := localErr
			return nil, errlocal
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		return &problem, nil
	} else {
		return nil, openapi.ReportError("NSSF No Response")
	}

	return nil, nil
}

func (s *nssfService) NSSelectionGetForPduSession(ue *amf_context.AmfUe, snssai models.Snssai) (
	*models.AuthorizedNetworkSliceInfo, *models.ProblemDetails, error,
) {
	client := s.getNSSelectionClient(ue.NssfUri)
	if client == nil {
		return nil, nil, openapi.ReportError("nssf not found")
	}

	amfSelf := amf_context.GetSelf()
	sliceInfoForPduSession := models.SliceInfoForPduSession{
		SNssai:            &snssai,
		RoamingIndication: models.RoamingIndication_NON_ROAMING, // not support roaming
	}

	e, err := json.Marshal(sliceInfoForPduSession)
	if err != nil {
		logger.ConsumerLog.Warnf("slice json marshal failed: %+v", err)
	}
	tai, taierr := json.Marshal(ue.Tai)
	if taierr != nil {
		logger.ConsumerLog.Warnf("tai json marshal failed: %+v", taierr)
	}
	paramOpt := Nnssf_NSSelection.NSSelectionGetParamOpts{
		SliceInfoRequestForPduSession: optional.NewInterface(string(e)),
		Tai:                           optional.NewInterface(string(tai)), // TS 29.531 R15.3 6.1.3.2.3.1
	}

	ctx, _, err := amf_context.GetSelf().GetTokenCtx(models.ServiceName_NNSSF_NSSELECTION, models.NfType_NSSF)
	if err != nil {
		return nil, nil, err
	}
	res, httpResp, localErr := client.NetworkSliceInformationDocumentApi.NSSelectionGet(ctx,
		models.NfType_AMF, amfSelf.NfId, &paramOpt)
	defer func() {
		if httpResp != nil {
			if rspCloseErr := httpResp.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("NSSelectionGet response body cannot close: %+v",
					rspCloseErr)
			}
		}
	}()
	if localErr == nil {
		return &res, nil, nil
	} else if httpResp != nil {
		if httpResp.Status != localErr.Error() {
			return nil, nil, localErr
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		return nil, &problem, nil
	} else {
		return nil, nil, openapi.ReportError("NSSF No Response")
	}
}
