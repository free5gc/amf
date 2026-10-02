package consumer

import (
	"fmt"
	"sync"
	"time"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	Nnrf_NFDiscovery "github.com/free5gc/openapi/nrf/NFDisc"
	Nnssf_NSSelection "github.com/free5gc/openapi/nssf/NSSel"
	sbi_metrics "github.com/free5gc/util/metrics/sbi"
)

const (
	// nssfSelectionTimeout is the retry budget for NSSF discovery, so a missing NSSF
	// cannot block the UE handler forever. One in-flight request may still exceed it.
	nssfSelectionTimeout = 5 * time.Second
	// nssfSelectionRetryInterval is the wait between two NSSF discovery attempts.
	nssfSelectionRetryInterval = 2 * time.Second
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
	configuration.SetMetrics(sbi_metrics.SbiMetricHook)
	client = Nnssf_NSSelection.NewAPIClient(configuration)

	s.NSSelectionMu.RUnlock()
	s.NSSelectionMu.Lock()
	defer s.NSSelectionMu.Unlock()
	s.NSSelectionClients[uri] = client
	return client
}

func (s *nssfService) NSSelectionGetForRegistration(
	ue *amf_context.AmfUe,
	requestedNssai []models.Nssf_NSSel_MappingOfSnssai,
) (
	*models.ProblemDetails, error,
) {
	client := s.getNSSelectionClient(ue.NssfUri)
	if client == nil {
		return nil, openapi.ReportError("nssf not found")
	}

	amfSelf := amf_context.GetSelf()
	ctx, _, err := amf_context.GetSelf().GetTokenCtx(models.Nrf_NFMgmt_ServiceName_NNSSF_NSSELECTION,
		models.Nrf_NFMgmt_NFType_NSSF)
	if err != nil {
		return nil, err
	}
	sliceInfo := models.Nssf_NSSel_SliceInfoForRegistration{
		SubscribedNssai: ue.SubscribedNssai,
	}

	for _, snssai := range requestedNssai {
		sliceInfo.RequestedNssai = append(sliceInfo.RequestedNssai, *snssai.ServingSnssai)
		if snssai.HomeSnssai != nil {
			sliceInfo.MappingOfNssai = append(sliceInfo.MappingOfNssai, snssai)
		}
	}

	var paramOpt Nnssf_NSSelection.NSSelectionGetRequest

	testNfType := models.Nrf_NFMgmt_NFType_AMF

	paramOpt = Nnssf_NSSelection.NSSelectionGetRequest{
		NfType:                          &testNfType,
		NfId:                            &amfSelf.NfId,
		SliceInfoRequestForRegistration: &sliceInfo,
		Tai:                             &ue.Tai, // TS 29.531 R15.3 6.1.3.2.3.1
	}

	res, localErr := client.NetworkSliceInformationDocumentApi.NSSelectionGet(ctx,
		&paramOpt)
	if localErr == nil {
		ue.NetworkSliceInfo = res.Nssf_NSSel_AuthorizedNetworkSliceInfo
		for _, allowedNssai := range res.Nssf_NSSel_AuthorizedNetworkSliceInfo.AllowedNssaiList {
			ue.AllowedNssai[allowedNssai.AccessType] = allowedNssai.AllowedSnssaiList
		}
		ue.ConfiguredNssai = res.Nssf_NSSel_AuthorizedNetworkSliceInfo.ConfiguredNssai
	} else {
		switch apiErr := localErr.(type) {
		// API error
		case openapi.GenericOpenAPIError:
			switch errModel := apiErr.Model().(type) {
			case Nnssf_NSSelection.NSSelectionGetError:
				return errModel.ProblemDetails, localErr
			case error:
				return openapi.ProblemDetailsSystemFailure(errModel.Error()), nil
			default:
				return nil, openapi.ReportError("openapi error")
			}
		case error:
			return openapi.ProblemDetailsSystemFailure(apiErr.Error()), nil
		default:
			return nil, openapi.ReportError("openapi error")
		}
	}

	return nil, nil
}

func (s *nssfService) NSSelectionGetForPduSession(ue *amf_context.AmfUe, snssai models.Snssai) (
	*models.Nssf_NSSel_AuthorizedNetworkSliceInfo, *models.ProblemDetails, error,
) {
	client := s.getNSSelectionClient(ue.NssfUri)
	if client == nil {
		return nil, nil, openapi.ReportError("nssf not found")
	}

	amfSelf := amf_context.GetSelf()
	sliceInfoForPduSession := models.Nssf_NSSel_SliceInfoForPDUSession{
		SNssai:            &snssai,
		RoamingIndication: models.Nssf_NSSel_RoamingIndication_NON_ROAMING, // not support roaming
	}

	testNfType := models.Nrf_NFMgmt_NFType_AMF

	paramOpt := Nnssf_NSSelection.NSSelectionGetRequest{
		NfType:                        &testNfType,
		NfId:                          &amfSelf.NfId,
		SliceInfoRequestForPduSession: &sliceInfoForPduSession,
		Tai:                           &ue.Tai, // TS 29.531 R15.3 6.1.3.2.3.1
	}

	ctx, _, err := amf_context.GetSelf().GetTokenCtx(models.Nrf_NFMgmt_ServiceName_NNSSF_NSSELECTION,
		models.Nrf_NFMgmt_NFType_NSSF)
	if err != nil {
		return nil, nil, err
	}
	res, localErr := client.NetworkSliceInformationDocumentApi.NSSelectionGet(ctx, &paramOpt)

	if localErr == nil {
		return res.Nssf_NSSel_AuthorizedNetworkSliceInfo, nil, nil
	} else {
		switch apiErr := localErr.(type) {
		// API error
		case openapi.GenericOpenAPIError:
			switch errModel := apiErr.Model().(type) {
			case Nnssf_NSSelection.NSSelectionGetError:
				return nil, errModel.ProblemDetails, localErr
			case error:
				return nil, openapi.ProblemDetailsSystemFailure(errModel.Error()), nil
			default:
				return nil, nil, openapi.ReportError("openapi error")
			}
		case error:
			return nil, openapi.ProblemDetailsSystemFailure(apiErr.Error()), nil
		default:
			return nil, nil, openapi.ReportError("server no response")
		}
	}
}

// SelectNssfWithTimeout discovers an NSSF via NRF and stores it in ue.NssfUri,
// retrying until nssfSelectionTimeout elapses.
func (s *nssfService) SelectNssfWithTimeout(ue *amf_context.AmfUe, nrfUri string) error {
	return retryWithTimeout(nssfSelectionTimeout, nssfSelectionRetryInterval, func() error {
		searchReq := Nnrf_NFDiscovery.SearchNFInstancesRequest{}
		err := s.consumer.SearchNssfNSSelectionInstance(ue, nrfUri, models.Nrf_NFMgmt_NFType_NSSF,
			models.Nrf_NFMgmt_NFType_AMF, &searchReq)
		if err != nil {
			ue.GmmLog.Errorf("AMF can not select an NSSF Instance by NRF[Error: %+v]", err)
		}
		return err
	})
}

// retryWithTimeout calls fn until it succeeds, sleeping interval between attempts.
// It gives up once another sleep would pass timeout, returning the last error wrapped.
func retryWithTimeout(timeout, interval time.Duration, fn func() error) error {
	deadline := time.Now().Add(timeout)
	for {
		err := fn()
		if err == nil {
			return nil
		}
		if time.Now().Add(interval).After(deadline) {
			return fmt.Errorf("NSSF selection timeout after %v: %w", timeout, err)
		}
		time.Sleep(interval)
	}
}
