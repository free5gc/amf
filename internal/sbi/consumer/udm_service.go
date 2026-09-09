package consumer

import (
	"fmt"
	"sync"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	Nudm_SubscriberDataManagement "github.com/free5gc/openapi/udm/SDM"
	Nudm_UEContextManagement "github.com/free5gc/openapi/udm/UECM"
	sbi_metrics "github.com/free5gc/util/metrics/sbi"
)

type nudmService struct {
	consumer *Consumer

	SubscriberDMngmntMu sync.RWMutex
	UEContextMngmntMu   sync.RWMutex

	SubscriberDMngmntClients map[string]*Nudm_SubscriberDataManagement.APIClient
	UEContextMngmntClients   map[string]*Nudm_UEContextManagement.APIClient
}

func (s *nudmService) getSubscriberDMngmntClients(uri string) *Nudm_SubscriberDataManagement.APIClient {
	if uri == "" {
		return nil
	}
	s.SubscriberDMngmntMu.RLock()
	client, ok := s.SubscriberDMngmntClients[uri]
	if ok {
		s.SubscriberDMngmntMu.RUnlock()
		return client
	}

	configuration := Nudm_SubscriberDataManagement.NewConfiguration()
	configuration.SetBasePath(uri)
	configuration.SetMetrics(sbi_metrics.SbiMetricHook)
	client = Nudm_SubscriberDataManagement.NewAPIClient(configuration)

	s.SubscriberDMngmntMu.RUnlock()
	s.SubscriberDMngmntMu.Lock()
	defer s.SubscriberDMngmntMu.Unlock()
	s.SubscriberDMngmntClients[uri] = client
	return client
}

func (s *nudmService) getUEContextMngmntClient(uri string) *Nudm_UEContextManagement.APIClient {
	if uri == "" {
		return nil
	}
	s.UEContextMngmntMu.RLock()
	client, ok := s.UEContextMngmntClients[uri]
	if ok {
		s.UEContextMngmntMu.RUnlock()
		return client
	}

	configuration := Nudm_UEContextManagement.NewConfiguration()
	configuration.SetBasePath(uri)
	client = Nudm_UEContextManagement.NewAPIClient(configuration)

	s.UEContextMngmntMu.RUnlock()
	s.UEContextMngmntMu.Lock()
	defer s.UEContextMngmntMu.Unlock()
	s.UEContextMngmntClients[uri] = client
	return client
}

func (s *nudmService) PutUpuAck(ue *amf_context.AmfUe, upuMacIue string) error {
	client := s.getSubscriberDMngmntClients(ue.NudmSDMUri)
	if client == nil {
		return openapi.ReportError("udm not found")
	}

	ctx, _, err := amf_context.GetSelf().GetTokenCtxForNFInstance(
		models.Nrf_NFMgmt_ServiceName_NUDM_SDM, models.Nrf_NFMgmt_NFType_UDM, ue.UdmId)
	if err != nil {
		return err
	}

	ackInfo := models.Udm_SDM_AcknowledgeInfo{
		UpuMacIue: upuMacIue,
	}
	upuReq := Nudm_SubscriberDataManagement.UpuAckRequest{
		Supi:        &ue.Supi,
		RequestBody: &ackInfo,
	}
	_, err = client.ProvidingAcknowledgementOfUEParametersUpdateApi.
		UpuAck(ctx, &upuReq)

	return err
}

func (s *nudmService) SDMGetAmData(ue *amf_context.AmfUe) (problemDetails *models.ProblemDetails, err error) {
	client := s.getSubscriberDMngmntClients(ue.NudmSDMUri)
	if client == nil {
		return nil, openapi.ReportError("udm not found")
	}

	getAmDataParamReq := Nudm_SubscriberDataManagement.GetAmDataRequest{
		Supi: &ue.Supi,
		PlmnId: &models.PlmnIdNid{
			Mnc: ue.PlmnId.Mnc,
			Mcc: ue.PlmnId.Mcc,
		},
	}

	ctx, _, err := amf_context.GetSelf().GetTokenCtxForNFInstance(
		models.Nrf_NFMgmt_ServiceName_NUDM_SDM, models.Nrf_NFMgmt_NFType_UDM, ue.UdmId)
	if err != nil {
		return nil, err
	}

	data, localErr := client.AccessAndMobilitySubscriptionDataRetrievalApi.GetAmData(
		ctx, &getAmDataParamReq)
	if localErr == nil {
		ue.AccessAndMobilitySubscriptionData = data.Udm_SDM_AccessAndMobilitySubscriptionData
		if len(data.Udm_SDM_AccessAndMobilitySubscriptionData.Gpsis) > 0 {
			ue.Gpsi = data.Udm_SDM_AccessAndMobilitySubscriptionData.Gpsis[0] // TODO: select GPSI
		}
	} else {
		err = localErr
		switch apiErr := localErr.(type) {
		// API error
		case openapi.GenericOpenAPIError:
			switch errorModel := apiErr.Model().(type) {
			case Nudm_SubscriberDataManagement.GetAmDataError:
				problemDetails = errorModel.ProblemDetails
			case error:
				problemDetails = openapi.ProblemDetailsSystemFailure(errorModel.Error())
			default:
				err = openapi.ReportError("openapi error")
			}
		case error:
			problemDetails = openapi.ProblemDetailsSystemFailure(apiErr.Error())
		default:
			err = openapi.ReportError("openapi error")
		}
	}
	return problemDetails, err
}

func (s *nudmService) SDMGetSmfSelectData(ue *amf_context.AmfUe) (problemDetails *models.ProblemDetails, err error) {
	client := s.getSubscriberDMngmntClients(ue.NudmSDMUri)
	if client == nil {
		return nil, openapi.ReportError("udm not found")
	}

	paramReq := Nudm_SubscriberDataManagement.GetSmfSelDataRequest{
		Supi:   &ue.Supi,
		PlmnId: &ue.PlmnId,
	}

	ctx, _, err := amf_context.GetSelf().GetTokenCtxForNFInstance(
		models.Nrf_NFMgmt_ServiceName_NUDM_SDM, models.Nrf_NFMgmt_NFType_UDM, ue.UdmId)
	if err != nil {
		return nil, err
	}

	data, localErr := client.SMFSelectionSubscriptionDataRetrievalApi.
		GetSmfSelData(ctx, &paramReq)

	if localErr == nil {
		ue.SmfSelectionData = data.Udm_SDM_SmfSelectionSubscriptionData
	} else {
		err = localErr
		switch errType := localErr.(type) {
		case openapi.GenericOpenAPIError:
			// API error
			switch errModel := errType.Model().(type) {
			case Nudm_SubscriberDataManagement.GetSmfSelDataError:
				problemDetails = errModel.ProblemDetails
			case error:
				err = errModel
			default:
				err = openapi.ReportError("openapi error")
			}
		case error:
			problemDetails = openapi.ProblemDetailsSystemFailure(err.Error())
		default:
			err = openapi.ReportError("openapi error")
		}
	}

	return problemDetails, err
}

func (s *nudmService) SDMGetUeContextInSmfData(
	ue *amf_context.AmfUe,
) (problemDetails *models.ProblemDetails, err error) {
	client := s.getSubscriberDMngmntClients(ue.NudmSDMUri)
	if client == nil {
		return nil, openapi.ReportError("udm not found")
	}

	ctx, _, err := amf_context.GetSelf().GetTokenCtxForNFInstance(
		models.Nrf_NFMgmt_ServiceName_NUDM_SDM, models.Nrf_NFMgmt_NFType_UDM, ue.UdmId)
	if err != nil {
		return nil, err
	}

	getUeCtxInSmfDataReq := Nudm_SubscriberDataManagement.GetUeCtxInSmfDataRequest{
		Supi: &ue.Supi,
	}

	data, localErr := client.UEContextInSMFDataRetrievalApi.
		GetUeCtxInSmfData(ctx, &getUeCtxInSmfDataReq)
	if localErr == nil {
		ue.UeContextInSmfData = data.Udm_SDM_UeContextInSmfData
	} else {
		err = localErr
		switch errType := localErr.(type) {
		case openapi.GenericOpenAPIError:
			switch errModel := errType.Model().(type) {
			case Nudm_SubscriberDataManagement.GetUeCtxInSmfDataError:
				problemDetails = errModel.ProblemDetails
			case error:
				err = errModel
			default:
				err = openapi.ReportError("openapi error")
			}
		case error:
			problemDetails = openapi.ProblemDetailsSystemFailure(err.Error())
		default:
			return nil, openapi.ReportError("openapi error")
		}
	}

	return problemDetails, err
}

func (s *nudmService) SDMSubscribe(ue *amf_context.AmfUe) (problemDetails *models.ProblemDetails, err error) {
	client := s.getSubscriberDMngmntClients(ue.NudmSDMUri)
	if client == nil {
		return nil, openapi.ReportError("udm not found")
	}

	amfSelf := amf_context.GetSelf()
	sdmSubscription := models.Udm_SDM_SdmSubscription{
		NfInstanceId: amfSelf.NfId,
		PlmnId:       &ue.PlmnId,
	}

	subscribeReq := Nudm_SubscriberDataManagement.SubscribeRequest{
		UeId:        &ue.Supi,
		RequestBody: &sdmSubscription,
	}

	ctx, _, err := amf_context.GetSelf().GetTokenCtxForNFInstance(
		models.Nrf_NFMgmt_ServiceName_NUDM_SDM, models.Nrf_NFMgmt_NFType_UDM, ue.UdmId)
	if err != nil {
		return nil, err
	}

	resSubscription, localErr := client.SubscriptionCreationApi.Subscribe(
		ctx, &subscribeReq)
	if localErr == nil {
		ue.SdmSubscriptionId = resSubscription.Udm_SDM_SdmSubscription.SubscriptionId
		return problemDetails, err
	} else {
		err = localErr
		switch errType := localErr.(type) {
		case openapi.GenericOpenAPIError:
			switch errModel := errType.Model().(type) {
			case Nudm_SubscriberDataManagement.SubscribeError:
				problemDetails = errModel.ProblemDetails
			case error:
				err = errModel
			default:
				err = openapi.ReportError("openapi error")
			}
		case error:
			problemDetails = openapi.ProblemDetailsSystemFailure(err.Error())
		default:
			return nil, openapi.ReportError("openapi error")
		}
	}
	return problemDetails, err
}

func (s *nudmService) SDMGetSliceSelectionSubscriptionData(
	ue *amf_context.AmfUe,
) (problemDetails *models.ProblemDetails, err error) {
	client := s.getSubscriberDMngmntClients(ue.NudmSDMUri)
	if client == nil {
		return nil, openapi.ReportError("udm not found")
	}

	paramReq := Nudm_SubscriberDataManagement.GetNSSAIRequest{
		Supi:   &ue.Supi,
		PlmnId: &ue.PlmnId,
	}

	ctx, _, err := amf_context.GetSelf().GetTokenCtxForNFInstance(
		models.Nrf_NFMgmt_ServiceName_NUDM_SDM, models.Nrf_NFMgmt_NFType_UDM, ue.UdmId)
	if err != nil {
		return nil, err
	}

	nssai, localErr := client.SliceSelectionSubscriptionDataRetrievalApi.
		GetNSSAI(ctx, &paramReq)

	if localErr == nil {
		for _, defaultSnssai := range nssai.Udm_SDM_Nssai.DefaultSingleNssais {
			subscribedSnssai := models.Nssf_NSSel_SubscribedSnssai{
				SubscribedSnssai: &models.Snssai{
					Sst: defaultSnssai.Sst,
					Sd:  defaultSnssai.Sd,
				},
				DefaultIndication: true,
			}
			ue.SubscribedNssai = append(ue.SubscribedNssai, subscribedSnssai)
		}
		for _, snssai := range nssai.Udm_SDM_Nssai.SingleNssais {
			subscribedSnssai := models.Nssf_NSSel_SubscribedSnssai{
				SubscribedSnssai: &models.Snssai{
					Sst: snssai.Sst,
					Sd:  snssai.Sd,
				},
				DefaultIndication: false,
			}
			ue.SubscribedNssai = append(ue.SubscribedNssai, subscribedSnssai)
		}
	} else {
		err = localErr
		// API error
		switch errType := localErr.(type) {
		case openapi.GenericOpenAPIError:
			switch errModel := errType.Model().(type) {
			case Nudm_SubscriberDataManagement.GetNSSAIError:
				problemDetails = errModel.ProblemDetails
			case error:
				err = errModel
			default:
				err = openapi.ReportError("openapi error")
			}
		case error:
			problemDetails = openapi.ProblemDetailsSystemFailure(err.Error())
		default:
			return nil, openapi.ReportError("openapi error")
		}
	}
	return problemDetails, err
}

func (s *nudmService) SDMUnsubscribe(ue *amf_context.AmfUe) (problemDetails *models.ProblemDetails, err error) {
	client := s.getSubscriberDMngmntClients(ue.NudmSDMUri)
	if client == nil {
		return nil, openapi.ReportError("udm not found")
	}

	ctx, _, err := amf_context.GetSelf().GetTokenCtxForNFInstance(
		models.Nrf_NFMgmt_ServiceName_NUDM_SDM, models.Nrf_NFMgmt_NFType_UDM, ue.UdmId)
	if err != nil {
		return nil, err
	}

	unsubscribeReq := Nudm_SubscriberDataManagement.UnsubscribeRequest{
		UeId:           &ue.Supi,
		SubscriptionId: &ue.SdmSubscriptionId,
	}

	_, localErr := client.SubscriptionDeletionApi.Unsubscribe(ctx, &unsubscribeReq)

	if localErr != nil {
		err = localErr
		switch errType := localErr.(type) {
		// API error
		case openapi.GenericOpenAPIError:
			switch errModel := errType.Model().(type) {
			case Nudm_SubscriberDataManagement.UnsubscribeError:
				problemDetails = errModel.ProblemDetails
			case error:
				err = errModel
			default:
				err = openapi.ReportError("openapi error")
			}
		case error:
			problemDetails = openapi.ProblemDetailsSystemFailure(err.Error())
		default:
			return nil, openapi.ReportError("openapi error")
		}
	}
	return problemDetails, err
}

func (s *nudmService) UeCmRegistration(
	ue *amf_context.AmfUe, accessType models.AccessType, initialRegistrationInd bool,
) (*models.ProblemDetails, error) {
	client := s.getUEContextMngmntClient(ue.NudmUECMUri)
	if client == nil {
		return nil, openapi.ReportError("udm not found")
	}

	amfSelf := amf_context.GetSelf()
	ctx, _, err := amf_context.GetSelf().GetTokenCtxForNFInstance(
		models.Nrf_NFMgmt_ServiceName_NUDM_UECM, models.Nrf_NFMgmt_NFType_UDM, ue.UdmId)
	if err != nil {
		return nil, err
	}

	switch accessType {
	case models.AccessType_3_GPP_ACCESS:
		deregCallbackUri := fmt.Sprintf("%s%s/deregistration/%s",
			amfSelf.GetIPv4Uri(),
			factory.AmfCallbackResUriPrefix,
			ue.Supi,
		)

		registrationData := models.Udm_UECM_Amf3GppAccessRegistration{
			AmfInstanceId:          amfSelf.NfId,
			InitialRegistrationInd: initialRegistrationInd,
			Guami:                  &amfSelf.ServedGuamiList[0],
			RatType:                ue.RatType,
			DeregCallbackUri:       deregCallbackUri,
			// TODO: not support Homogenous Support of IMS Voice over PS Sessions this stage
			ImsVoPs: models.Udm_UECM_ImsVoPs_HOMOGENEOUS_NON_SUPPORT,
		}

		regReq := Nudm_UEContextManagement.Call3GppRegistrationRequest{
			UeId:        &ue.Supi,
			RequestBody: &registrationData,
		}

		_, localErr := client.AMFRegistrationFor3GPPAccessApi.Call3GppRegistration(ctx,
			&regReq)
		if localErr == nil {
			ue.UeCmRegistered[accessType] = true
			return nil, nil
		} else {
			switch apiErr := localErr.(type) {
			// API error
			case openapi.GenericOpenAPIError:
				switch errorModel := apiErr.Model().(type) {
				case Nudm_UEContextManagement.Call3GppRegistrationError:
					return errorModel.ProblemDetails, nil
				case error:
					return openapi.ProblemDetailsSystemFailure(errorModel.Error()), nil
				default:
					return nil, openapi.ReportError("openapi error")
				}
			case error:
				return openapi.ProblemDetailsSystemFailure(apiErr.Error()), nil
			default:
				return nil, openapi.ReportError("openapi error")
			}
		}
	case models.AccessType_NON_3_GPP_ACCESS:
		deregCallbackUri := fmt.Sprintf("%s%s/deregistration/%s",
			amfSelf.GetIPv4Uri(),
			factory.AmfCallbackResUriPrefix,
			ue.Supi,
		)

		registrationData := models.Udm_UECM_AmfNon3GppAccessRegistration{
			AmfInstanceId:    amfSelf.NfId,
			Guami:            &amfSelf.ServedGuamiList[0],
			RatType:          ue.RatType,
			DeregCallbackUri: deregCallbackUri,
		}

		regReq := Nudm_UEContextManagement.Non3GppRegistrationRequest{
			UeId:        &ue.Supi,
			RequestBody: &registrationData,
		}

		_, localErr := client.AMFRegistrationForNon3GPPAccessApi.
			Non3GppRegistration(ctx, &regReq)

		if localErr == nil {
			ue.UeCmRegistered[accessType] = true
			return nil, nil
		} else {
			switch apiErr := localErr.(type) {
			case openapi.GenericOpenAPIError:
				switch errorModel := apiErr.Model().(type) {
				case Nudm_UEContextManagement.Non3GppRegistrationError:
					return errorModel.ProblemDetails, nil
				case error:
					return openapi.ProblemDetailsSystemFailure(errorModel.Error()), nil
				default:
					return nil, openapi.ReportError("openapi error")
				}
			case error:
				return openapi.ProblemDetailsSystemFailure(apiErr.Error()), nil
			default:
				return nil, openapi.ReportError("openapi error")
			}
		}
	}

	return nil, nil
}

func (s *nudmService) UeCmDeregistration(
	ue *amf_context.AmfUe, accessType models.AccessType,
) (*models.ProblemDetails, error) {
	client := s.getUEContextMngmntClient(ue.NudmUECMUri)
	if client == nil {
		return nil, openapi.ReportError("udm not found")
	}

	amfSelf := amf_context.GetSelf()
	ctx, _, err := amf_context.GetSelf().GetTokenCtxForNFInstance(
		models.Nrf_NFMgmt_ServiceName_NUDM_UECM, models.Nrf_NFMgmt_NFType_UDM, ue.UdmId)
	if err != nil {
		return nil, err
	}

	switch accessType {
	case models.AccessType_3_GPP_ACCESS:
		modificationData := models.Udm_UECM_Amf3GppAccessRegistrationModification{
			Guami:     &amfSelf.ServedGuamiList[0],
			PurgeFlag: true,
		}

		modificationReq := Nudm_UEContextManagement.Update3GppRegistrationRequest{
			UeId:        &ue.Supi,
			RequestBody: &modificationData,
		}

		_, localErr := client.ParameterUpdateInTheAMFRegistrationFor3GPPAccessApi.Update3GppRegistration(ctx,
			&modificationReq)

		if localErr == nil {
			return nil, nil
		} else {
			switch apiErr := localErr.(type) {
			// API error
			case openapi.GenericOpenAPIError:
				switch errorModel := apiErr.Model().(type) {
				case Nudm_UEContextManagement.Update3GppRegistrationError:
					return errorModel.ProblemDetails, nil
				case error:
					return openapi.ProblemDetailsSystemFailure(errorModel.Error()), nil
				default:
					return nil, openapi.ReportError("openapi error")
				}
			case error:
				return openapi.ProblemDetailsSystemFailure(apiErr.Error()), nil
			default:
				return nil, openapi.ReportError("openapi error")
			}
		}
	case models.AccessType_NON_3_GPP_ACCESS:
		modificationData := models.Udm_UECM_AmfNon3GppAccessRegistrationModification{
			Guami:     &amfSelf.ServedGuamiList[0],
			PurgeFlag: true,
		}
		modificationReq := Nudm_UEContextManagement.UpdateNon3GppRegistrationRequest{
			UeId:        &ue.Supi,
			RequestBody: &modificationData,
		}

		_, localErr := client.ParameterUpdateInTheAMFRegistrationForNon3GPPAccessApi.UpdateNon3GppRegistration(
			ctx, &modificationReq)

		if localErr == nil {
			return nil, nil
		} else {
			switch apiErr := localErr.(type) {
			// API error
			case openapi.GenericOpenAPIError:
				switch errorModel := apiErr.Model().(type) {
				case Nudm_UEContextManagement.UpdateNon3GppRegistrationError:
					return errorModel.ProblemDetails, nil
				case error:
					return openapi.ProblemDetailsSystemFailure(errorModel.Error()), nil
				default:
					return nil, openapi.ReportError("openapi error")
				}
			case error:
				return openapi.ProblemDetailsSystemFailure(apiErr.Error()), nil
			default:
				return nil, openapi.ReportError("openapi error")
			}
		}
	}

	return nil, nil
}
