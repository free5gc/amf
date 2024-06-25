package consumer

import (
	"fmt"
	"sync"

	"github.com/antihax/optional"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/Nudm_SubscriberDataManagement"
	"github.com/free5gc/openapi/Nudm_UEContextManagement"
	"github.com/free5gc/openapi/models"
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

	ctx, _, err := amf_context.GetSelf().GetTokenCtx(models.ServiceName_NUDM_SDM, models.NfType_UDM)
	if err != nil {
		return err
	}

	ackInfo := models.AcknowledgeInfo{
		UpuMacIue: upuMacIue,
	}
	upuOpt := Nudm_SubscriberDataManagement.PutUpuAckParamOpts{
		AcknowledgeInfo: optional.NewInterface(ackInfo),
	}
	httpResp, err := client.ProvidingAcknowledgementOfUEParametersUpdateApi.
		PutUpuAck(ctx, ue.Supi, &upuOpt)
	defer func() {
		if httpResp != nil {
			if rspCloseErr := httpResp.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("PutUpuAck response body cannot close: %+v",
					rspCloseErr)
			}
		}
	}()
	return err
}

func (s *nudmService) SDMGetAmData(ue *amf_context.AmfUe) (problemDetails *models.ProblemDetails, err error) {
	client := s.getSubscriberDMngmntClients(ue.NudmSDMUri)
	if client == nil {
		return nil, openapi.ReportError("udm not found")
	}

	getAmDataParamOpt := Nudm_SubscriberDataManagement.GetAmDataParamOpts{
		PlmnId: optional.NewInterface(openapi.MarshToJsonString(ue.PlmnId)),
	}

	ctx, _, err := amf_context.GetSelf().GetTokenCtx(models.ServiceName_NUDM_SDM, models.NfType_UDM)
	if err != nil {
		return nil, err
	}

	data, httpResp, localErr := client.AccessAndMobilitySubscriptionDataRetrievalApi.GetAmData(
		ctx, ue.Supi, &getAmDataParamOpt)
	defer func() {
		if httpResp != nil {
			if rspCloseErr := httpResp.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("GetAmData response body cannot close: %+v",
					rspCloseErr)
			}
		}
	}()
	if localErr == nil {
		ue.AccessAndMobilitySubscriptionData = &data
		ue.Gpsi = data.Gpsis[0] // TODO: select GPSI
	} else if httpResp != nil {
		if httpResp.Status != localErr.Error() {
			err = localErr
			return problemDetails, err
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = openapi.ReportError("server no response")
	}
	return problemDetails, err
}

func (s *nudmService) SDMGetSmfSelectData(ue *amf_context.AmfUe) (problemDetails *models.ProblemDetails, err error) {
	client := s.getSubscriberDMngmntClients(ue.NudmSDMUri)
	if client == nil {
		return nil, openapi.ReportError("udm not found")
	}

	paramOpt := Nudm_SubscriberDataManagement.GetSmfSelectDataParamOpts{
		PlmnId: optional.NewInterface(openapi.MarshToJsonString(ue.PlmnId)),
	}

	ctx, _, err := amf_context.GetSelf().GetTokenCtx(models.ServiceName_NUDM_SDM, models.NfType_UDM)
	if err != nil {
		return nil, err
	}

	data, httpResp, localErr := client.SMFSelectionSubscriptionDataRetrievalApi.
		GetSmfSelectData(ctx, ue.Supi, &paramOpt)
	defer func() {
		if httpResp != nil {
			if rspCloseErr := httpResp.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("GetSmfSelectData response body cannot close: %+v",
					rspCloseErr)
			}
		}
	}()
	if localErr == nil {
		ue.SmfSelectionData = &data
	} else if httpResp != nil {
		if httpResp.Status != localErr.Error() {
			err = localErr
			return problemDetails, err
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = openapi.ReportError("server no response")
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

	ctx, _, err := amf_context.GetSelf().GetTokenCtx(models.ServiceName_NUDM_SDM, models.NfType_UDM)
	if err != nil {
		return nil, err
	}

	data, httpResp, localErr := client.UEContextInSMFDataRetrievalApi.
		GetUeContextInSmfData(ctx, ue.Supi, nil)
	defer func() {
		if httpResp != nil {
			if rspCloseErr := httpResp.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("GetUeContextInSmfData response body cannot close: %+v",
					rspCloseErr)
			}
		}
	}()
	if localErr == nil {
		ue.UeContextInSmfData = &data
	} else if httpResp != nil {
		if httpResp.Status != localErr.Error() {
			err = localErr
			return nil, err
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = openapi.ReportError("server no response")
	}

	return problemDetails, err
}

func (s *nudmService) SDMSubscribe(ue *amf_context.AmfUe) (problemDetails *models.ProblemDetails, err error) {
	client := s.getSubscriberDMngmntClients(ue.NudmSDMUri)
	if client == nil {
		return nil, openapi.ReportError("udm not found")
	}

	amfSelf := amf_context.GetSelf()
	sdmSubscription := models.SdmSubscription{
		NfInstanceId: amfSelf.NfId,
		PlmnId:       &ue.PlmnId,
	}

	ctx, _, err := amf_context.GetSelf().GetTokenCtx(models.ServiceName_NUDM_SDM, models.NfType_UDM)
	if err != nil {
		return nil, err
	}

	resSubscription, httpResp, localErr := client.SubscriptionCreationApi.Subscribe(
		ctx, ue.Supi, sdmSubscription)
	defer func() {
		if httpResp != nil {
			if rspCloseErr := httpResp.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("Subscribe response body cannot close: %+v",
					rspCloseErr)
			}
		}
	}()
	if localErr == nil {
		ue.SdmSubscriptionId = resSubscription.SubscriptionId
		return problemDetails, err
	} else if httpResp != nil {
		if httpResp.Status != localErr.Error() {
			err = localErr
			return problemDetails, err
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = openapi.ReportError("server no response")
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

	paramOpt := Nudm_SubscriberDataManagement.GetNssaiParamOpts{
		PlmnId: optional.NewInterface(openapi.MarshToJsonString(ue.PlmnId)),
	}

	ctx, _, err := amf_context.GetSelf().GetTokenCtx(models.ServiceName_NUDM_SDM, models.NfType_UDM)
	if err != nil {
		return nil, err
	}

	nssai, httpResp, localErr := client.SliceSelectionSubscriptionDataRetrievalApi.
		GetNssai(ctx, ue.Supi, &paramOpt)
	defer func() {
		if httpResp != nil {
			if rspCloseErr := httpResp.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("GetNssai response body cannot close: %+v",
					rspCloseErr)
			}
		}
	}()
	if localErr == nil {
		for _, defaultSnssai := range nssai.DefaultSingleNssais {
			subscribedSnssai := models.SubscribedSnssai{
				SubscribedSnssai: &models.Snssai{
					Sst: defaultSnssai.Sst,
					Sd:  defaultSnssai.Sd,
				},
				DefaultIndication: true,
			}
			ue.SubscribedNssai = append(ue.SubscribedNssai, subscribedSnssai)
		}
		for _, snssai := range nssai.SingleNssais {
			subscribedSnssai := models.SubscribedSnssai{
				SubscribedSnssai: &models.Snssai{
					Sst: snssai.Sst,
					Sd:  snssai.Sd,
				},
				DefaultIndication: false,
			}
			ue.SubscribedNssai = append(ue.SubscribedNssai, subscribedSnssai)
		}
	} else if httpResp != nil {
		if httpResp.Status != localErr.Error() {
			err = localErr
			return problemDetails, err
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = openapi.ReportError("server no response")
	}
	return problemDetails, err
}

func (s *nudmService) SDMUnsubscribe(ue *amf_context.AmfUe) (problemDetails *models.ProblemDetails, err error) {
	client := s.getSubscriberDMngmntClients(ue.NudmSDMUri)
	if client == nil {
		return nil, openapi.ReportError("udm not found")
	}

	ctx, _, err := amf_context.GetSelf().GetTokenCtx(models.ServiceName_NUDM_SDM, models.NfType_UDM)
	if err != nil {
		return nil, err
	}

	httpResp, localErr := client.SubscriptionDeletionApi.Unsubscribe(ctx, ue.Supi, ue.SdmSubscriptionId)
	defer func() {
		if httpResp != nil {
			if rspCloseErr := httpResp.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("Unsubscribe response body cannot close: %+v",
					rspCloseErr)
			}
		}
	}()
	if localErr == nil {
		return problemDetails, err
	} else if httpResp != nil {
		if httpResp.Status != localErr.Error() {
			err = localErr
			return nil, err
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = openapi.ReportError("server no response")
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
	ctx, _, err := amf_context.GetSelf().GetTokenCtx(models.ServiceName_NUDM_UEAU, models.NfType_UDM)
	if err != nil {
		return nil, err
	}

	switch accessType {
	case models.AccessType__3_GPP_ACCESS:
		deregCallbackUri := fmt.Sprintf("%s%s/deregistration/%s",
			amfSelf.GetIPv4Uri(),
			factory.AmfCallbackResUriPrefix,
			ue.Supi,
		)

		registrationData := models.Amf3GppAccessRegistration{
			AmfInstanceId:          amfSelf.NfId,
			InitialRegistrationInd: initialRegistrationInd,
			Guami:                  &amfSelf.ServedGuamiList[0],
			RatType:                ue.RatType,
			DeregCallbackUri:       deregCallbackUri,
			// TODO: not support Homogenous Support of IMS Voice over PS Sessions this stage
			ImsVoPs: models.ImsVoPs_HOMOGENEOUS_NON_SUPPORT,
		}

		_, httpResp, localErr := client.AMFRegistrationFor3GPPAccessApi.Registration(ctx,
			ue.Supi, registrationData)
		defer func() {
			if httpResp != nil {
				if rspCloseErr := httpResp.Body.Close(); rspCloseErr != nil {
					logger.ConsumerLog.Errorf("Registration response body cannot close: %+v",
						rspCloseErr)
				}
			}
		}()
		if localErr == nil {
			ue.UeCmRegistered[accessType] = true
			return nil, nil
		} else if httpResp != nil {
			if httpResp.Status != localErr.Error() {
				return nil, localErr
			}
			problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
			return &problem, nil
		} else {
			return nil, openapi.ReportError("server no response")
		}
	case models.AccessType_NON_3_GPP_ACCESS:
		registrationData := models.AmfNon3GppAccessRegistration{
			AmfInstanceId: amfSelf.NfId,
			Guami:         &amfSelf.ServedGuamiList[0],
			RatType:       ue.RatType,
		}

		_, httpResp, localErr := client.AMFRegistrationForNon3GPPAccessApi.
			Register(ctx, ue.Supi, registrationData)
		defer func() {
			if httpResp != nil {
				if rspCloseErr := httpResp.Body.Close(); rspCloseErr != nil {
					logger.ConsumerLog.Errorf("Register response body cannot close: %+v",
						rspCloseErr)
				}
			}
		}()
		if localErr == nil {
			ue.UeCmRegistered[accessType] = true
			return nil, nil
		} else if httpResp != nil {
			if httpResp.Status != localErr.Error() {
				return nil, localErr
			}
			problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
			return &problem, nil
		} else {
			return nil, openapi.ReportError("server no response")
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
	ctx, _, err := amf_context.GetSelf().GetTokenCtx(models.ServiceName_NUDM_UECM, models.NfType_UDM)
	if err != nil {
		return nil, err
	}

	switch accessType {
	case models.AccessType__3_GPP_ACCESS:
		modificationData := models.Amf3GppAccessRegistrationModification{
			Guami:     &amfSelf.ServedGuamiList[0],
			PurgeFlag: true,
		}

		httpResp, localErr := client.ParameterUpdateInTheAMFRegistrationFor3GPPAccessApi.Update(ctx,
			ue.Supi, modificationData)
		defer func() {
			if httpResp != nil {
				if rspCloseErr := httpResp.Body.Close(); rspCloseErr != nil {
					logger.ConsumerLog.Errorf("Update response body cannot close: %+v",
						rspCloseErr)
				}
			}
		}()
		if localErr == nil {
			return nil, nil
		} else if httpResp != nil {
			if httpResp.Status != localErr.Error() {
				return nil, localErr
			}
			problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
			return &problem, nil
		} else {
			return nil, openapi.ReportError("server no response")
		}
	case models.AccessType_NON_3_GPP_ACCESS:
		modificationData := models.AmfNon3GppAccessRegistrationModification{
			Guami:     &amfSelf.ServedGuamiList[0],
			PurgeFlag: true,
		}

		httpResp, localErr := client.ParameterUpdateInTheAMFRegistrationForNon3GPPAccessApi.UpdateAmfNon3gppAccess(
			ctx, ue.Supi, modificationData)
		defer func() {
			if httpResp != nil {
				if rspCloseErr := httpResp.Body.Close(); rspCloseErr != nil {
					logger.ConsumerLog.Errorf("UpdateAmfNon3gppAccess response body cannot close: %+v",
						rspCloseErr)
				}
			}
		}()
		if localErr == nil {
			return nil, nil
		} else if httpResp != nil {
			if httpResp.Status != localErr.Error() {
				return nil, localErr
			}
			problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
			return &problem, nil
		} else {
			return nil, openapi.ReportError("server no response")
		}
	}

	return nil, nil
}
