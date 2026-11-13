package consumer

import (
	"regexp"
	"sync"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	Npcf_AMPolicy "github.com/free5gc/openapi/pcf/AMPolCtrl"
	sbi_metrics "github.com/free5gc/util/metrics/sbi"
)

type npcfService struct {
	consumer *Consumer

	AMPolicyMu sync.RWMutex

	AMPolicyClients map[string]*Npcf_AMPolicy.APIClient
}

func (s *npcfService) getAMPolicyClient(uri string) *Npcf_AMPolicy.APIClient {
	if uri == "" {
		return nil
	}
	s.AMPolicyMu.RLock()
	client, ok := s.AMPolicyClients[uri]
	if ok {
		s.AMPolicyMu.RUnlock()
		return client
	}

	configuration := Npcf_AMPolicy.NewConfiguration()
	configuration.SetBasePath(uri)
	configuration.SetMetrics(sbi_metrics.SbiMetricHook)
	client = Npcf_AMPolicy.NewAPIClient(configuration)

	s.AMPolicyMu.RUnlock()
	s.AMPolicyMu.Lock()
	defer s.AMPolicyMu.Unlock()
	s.AMPolicyClients[uri] = client
	return client
}

func (s *npcfService) AMPolicyControlCreate(
	ue *amf_context.AmfUe, anType models.AccessType,
) (*models.ProblemDetails, error) {
	client := s.getAMPolicyClient(ue.PcfUri)
	if client == nil {
		return nil, openapi.ReportError("pcf not found")
	}
	amfSelf := amf_context.GetSelf()
	ctx, _, err := amf_context.GetSelf().GetTokenCtxForNFInstance(
		models.Nrf_NFMgmt_ServiceName_NPCF_AM_POLICY_CONTROL, models.Nrf_NFMgmt_NFType_PCF, ue.PcfId)
	if err != nil {
		return nil, err
	}

	policyAssociationRequest := models.Pcf_AMPolCtrl_PolicyAssociationRequest{
		NotificationUri: amfSelf.GetIPv4Uri() + factory.AmfCallbackResUriPrefix + "/am-policy/",
		Supi:            ue.Supi,
		Pei:             ue.Pei,
		Gpsi:            ue.Gpsi,
		AccessType:      anType,
		ServingPlmn: &models.PlmnIdNid{
			Mcc: ue.PlmnId.Mcc,
			Mnc: ue.PlmnId.Mnc,
		},
		Guami:    &amfSelf.ServedGuamiList[0],
		SuppFeat: "0",
	}
	var policyAssociationreq Npcf_AMPolicy.CreateIndividualAMPolicyAssociationRequest

	policyAssociationreq.SetRequestBody(policyAssociationRequest)

	if ue.AccessAndMobilitySubscriptionData != nil {
		policyAssociationRequest.Rfsp = ue.AccessAndMobilitySubscriptionData.RfspIndex
	}

	res, localErr := client.AMPolicyAssociationsCollectionApi.
		CreateIndividualAMPolicyAssociation(ctx, &policyAssociationreq)
	if localErr == nil {
		locationHeader := res.Location
		logger.ConsumerLog.Debugf("location header: %+v", locationHeader)
		ue.AmPolicyUri = locationHeader

		re := regexp.MustCompile("/policies/.*")
		match := re.FindStringSubmatch(locationHeader)

		ue.PolicyAssociationId = match[0][10:]
		ue.AmPolicyAssociation = res.Pcf_AMPolCtrl_PolicyAssociation

		if res.Pcf_AMPolCtrl_PolicyAssociation.Triggers != nil {
			for _, trigger := range res.Pcf_AMPolCtrl_PolicyAssociation.Triggers {
				if trigger == models.Pcf_AMPolCtrl_RequestTrigger_LOC_CH {
					ue.RequestTriggerLocationChange = true
				}
				// if trigger == models.RequestTrigger_PRA_CH {
				// TODO: Presence Reporting Area handling (TS 23.503 6.1.2.5, TS 23.501 5.6.11)
				// }
			}
		}

		logger.ConsumerLog.Debugf("UE AM Policy Association ID: %s", ue.PolicyAssociationId)
		logger.ConsumerLog.Debugf("AmPolicyAssociation: %+v", ue.AmPolicyAssociation)
	} else {
		switch apiErr := localErr.(type) {
		// API error
		case openapi.GenericOpenAPIError:
			switch errorModel := apiErr.Model().(type) {
			case Npcf_AMPolicy.CreateIndividualAMPolicyAssociationError:
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
	return nil, nil
}

func (s *npcfService) AMPolicyControlUpdate(
	ue *amf_context.AmfUe, updateRequest models.Pcf_AMPolCtrl_PolicyAssociationUpdateRequest,
) (problemDetails *models.ProblemDetails, err error) {
	client := s.getAMPolicyClient(ue.PcfUri)
	if client == nil {
		return nil, openapi.ReportError("pcf not found")
	}

	ctx, _, err := amf_context.GetSelf().GetTokenCtxForNFInstance(
		models.Nrf_NFMgmt_ServiceName_NPCF_AM_POLICY_CONTROL, models.Nrf_NFMgmt_NFType_PCF, ue.PcfId)
	if err != nil {
		return nil, err
	}

	var policyUpdateReq Npcf_AMPolicy.ReportObservedEventTriggersForIndividualAMPolicyAssociationRequest

	policyUpdateReq.SetPolAssoId(ue.PolicyAssociationId)
	policyUpdateReq.SetRequestBody(updateRequest)

	res, localErr := client.IndividualAMPolicyAssociationDocumentApi.
		ReportObservedEventTriggersForIndividualAMPolicyAssociation(ctx, &policyUpdateReq)
	if localErr == nil {
		if res.Pcf_AMPolCtrl_PolicyUpdate.ServAreaRes != nil {
			ue.AmPolicyAssociation.ServAreaRes = res.Pcf_AMPolCtrl_PolicyUpdate.ServAreaRes
		}
		if res.Pcf_AMPolCtrl_PolicyUpdate.Rfsp != 0 {
			ue.AmPolicyAssociation.Rfsp = res.Pcf_AMPolCtrl_PolicyUpdate.Rfsp
		}
		ue.AmPolicyAssociation.Triggers = res.Pcf_AMPolCtrl_PolicyUpdate.Triggers
		ue.RequestTriggerLocationChange = false
		for _, trigger := range res.Pcf_AMPolCtrl_PolicyUpdate.Triggers {
			if trigger == models.Pcf_AMPolCtrl_RequestTrigger_LOC_CH {
				ue.RequestTriggerLocationChange = true
			}
			// if trigger == models.RequestTrigger_PRA_CH {
			// TODO: Presence Reporting Area handling (TS 23.503 6.1.2.5, TS 23.501 5.6.11)
			// }
		}
	} else {
		switch apiErr := localErr.(type) {
		// API error
		case openapi.GenericOpenAPIError:
			switch errorModel := apiErr.Model().(type) {
			case Npcf_AMPolicy.ReportObservedEventTriggersForIndividualAMPolicyAssociationError:
				return errorModel.ProblemDetails, nil
			case error:
				return openapi.ProblemDetailsSystemFailure(errorModel.Error()), nil
			default:
				err = openapi.ReportError("openapi error")
			}
		case error:
			return openapi.ProblemDetailsSystemFailure(apiErr.Error()), nil
		default:
			err = openapi.ReportError("server no response")
		}
	}
	return nil, err
}

func (s *npcfService) AMPolicyControlDelete(ue *amf_context.AmfUe) (problemDetails *models.ProblemDetails, err error) {
	client := s.getAMPolicyClient(ue.PcfUri)
	if client == nil {
		return nil, openapi.ReportError("pcf not found")
	}

	ctx, _, ctxErr := amf_context.GetSelf().GetTokenCtxForNFInstance(
		models.Nrf_NFMgmt_ServiceName_NPCF_AM_POLICY_CONTROL, models.Nrf_NFMgmt_NFType_PCF, ue.PcfId)
	if ctxErr != nil {
		return nil, ctxErr
	}

	var deleteReq Npcf_AMPolicy.DeleteIndividualAMPolicyAssociationRequest
	deleteReq.SetPolAssoId(ue.PolicyAssociationId)

	_, err = client.IndividualAMPolicyAssociationDocumentApi.DeleteIndividualAMPolicyAssociation(ctx, &deleteReq)
	if err == nil {
		ue.RemoveAmPolicyAssociation()
	} else {
		switch apiErr := err.(type) {
		// API error
		case openapi.GenericOpenAPIError:
			switch errorModel := apiErr.Model().(type) {
			case Npcf_AMPolicy.DeleteIndividualAMPolicyAssociationError:
				return errorModel.ProblemDetails, nil
			case error:
				return openapi.ProblemDetailsSystemFailure(errorModel.Error()), nil
			default:
				err = openapi.ReportError("openapi error")
			}
		case error:
			return openapi.ProblemDetailsSystemFailure(apiErr.Error()), nil
		default:
			err = openapi.ReportError("server no response")
		}
	}
	return nil, err
}
