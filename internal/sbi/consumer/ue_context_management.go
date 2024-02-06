package consumer

import (
	"fmt"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/Nudm_UEContextManagement"
	"github.com/free5gc/openapi/models"
)

func UeCmRegistration(ue *amf_context.AmfUe, accessType models.AccessType, initialRegistrationInd bool) (
	*models.ProblemDetails, error,
) {
	configuration := Nudm_UEContextManagement.NewConfiguration()
	configuration.SetBasePath(ue.NudmUECMUri)
	client := Nudm_UEContextManagement.NewAPIClient(configuration)

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

func UeCmDeregistration(ue *amf_context.AmfUe, accessType models.AccessType) (
	*models.ProblemDetails, error,
) {
	configuration := Nudm_UEContextManagement.NewConfiguration()
	configuration.SetBasePath(ue.NudmUECMUri)
	client := Nudm_UEContextManagement.NewAPIClient(configuration)

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
