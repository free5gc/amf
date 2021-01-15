package consumer

import (
	"context"

	"free5gc/lib/openapi"
	"free5gc/lib/openapi/Nudm_UEContextManagement"
	"free5gc/lib/openapi/models"
	amf_context "free5gc/src/amf/context"
)

func UeCmRegistration(ue *amf_context.AmfUe, accessType models.AccessType, initialRegistrationInd bool) (
	*models.ProblemDetails, error) {

	configuration := Nudm_UEContextManagement.NewConfiguration()
	configuration.SetBasePath(ue.NudmUECMUri)
	client := Nudm_UEContextManagement.NewAPIClient(configuration)

	amfSelf := amf_context.AMF_Self()

	switch accessType {
	case models.AccessType__3_GPP_ACCESS:
		registrationData := models.Amf3GppAccessRegistration{
			AmfInstanceId:          amfSelf.NfId,
			InitialRegistrationInd: initialRegistrationInd,
			Guami:                  &amfSelf.ServedGuamiList[0],
			RatType:                ue.RatType,
			// TODO: not support Homogenous Support of IMS Voice over PS Sessions this stage
			ImsVoPs: models.ImsVoPs_HOMOGENEOUS_NON_SUPPORT,
		}

		_, httpResp, localErr := client.AMFRegistrationFor3GPPAccessApi.Registration(context.Background(),
			ue.Supi, registrationData)
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
		registrationData := models.AmfNon3GppAccessRegistration{
			AmfInstanceId: amfSelf.NfId,
			Guami:         &amfSelf.ServedGuamiList[0],
			RatType:       ue.RatType,
		}

		_, httpResp, localErr :=
			client.AMFRegistrationForNon3GPPAccessApi.Register(context.Background(), ue.Supi, registrationData)
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
