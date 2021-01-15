package consumer

import (
	"context"
	"encoding/json"
	"free5gc/lib/openapi"
	"free5gc/lib/openapi/Nnssf_NSSelection"
	"free5gc/lib/openapi/models"
	amf_context "free5gc/src/amf/context"
	"free5gc/src/nssf/logger"

	"github.com/antihax/optional"
)

func NSSelectionGetForRegistration(ue *amf_context.AmfUe, requestedNssai []models.Snssai) (
	*models.ProblemDetails, error) {
	configuration := Nnssf_NSSelection.NewConfiguration()
	configuration.SetBasePath(ue.NssfUri)
	client := Nnssf_NSSelection.NewAPIClient(configuration)

	amfSelf := amf_context.AMF_Self()
	sliceInfoForRegistration := models.SliceInfoForRegistration{
		RequestedNssai:  requestedNssai,
		SubscribedNssai: ue.SubscribedNssai,
	}

	var paramOpt Nnssf_NSSelection.NSSelectionGetParamOpts
	if e, err := json.Marshal(sliceInfoForRegistration); err != nil {
		logger.Nsselection.Warnf("json marshal failed: %+v", err)
	} else {
		paramOpt = Nnssf_NSSelection.NSSelectionGetParamOpts{
			SliceInfoRequestForRegistration: optional.NewInterface(string(e)),
		}
	}
	res, httpResp, localErr := client.NetworkSliceInformationDocumentApi.NSSelectionGet(context.Background(),
		models.NfType_AMF, amfSelf.NfId, &paramOpt)
	if localErr == nil {
		ue.NetworkSliceInfo = &res
		for _, allowedNssai := range res.AllowedNssaiList {
			ue.AllowedNssai[allowedNssai.AccessType] = allowedNssai.AllowedSnssaiList
		}
		ue.ConfiguredNssai = res.ConfiguredNssai
	} else if httpResp != nil {
		if httpResp.Status != localErr.Error() {
			err := localErr
			return nil, err
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		return &problem, nil
	} else {
		return nil, openapi.ReportError("NSSF No Response")
	}

	return nil, nil
}

func NSSelectionGetForPduSession(ue *amf_context.AmfUe, snssai models.Snssai) (
	*models.AuthorizedNetworkSliceInfo, *models.ProblemDetails, error) {
	configuration := Nnssf_NSSelection.NewConfiguration()
	configuration.SetBasePath(ue.NssfUri)
	client := Nnssf_NSSelection.NewAPIClient(configuration)

	amfSelf := amf_context.AMF_Self()
	sliceInfoForPduSession := models.SliceInfoForPduSession{
		SNssai:            &snssai,
		RoamingIndication: models.RoamingIndication_NON_ROAMING, // not support roaming
	}

	e, err := json.Marshal(sliceInfoForPduSession)
	if err != nil {
		logger.Nsselection.Warnf("json marshal failed: %+v", err)
	}
	paramOpt := Nnssf_NSSelection.NSSelectionGetParamOpts{
		SliceInfoRequestForPduSession: optional.NewInterface(string(e)),
	}
	res, httpResp, localErr := client.NetworkSliceInformationDocumentApi.NSSelectionGet(context.Background(),
		models.NfType_AMF, amfSelf.NfId, &paramOpt)
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
