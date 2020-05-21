package consumer

import (
	"context"
	"encoding/json"
	"free5gc/lib/openapi"
	"free5gc/lib/openapi/Nnssf_NSSelection"
	"free5gc/lib/openapi/models"
	amf_context "free5gc/src/amf/context"

	"github.com/antihax/optional"
)

func NSSelectionGetForRegistration(ue *amf_context.AmfUe, requestedNssai []models.Snssai) (problemDetails *models.ProblemDetails, err error) {
	configuration := Nnssf_NSSelection.NewConfiguration()
	configuration.SetBasePath(ue.NssfUri)
	client := Nnssf_NSSelection.NewAPIClient(configuration)

	amfSelf := amf_context.AMF_Self()
	sliceInfoForRegistration := models.SliceInfoForRegistration{
		RequestedNssai:  requestedNssai,
		SubscribedNssai: ue.SubscribedNssai,
	}

	e, _ := json.Marshal(sliceInfoForRegistration)
	paramOpt := Nnssf_NSSelection.NSSelectionGetParamOpts{
		SliceInfoRequestForRegistration: optional.NewInterface(string(e)),
	}
	res, httpResp, localErr := client.NetworkSliceInformationDocumentApi.NSSelectionGet(context.Background(), models.NfType_AMF, amfSelf.NfId, &paramOpt)
	if localErr == nil {
		ue.NetworkSliceInfo = &res
		for _, allowedNssai := range res.AllowedNssaiList {
			ue.AllowedNssai[allowedNssai.AccessType] = allowedNssai.AllowedSnssaiList
		}
		ue.ConfiguredNssai = res.ConfiguredNssai
	} else if httpResp != nil {
		if httpResp.Status != localErr.Error() {
			err = localErr
			return
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = openapi.ReportError("NSSF No Response")
	}

	return
}

func NSSelectionGetForPduSession(ue *amf_context.AmfUe, snssai models.Snssai) (response *models.AuthorizedNetworkSliceInfo, problemDetails *models.ProblemDetails, err error) {
	configuration := Nnssf_NSSelection.NewConfiguration()
	configuration.SetBasePath(ue.NssfUri)
	client := Nnssf_NSSelection.NewAPIClient(configuration)

	amfSelf := amf_context.AMF_Self()
	sliceInfoForPduSession := models.SliceInfoForPduSession{
		SNssai:            &snssai,
		RoamingIndication: models.RoamingIndication_NON_ROAMING, // not support roaming
	}

	e, _ := json.Marshal(sliceInfoForPduSession)
	paramOpt := Nnssf_NSSelection.NSSelectionGetParamOpts{
		SliceInfoRequestForPduSession: optional.NewInterface(string(e)),
	}
	res, httpResp, localErr := client.NetworkSliceInformationDocumentApi.NSSelectionGet(context.Background(), models.NfType_AMF, amfSelf.NfId, &paramOpt)
	if localErr == nil {
		response = &res
	} else if httpResp != nil {
		if httpResp.Status != localErr.Error() {
			err = localErr
			return
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = openapi.ReportError("NSSF No Response")
	}

	return
}
