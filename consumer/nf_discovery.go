package consumer

import (
	"context"
	"fmt"
	"free5gc/lib/openapi/Nnrf_NFDiscovery"
	"free5gc/lib/openapi/models"
	amf_context "free5gc/src/amf/context"
	"free5gc/src/amf/logger"
	"free5gc/src/amf/util"
	"net/http"
)

func SendSearchNFInstances(nrfUri string, targetNfType, requestNfType models.NfType,
	param *Nnrf_NFDiscovery.SearchNFInstancesParamOpts) (models.SearchResult, error) {

	// Set client and set url
	configuration := Nnrf_NFDiscovery.NewConfiguration()
	configuration.SetBasePath(nrfUri)
	client := Nnrf_NFDiscovery.NewAPIClient(configuration)

	result, res, err := client.NFInstancesStoreApi.SearchNFInstances(context.TODO(), targetNfType, requestNfType, param)
	if res != nil && res.StatusCode == http.StatusTemporaryRedirect {
		err = fmt.Errorf("Temporary Redirect For Non NRF Consumer")
	}
	return result, err
}

func SearchUdmSdmInstance(ue *amf_context.AmfUe, nrfUri string, targetNfType, requestNfType models.NfType,
	param *Nnrf_NFDiscovery.SearchNFInstancesParamOpts) error {

	resp, localErr := SendSearchNFInstances(nrfUri, targetNfType, requestNfType, param)
	if localErr != nil {
		return localErr
	}

	// select the first UDM_SDM, TODO: select base on other info
	var sdmUri string
	for _, nfProfile := range resp.NfInstances {
		ue.UdmId = nfProfile.NfInstanceId
		sdmUri = util.SearchNFServiceUri(nfProfile, models.ServiceName_NUDM_SDM, models.NfServiceStatus_REGISTERED)
		if sdmUri != "" {
			break
		}
	}
	ue.NudmSDMUri = sdmUri
	if ue.NudmSDMUri == "" {
		err := fmt.Errorf("AMF can not select an UDM by NRF")
		logger.ConsumerLog.Errorf(err.Error())
		return err
	}
	return nil
}

func SearchNssfNSSelectionInstance(ue *amf_context.AmfUe, nrfUri string, targetNfType, requestNfType models.NfType,
	param *Nnrf_NFDiscovery.SearchNFInstancesParamOpts) error {

	resp, localErr := SendSearchNFInstances(nrfUri, targetNfType, requestNfType, param)
	if localErr != nil {
		return localErr
	}

	// select the first NSSF, TODO: select base on other info
	var nssfUri string
	for _, nfProfile := range resp.NfInstances {
		ue.NssfId = nfProfile.NfInstanceId
		nssfUri = util.SearchNFServiceUri(nfProfile, models.ServiceName_NNSSF_NSSELECTION, models.NfServiceStatus_REGISTERED)
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

func SearchAmfCommunicationInstance(ue *amf_context.AmfUe, nrfUri string, targetNfType,
	requestNfType models.NfType, param *Nnrf_NFDiscovery.SearchNFInstancesParamOpts) (err error) {

	resp, localErr := SendSearchNFInstances(nrfUri, targetNfType, requestNfType, param)
	if localErr != nil {
		err = localErr
		return
	}

	// select the first AMF, TODO: select base on other info
	var amfUri string
	for _, nfProfile := range resp.NfInstances {
		ue.TargetAmfProfile = &nfProfile
		amfUri = util.SearchNFServiceUri(nfProfile, models.ServiceName_NAMF_COMM, models.NfServiceStatus_REGISTERED)
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
