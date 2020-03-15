package amf_consumer

import (
	"context"
	"fmt"
	"gofree5gc/lib/Nnrf_NFDiscovery"
	"gofree5gc/lib/openapi/models"
	"gofree5gc/src/amf/amf_context"
	"gofree5gc/src/amf/amf_util"
	"gofree5gc/src/amf/logger"
	"net/http"
)

func SendSearchNFInstances(nrfUri string, targetNfType, requestNfType models.NfType, param *Nnrf_NFDiscovery.SearchNFInstancesParamOpts) (result models.SearchResult, err error) {

	// Set client and set url
	configuration := Nnrf_NFDiscovery.NewConfiguration()
	configuration.SetBasePath(nrfUri)
	client := Nnrf_NFDiscovery.NewAPIClient(configuration)

	var res *http.Response
	result, res, err = client.NFInstancesStoreApi.SearchNFInstances(context.TODO(), targetNfType, requestNfType, param)
	if res != nil && res.StatusCode == http.StatusTemporaryRedirect {
		err = fmt.Errorf("Temporary Redirect For Non NRF Consumer")
	}
	return
}

func SearchUdmSdmInstance(ue *amf_context.AmfUe, nrfUri string, targetNfType, requestNfType models.NfType, param *Nnrf_NFDiscovery.SearchNFInstancesParamOpts) (err error) {

	resp, localErr := SendSearchNFInstances(nrfUri, targetNfType, requestNfType, param)
	if localErr != nil {
		err = localErr
		return
	}

	// select the first UDM_SDM, TODO: select base on other info
	var sdmUri string
	for _, nfProfile := range resp.NfInstances {
		ue.UdmId = nfProfile.NfInstanceId
		sdmUri = amf_util.SearchNFServiceUri(nfProfile, models.ServiceName_NUDM_SDM, models.NfServiceStatus_REGISTERED)
		if sdmUri != "" {
			break
		}
	}
	ue.NudmSDMUri = sdmUri
	if ue.NudmSDMUri == "" {
		err = fmt.Errorf("AMF can not select an UDM by NRF")
		logger.ConsumerLog.Errorf(err.Error())
	}
	return
}

func SearchNssfNSSelectionInstance(ue *amf_context.AmfUe, nrfUri string, targetNfType, requestNfType models.NfType, param *Nnrf_NFDiscovery.SearchNFInstancesParamOpts) (err error) {

	resp, localErr := SendSearchNFInstances(nrfUri, targetNfType, requestNfType, param)
	if localErr != nil {
		err = localErr
		return
	}

	// select the first NSSF, TODO: select base on other info
	var nssfUri string
	for _, nfProfile := range resp.NfInstances {
		ue.NssfId = nfProfile.NfInstanceId
		nssfUri = amf_util.SearchNFServiceUri(nfProfile, models.ServiceName_NNSSF_NSSELECTION, models.NfServiceStatus_REGISTERED)
		if nssfUri != "" {
			break
		}
	}
	ue.NssfUri = nssfUri
	if ue.NssfUri == "" {
		err = fmt.Errorf("AMF can not select an NSSF by NRF")
	}
	return
}

func SearchAmfCommunicationInstance(ue *amf_context.AmfUe, nrfUri string, targetNfType, requestNfType models.NfType, param *Nnrf_NFDiscovery.SearchNFInstancesParamOpts) (err error) {

	resp, localErr := SendSearchNFInstances(nrfUri, targetNfType, requestNfType, param)
	if localErr != nil {
		err = localErr
		return
	}

	// select the first NSSF, TODO: select base on other info
	var amfUri string
	for _, nfProfile := range resp.NfInstances {
		ue.TargetAmfProfile = &nfProfile
		amfUri = amf_util.SearchNFServiceUri(nfProfile, models.ServiceName_NAMF_COMM, models.NfServiceStatus_REGISTERED)
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
