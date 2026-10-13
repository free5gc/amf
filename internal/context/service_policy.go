package context

import (
	"slices"

	"github.com/free5gc/openapi/models"
)

const ServiceNameNamfCallback models.Nrf_NFMgmt_ServiceName = "namf-callback"

var servicePolicies = map[models.Nrf_NFMgmt_ServiceName][]models.Nrf_NFMgmt_NFType{
	models.Nrf_NFMgmt_ServiceName_NAMF_COMM: {
		models.Nrf_NFMgmt_NFType_AMF,
		models.Nrf_NFMgmt_NFType_SMF,
		models.Nrf_NFMgmt_NFType_SMSF,
		models.Nrf_NFMgmt_NFType_LMF,
		models.Nrf_NFMgmt_NFType_PCF,
		models.Nrf_NFMgmt_NFType_NEF,
		models.Nrf_NFMgmt_NFType_UDM,
		models.Nrf_NFMgmt_NFType_CBCF,
	},
	models.Nrf_NFMgmt_ServiceName_NAMF_EVTS: {
		models.Nrf_NFMgmt_NFType_NEF,
		models.Nrf_NFMgmt_NFType_SMF,
		models.Nrf_NFMgmt_NFType_UDM,
		models.Nrf_NFMgmt_NFType_NWDAF,
		models.Nrf_NFMgmt_NFType_DCCF,
		models.Nrf_NFMgmt_NFType_LMF,
		models.Nrf_NFMgmt_NFType_GMLC,
	},
	models.Nrf_NFMgmt_ServiceName_NAMF_MT: {
		models.Nrf_NFMgmt_NFType_SMSF,
		models.Nrf_NFMgmt_NFType_UDM,
	},
	models.Nrf_NFMgmt_ServiceName_NAMF_LOC: {
		models.Nrf_NFMgmt_NFType_GMLC,
		models.Nrf_NFMgmt_NFType_UDM,
	},
	ServiceNameNamfCallback: {
		models.Nrf_NFMgmt_NFType_AMF,
		models.Nrf_NFMgmt_NFType_SMF,
		models.Nrf_NFMgmt_NFType_PCF,
		models.Nrf_NFMgmt_NFType_UDM,
	},
	// OAM authorization is intentionally unchanged until management-plane
	// authentication is designed separately.
	models.Nrf_NFMgmt_ServiceName_NAMF_OAM: nil,
}

func AllowedNfTypesForService(serviceName models.Nrf_NFMgmt_ServiceName) (
	[]models.Nrf_NFMgmt_NFType, bool,
) {
	allowed, known := servicePolicies[serviceName]
	return slices.Clone(allowed), known
}
