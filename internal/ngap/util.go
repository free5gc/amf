package ngap

import "github.com/free5gc/openapi/models"

func isValidTai(tai models.Tai) bool {
	return tai.Tac != "" && tai.PlmnId.Mcc != "" && tai.PlmnId.Mnc != ""
}
