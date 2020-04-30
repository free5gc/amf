package gmm

import (
	"free5gc/lib/fsm"
	"free5gc/lib/openapi/models"
	"free5gc/src/amf/context"
	"free5gc/src/amf/gmm/state"
)

func NewGmmFuncTable(anType models.AccessType) fsm.FuncTable {
	table := fsm.NewFuncTable()
	if anType == models.AccessType__3_GPP_ACCESS {
		table[state.DE_REGISTERED] = DeRegistered_3gpp
		table[state.REGISTERED] = Registered_3gpp
		table[state.AUTHENTICATION] = Authentication_3gpp
		table[state.SECURITY_MODE] = SecurityMode_3gpp
		table[state.INITIAL_CONTEXT_SETUP] = InitialContextSetup_3gpp
	} else {
		table[state.DE_REGISTERED] = DeRegistered_non_3gpp
		table[state.REGISTERED] = Registered_non_3gpp
		table[state.AUTHENTICATION] = Authentication_non_3gpp
		table[state.SECURITY_MODE] = SecurityMode_non_3gpp
		table[state.INITIAL_CONTEXT_SETUP] = InitialContextSetup_non_3gpp
	}

	table[state.EXCEPTION] = Exception

	return table
}

func InitAmfUeSm(ue *context.AmfUe) (err error) {
	table := NewGmmFuncTable(models.AccessType__3_GPP_ACCESS)
	ue.Sm[models.AccessType__3_GPP_ACCESS], err = fsm.NewFSM(state.DE_REGISTERED, table)
	if err != nil {
		return
	}
	table = NewGmmFuncTable(models.AccessType_NON_3_GPP_ACCESS)
	ue.Sm[models.AccessType_NON_3_GPP_ACCESS], err = fsm.NewFSM(state.DE_REGISTERED, table)
	return
}
