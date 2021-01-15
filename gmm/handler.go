package gmm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"free5gc/lib/fsm"
	"free5gc/lib/nas"
	"free5gc/lib/nas/nasConvert"
	"free5gc/lib/nas/nasMessage"
	"free5gc/lib/nas/nasType"
	"free5gc/lib/nas/security"
	"free5gc/lib/ngap/ngapConvert"
	"free5gc/lib/ngap/ngapType"
	"free5gc/lib/openapi/Nnrf_NFDiscovery"
	"free5gc/lib/openapi/models"
	"free5gc/src/amf/consumer"
	"free5gc/src/amf/context"
	gmm_message "free5gc/src/amf/gmm/message"
	"free5gc/src/amf/logger"
	ngap_message "free5gc/src/amf/ngap/message"
	"free5gc/src/amf/producer/callback"
	"free5gc/src/amf/util"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/antihax/optional"
	"github.com/mitchellh/mapstructure"
	"github.com/mohae/deepcopy"
)

func HandleULNASTransport(ue *context.AmfUe, anType models.AccessType,
	ulNasTransport *nasMessage.ULNASTransport) error {
	logger.GmmLog.Infoln("Handle UL NAS Transport")

	if ue.MacFailed {
		return fmt.Errorf("NAS message integrity check failed")
	}

	switch ulNasTransport.GetPayloadContainerType() {
	case nasMessage.PayloadContainerTypeN1SMInfo:

		var pduSessionId int32
		var requestType models.RequestType
		var sNssai *models.Snssai
		var dnn string
		if nasPduSessionId := ulNasTransport.PduSessionID2Value; nasPduSessionId != nil {
			pduSessionId = int32(nasPduSessionId.GetPduSessionID2Value())
		} else {
			return fmt.Errorf("NAS N1 SM info need PDU Session ID")
		}
		// TODO: implement SSC mode3 Op
		if oldPduSessionId := ulNasTransport.OldPDUSessionID; oldPduSessionId != nil {
			return fmt.Errorf("SSC mode3 operation has not been implemented yet")
		}
		if NasSnssai := ulNasTransport.SNSSAI; NasSnssai != nil {
			snssai := nasConvert.SnssaiToModels(NasSnssai)
			sNssai = &snssai
		}
		if NasDnn := ulNasTransport.DNN; NasDnn != nil {
			dnn = string(NasDnn.GetDNN())
		}
		if ulNasTransport.RequestType != nil {
			NasRequestType := ulNasTransport.RequestType.GetRequestTypeValue()

			switch NasRequestType {
			case nasMessage.ULNASTransportRequestTypeInitialRequest:
				requestType = models.RequestType_INITIAL_REQUEST
			case nasMessage.ULNASTransportRequestTypeExistingPduSession:
				requestType = models.RequestType_EXISTING_PDU_SESSION
			case nasMessage.ULNASTransportRequestTypeInitialEmergencyRequest:
				requestType = models.RequestType_INITIAL_EMERGENCY_REQUEST
				logger.GmmLog.Warnln("requestType INITIAL_EMERGENCY_REQUEST is not supported")
			case nasMessage.ULNASTransportRequestTypeExistingEmergencyPduSession:
				requestType = models.RequestType_EXISTING_EMERGENCY_PDU_SESSION
			}
		}

		m := nas.NewMessage()
		err := m.GsmMessageDecode(&ulNasTransport.PayloadContainer.Buffer)
		if err != nil {
			return err
		}
		messageType := m.GsmMessage.GetMessageType()
		switch messageType {
		case nas.MsgTypePDUSessionEstablishmentRequest:
			return HandlePDUSessionEstablishmentRequest(ue, anType, ulNasTransport.PayloadContainer.Buffer,
				pduSessionId, requestType, sNssai, dnn)
		case nas.MsgTypePDUSessionModificationRequest:
			fallthrough
		case nas.MsgTypePDUSessionModificationComplete:
			fallthrough
		case nas.MsgTypePDUSessionModificationCommandReject:
			return HandlePDUSessionModificationForward(ue, anType, ulNasTransport.PayloadContainer.Buffer, pduSessionId)
		case nas.MsgTypePDUSessionReleaseRequest,
			nas.MsgTypePDUSessionReleaseComplete,
			nas.MsgTypePDUSessionReleaseReject:
			return HandlePDUSessionReleaseForward(ue, anType, ulNasTransport.PayloadContainer.Buffer, pduSessionId, messageType)
		case nas.MsgTypePDUSessionAuthenticationComplete:
			return HandlePDUSessionAuthenticationForward(ue, anType,
				ulNasTransport.PayloadContainer.GetPayloadContainerContents(), pduSessionId)
		case nas.MsgTypeStatus5GSM:
			return HandleStatus5GSM(ue, anType, ulNasTransport.PayloadContainer.Buffer, pduSessionId)
		}
	case nasMessage.PayloadContainerTypeSMS:
		return fmt.Errorf("PayloadContainerTypeSMS has not been implemented yet in UL NAS TRANSPORT")
	case nasMessage.PayloadContainerTypeLPP:
		return fmt.Errorf("PayloadContainerTypeLPP has not been implemented yet in UL NAS TRANSPORT")
	case nasMessage.PayloadContainerTypeSOR:
		return fmt.Errorf("PayloadContainerTypeSOR has not been implemented yet in UL NAS TRANSPORT")
	case nasMessage.PayloadContainerTypeUEPolicy:
		logger.GmmLog.Infoln("AMF Transfer UEPolicy To PCF")
		callback.SendN1MessageNotify(ue, models.N1MessageClass_UPDP,
			ulNasTransport.PayloadContainer.GetPayloadContainerContents(), nil)
	case nasMessage.PayloadContainerTypeUEParameterUpdate:
		logger.GmmLog.Infoln("AMF Transfer UEParameterUpdate To UDM")
		upuMac, err := nasConvert.UpuAckToModels(ulNasTransport.PayloadContainer.GetPayloadContainerContents())
		if err != nil {
			return err
		}
		err = consumer.PutUpuAck(ue, upuMac)
		if err != nil {
			return err
		}
		logger.GmmLog.Debugf("UpuMac[%s] in UPU ACK NAS Msg", upuMac)
	case nasMessage.PayloadContainerTypeMultiplePayload:
		return fmt.Errorf("PayloadContainerTypeMultiplePayload has not been implemented yet in UL NAS TRANSPORT")
	}
	return nil
}

func HandlePDUSessionEstablishmentRequest(ue *context.AmfUe, anType models.AccessType, payload []byte,
	pduSessionID int32, requestType models.RequestType, sNssai *models.Snssai, dnn string) error {

	logger.GmmLog.Infoln("[AMF] Handle PDU Session Establishment Request")
	// TODO Request Type Emergency requset
	var pduSession models.PduSessionContext
	pduSession.PduSessionId = pduSessionID
	pduSession.AccessType = anType
	amfSelf := context.AMF_Self()
	if requestType == models.RequestType_INITIAL_REQUEST {

		if sNssai == nil {
			if ue.SmfSelectionData != nil {
				for snssai, sNssaiInfo := range ue.SmfSelectionData.SubscribedSnssaiInfos {
					var err error
					sNssai, err = util.SnssaiHexToModels(snssai)
					if err != nil {
						return err
					}
					if dnn == "" {
						for _, dnnInfo := range sNssaiInfo.DnnInfos {
							if dnnInfo.DefaultDnnIndicator {
								dnn = dnnInfo.Dnn
								break
							}
						}
					}
				}
			}
			if sNssai == nil {
				allowedNssai := ue.AllowedNssai[anType]
				if len(allowedNssai) > 0 {
					sNssai = allowedNssai[0].AllowedSnssai
				} else {
					err := fmt.Errorf("Ue[%s] doesn't have allowedNssai\n", ue.Supi)
					logger.GmmLog.Errorf(err.Error())
					return err
				}
			}

		}
		pduSession.SNssai = sNssai
		if dnn == "" {
			// default DNN decided by AMF
			dnn = amfSelf.SupportDnnLists[0]
		}
		pduSession.Dnn = dnn

		var smfID, smfUri string
		if smfIDTmp, smfUriTmp, err := selectSmf(ue, anType, &pduSession, payload); err != nil {
			logger.GmmLog.Errorf("[AMF] SMF Selection for Snssai[%+v] Failed[%+v]", sNssai, err)
			return err
		} else {
			smfID = smfIDTmp
			smfUri = smfUriTmp
		}

		// Store PduSessionContext For duplicated PDU Session Id
		if smContext, ok := ue.SmContextList[pduSessionID]; ok {
			ue.StoredSmContext[pduSessionID] = &context.StoredSmContext{
				SmfId:             smfID,
				SmfUri:            smfUri,
				PduSessionContext: &pduSession,
				AnType:            anType,
				Payload:           payload,
			}
			updateData := models.SmContextUpdateData{
				Release: true,
				Cause:   models.Cause_REL_DUE_TO_DUPLICATE_SESSION_ID,
				SmContextStatusUri: fmt.Sprintf("%s/namf-callback/v1/smContextStatus/%s/%d",
					amfSelf.GetIPv4Uri(), ue.Guti, pduSessionID),
			}
			logger.GmmLog.Warningln("Duplicated PDU session ID")
			response, _, _, err := consumer.SendUpdateSmContextRequest(ue, smContext.SmfUri,
				smContext.PduSessionContext.SmContextRef, updateData, nil, nil)
			if err != nil {
				return err
			} else if response == nil {
				err := fmt.Errorf("PDU Session ID[%d] can't be released in DUPLICATE_SESSION_ID case", pduSessionID)
				logger.GmmLog.Errorln(err)
				gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeN1SMInfo,
					payload, pduSessionID, nasMessage.Cause5GMMPayloadWasNotForwarded, nil, 0)
			} else if response != nil {
				smContext.UserLocation = ue.Location
				responseData := response.JsonData
				n2Info := response.BinaryDataN2SmInformation
				if n2Info != nil {
					switch responseData.N2SmInfoType {
					case models.N2SmInfoType_PDU_RES_REL_CMD:
						logger.GmmLog.Debugln("AMF Transfer NGAP PDU Session Resource Release Command from SMF")
						list := ngapType.PDUSessionResourceToReleaseListRelCmd{}
						ngap_message.AppendPDUSessionResourceToReleaseListRelCmd(&list, pduSessionID, n2Info)
						ngap_message.SendPDUSessionResourceReleaseCommand(ue.RanUe[anType], nil, list)
					}
				}
			}
			return nil
		}

		smContextCreateData := consumer.BuildCreateSmContextRequest(ue, pduSession, requestType)

		response, smContextRef, errResponse, problemDetail, err :=
			consumer.SendCreateSmContextRequest(ue, smfUri, payload, smContextCreateData)
		if response != nil {
			var smContext context.SmContext
			pduSession.SmContextRef = smContextRef
			logger.GmmLog.Infof("smconetxt ef : %s", smContextRef)

			smContext.PduSessionContext = &pduSession
			smContext.UserLocation = deepcopy.Copy(ue.Location).(models.UserLocation)
			smContext.SmfUri = smfUri
			smContext.SmfId = smfID
			ue.SmContextList[pduSession.PduSessionId] = &smContext
			logger.GmmLog.Infof("Http create smContext[pduSessionID: %d] Success", pduSession.PduSessionId)
			// TODO: handle response(response N2SmInfo to RAN if exists)
		} else if errResponse != nil {
			logger.GmmLog.Warnf("PDU Session Establishment Request is rejected by SMF[pduSessionId:%d]\n",
				pduSession.PduSessionId)
			gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeN1SMInfo,
				errResponse.BinaryDataN1SmMessage, pduSessionID, 0, nil, 0)
		} else if err != nil {
			return err
		} else {
			// TODO: error handling
			return fmt.Errorf("Failed to Create smContext[pduSessionID: %d], Error[%v]", pduSessionID, problemDetail)
		}
	} else if requestType == models.RequestType_EXISTING_PDU_SESSION {
		smContext, ok := ue.SmContextList[pduSessionID]
		if !ok {
			gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeN1SMInfo,
				payload, pduSessionID, nasMessage.Cause5GMMPayloadWasNotForwarded, nil, 0)
			return fmt.Errorf("PDU Session ID[%d] dose not exist for request Type [%s]", pduSessionID, requestType)
		}
		// TODO: Compare Smfid PLMN with AMF
		if smContext.SmfId == "" {
			err := fmt.Errorf("PDU Session ID[%d] correspond SMF-ID does not exist\n", pduSessionID)
			logger.GmmLog.Errorf(err.Error())
			gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeN1SMInfo,
				payload, pduSessionID, nasMessage.Cause5GMMPayloadWasNotForwarded, nil, 0)
			return err
		}
		targetAccessType := models.AccessType__3_GPP_ACCESS
		if anType == models.AccessType__3_GPP_ACCESS {
			targetAccessType = models.AccessType_NON_3_GPP_ACCESS
		}
		if !ue.InAllowedNssai(*smContext.PduSessionContext.SNssai, targetAccessType) {
			gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeN1SMInfo,
				payload, pduSessionID, nasMessage.Cause5GMMPayloadWasNotForwarded, nil, 0)
			return fmt.Errorf("S-NSSAI[%v] is not present in the Allowed NSSAI of target Access",
				*smContext.PduSessionContext.SNssai)
		}

		response, errResponse, problemDetail, err := consumer.SendUpdateSmContextHandoverBetweenAccessType(ue, pduSessionID,
			targetAccessType, payload)
		if response != nil {
			smContext.PduSessionContext.AccessType = targetAccessType
			logger.GmmLog.Infof("Success update smContext Handover Between AccessType[pduSessionID: %d]", pduSessionID)
			// TODO: handle response(response N2SmInfo to RAN if exists)
		} else if errResponse != nil {
			logger.GmmLog.Warnf("PDU Session Establishment Request is rejected by SMF[pduSessionId:%d]", pduSession.PduSessionId)
			if errResponse.BinaryDataN1SmMessage != nil {
				gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeN1SMInfo,
					errResponse.BinaryDataN1SmMessage, pduSessionID, 0, nil, 0)
			}
		} else if err != nil {
			return err
		} else {
			// TODO: error handling
			logger.GmmLog.Errorf("Failed to Create smContext[pduSessionID: %d], Error[%v]\n", pduSessionID, problemDetail)
			return nil
		}
	} else {
		return fmt.Errorf("RequestType INITIAL_EMERGENCY_REQUEST and EXISTING_EMERGENCY_PDU_SESSION haven't been supported")
	}
	return nil
}

func selectSmf(ue *context.AmfUe, anType models.AccessType, pduSession *models.PduSessionContext,
	payload []byte) (string, string, error) {

	var smfID string
	var smfUri string

	amfSelf := context.AMF_Self()
	nrfUri := amfSelf.NrfUri // default NRF URI is pre-configured by AMF

	nsiInformation := ue.GetNsiInformationFromSnssai(anType, *pduSession.SNssai)
	if nsiInformation == nil {
		if ue.NssfUri == "" {
			// TODO: Set a timeout of NSSF Selection or will starvation here
			for {
				if err := consumer.SearchNssfNSSelectionInstance(ue, amfSelf.NrfUri, models.NfType_NSSF,
					models.NfType_AMF, nil); err != nil {
					logger.GmmLog.Errorf("AMF can not select an NSSF Instance by NRF[Error: %+v]", err)
					time.Sleep(2 * time.Second)
				} else {
					break
				}
			}
		}

		response, problemDetails, err := consumer.NSSelectionGetForPduSession(ue, *pduSession.SNssai)
		if problemDetails != nil {
			logger.GmmLog.Errorf("NSSelection Get Failed Problem[%+v]", problemDetails)
			err = errors.New("NSSelection Get Failed Problem")
			return "", "", err
		}
		if err != nil {
			logger.GmmLog.Errorf("NSSelection Get Error[%+v]", err)
			return "", "", err
		}
		nsiInformation = response.NsiInformation
	}

	pduSession.NsInstance = nsiInformation.NsiId
	nrfApiUrl, err := url.Parse(nsiInformation.NrfId)
	if err != nil {
		logger.GmmLog.Errorf("Parse NRF URI error, use default NRF[%s]", nrfUri)
	} else {
		nrfUri = fmt.Sprintf("%s://%s", nrfApiUrl.Scheme, nrfApiUrl.Host)
	}

	param := Nnrf_NFDiscovery.SearchNFInstancesParamOpts{
		ServiceNames: optional.NewInterface([]models.ServiceName{models.ServiceName_NSMF_PDUSESSION}),
		Dnn:          optional.NewString(pduSession.Dnn),
		Snssais:      optional.NewInterface(util.MarshToJsonString([]models.Snssai{*pduSession.SNssai})),
	}
	if ue.PlmnId.Mcc != "" {
		param.TargetPlmnList = optional.NewInterface(util.MarshToJsonString(ue.PlmnId))
	}

	logger.GmmLog.Debugf("Search SMF from NRF[%s]", nrfUri)

	result, err := consumer.SendSearchNFInstances(nrfUri, models.NfType_SMF, models.NfType_AMF, &param)

	if err != nil || len(result.NfInstances) == 0 {
		logger.GmmLog.Errorln("number of result.NfInstances :", len(result.NfInstances))
		err = fmt.Errorf("DNN[%s] is not support by network and AMF can not select an SMF by NRF\n", pduSession.Dnn)
		logger.GmmLog.Errorf(err.Error())
		gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeN1SMInfo,
			payload, pduSession.PduSessionId, nasMessage.Cause5GMMDNNNotSupportedOrNotSubscribedInTheSlice, nil, 0)
		return "", "", err
	}

	// select the first SMF, TODO: select base on other info
	for _, nfProfile := range result.NfInstances {
		smfUri = util.SearchNFServiceUri(nfProfile, models.ServiceName_NSMF_PDUSESSION, models.NfServiceStatus_REGISTERED)
		if smfUri != "" {
			break
		}
	}
	return smfID, smfUri, nil
}

func HandlePDUSessionModificationForward(ue *context.AmfUe, anType models.AccessType, payload []byte,
	pduSessionID int32) error {

	logger.GmmLog.Infoln("[AMF] Handle PDU Session Modification Request")

	smContext, ok := ue.SmContextList[pduSessionID]
	if !ok {
		err := fmt.Errorf("PDU Session ID[%d] in PDU Session Modification Procedure is not exist\n", pduSessionID)
		logger.GmmLog.Errorf(err.Error())
		gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeN1SMInfo, payload,
			pduSessionID, nasMessage.Cause5GMMPayloadWasNotForwarded, nil, 0)
		return err
	}
	smContextUpdateData := models.SmContextUpdateData{
		N1SmMsg: &models.RefToBinaryData{
			ContentId: "N1SmMsg",
		},
	}
	smContextUpdateData.Pei = ue.Pei
	smContextUpdateData.Gpsi = ue.Gpsi
	if !context.CompareUserLocation(ue.Location, smContext.UserLocation) {
		smContextUpdateData.UeLocation = &ue.Location
	}
	response, errResponse, problemDetail, err := consumer.SendUpdateSmContextRequest(ue, smContext.SmfUri,
		smContext.PduSessionContext.SmContextRef, smContextUpdateData, payload, nil)
	if response != nil {
		smContext.UserLocation = ue.Location
		responseData := response.JsonData
		n1Msg := response.BinaryDataN1SmMessage
		n2Info := response.BinaryDataN2SmInformation
		if n2Info != nil {
			switch responseData.N2SmInfoType {
			case models.N2SmInfoType_PDU_RES_MOD_REQ:
				logger.GmmLog.Infoln("AMF Transfer NGAP PDU Resource Modify Req from SMF")
				var nasPdu []byte
				if n1Msg != nil {
					pduSessionId := uint8(pduSessionID)
					nasPdu, err = gmm_message.BuildDLNASTransport(ue, nasMessage.PayloadContainerTypeN1SMInfo,
						n1Msg, pduSessionId, nil, nil, 0)
					if err != nil {
						return err
					}
				}
				list := ngapType.PDUSessionResourceModifyListModReq{}
				ngap_message.AppendPDUSessionResourceModifyListModReq(&list, pduSessionID, nasPdu, n2Info)
				ngap_message.SendPDUSessionResourceModifyRequest(ue.RanUe[anType], list)
			}
		} else if n1Msg != nil {
			logger.GmmLog.Infoln("AMF tansfer Only N1 PDU Session Modification Msg to UE")
			gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeN1SMInfo,
				errResponse.BinaryDataN1SmMessage, pduSessionID, 0, nil, 0)
		}
	} else if errResponse != nil {
		errJSON := errResponse.JsonData
		n1Msg := errResponse.BinaryDataN1SmMessage
		logger.GmmLog.Warnf("PDU Session Modification Procedure is rejected by SMF[pduSessionId:%d], Error[%s]",
			pduSessionID, errJSON.Error.Cause)
		if n1Msg != nil {
			gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeN1SMInfo,
				errResponse.BinaryDataN1SmMessage, pduSessionID, 0, nil, 0)
		}
		// TODO: handle n2 info transfer
	} else if err != nil {
		return err
	} else {
		// TODO: error handling
		err := fmt.Errorf("Failed to Update smContext[pduSessionID: %d], Error[%v]", pduSessionID, problemDetail)
		logger.GmmLog.Errorf(err.Error())
		return err
	}

	return nil
}

func HandlePDUSessionReleaseForward(ue *context.AmfUe, anType models.AccessType, payload []byte,
	pduSessionID int32, gsmMessageType uint8) error {

	switch gsmMessageType {
	case nas.MsgTypePDUSessionReleaseRequest:
		logger.GmmLog.Infof("Handle PDU Session Release Request")
	case nas.MsgTypePDUSessionReleaseComplete:
		logger.GmmLog.Infof("Handle PDU Session Release Complete")
	case nas.MsgTypePDUSessionReleaseReject:
		logger.GmmLog.Infof("Handle PDU Session Release Reject")
	}

	smContext, ok := ue.SmContextList[pduSessionID]
	if !ok {
		err := fmt.Errorf("PDU Session ID[%d] does not exist\n", pduSessionID)
		logger.GmmLog.Errorf(err.Error())
		gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeN1SMInfo, payload,
			pduSessionID, nasMessage.Cause5GMMPayloadWasNotForwarded, nil, 0)
		return err
	}
	smContextUpdateData := models.SmContextUpdateData{
		N1SmMsg: &models.RefToBinaryData{
			ContentId: "N1SmMsg",
		},
	}
	smContextUpdateData.UeLocation = &ue.Location
	response, errResponse, problemDetail, err := consumer.SendUpdateSmContextRequest(ue, smContext.SmfUri,
		smContext.PduSessionContext.SmContextRef, smContextUpdateData, payload, nil)
	if response != nil {
		smContext.UserLocation = ue.Location
		responseData := response.JsonData
		n1Msg := response.BinaryDataN1SmMessage
		n2Info := response.BinaryDataN2SmInformation
		if n2Info != nil {
			switch responseData.N2SmInfoType {
			case models.N2SmInfoType_PDU_RES_REL_CMD:
				logger.GmmLog.Debugln("AMF Transfer NGAP PDU Session Resource Release Command from SMF")
				var nasPdu []byte
				if n1Msg != nil {
					pduSessionId := uint8(pduSessionID)
					nasPdu, err = gmm_message.BuildDLNASTransport(ue, nasMessage.PayloadContainerTypeN1SMInfo,
						n1Msg, pduSessionId, nil, nil, 0)
					if err != nil {
						return err
					}
				}
				list := ngapType.PDUSessionResourceToReleaseListRelCmd{}
				ngap_message.AppendPDUSessionResourceToReleaseListRelCmd(&list, pduSessionID, n2Info)
				ngap_message.SendPDUSessionResourceReleaseCommand(ue.RanUe[anType], nasPdu, list)
			}
		} else if n1Msg != nil {
			logger.GmmLog.Debugln("AMF tansfer Only N1 PDU Session Release Msg to UE")
			gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeN1SMInfo,
				n1Msg, pduSessionID, 0, nil, 0)
		}
	} else if errResponse != nil {
		errJSON := errResponse.JsonData
		n1Msg := errResponse.BinaryDataN1SmMessage
		logger.GmmLog.Warnf("PDU Session Release Procedure is rejected by SMF[pduSessionId:%d], Error[%s]",
			pduSessionID, errJSON.Error.Cause)
		if n1Msg != nil {
			gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeN1SMInfo,
				errResponse.BinaryDataN1SmMessage, pduSessionID, 0, nil, 0)
		}
	} else if err != nil {
		return err
	} else {
		// TODO: error handling
		err := fmt.Errorf("Failed to Update smContext[pduSessionID: %d], Error[%v]", pduSessionID, problemDetail)
		logger.GmmLog.Errorf(err.Error())
		return err
	}
	return nil
}

func HandlePDUSessionAuthenticationForward(ue *context.AmfUe, anType models.AccessType,
	payload []byte, pduSessionID int32) error {

	smContext, ok := ue.SmContextList[pduSessionID]
	if !ok {
		err := fmt.Errorf("PDU Session ID[%d] in PDU Session Authentication Complete is not exist\n", pduSessionID)
		logger.GmmLog.Errorf(err.Error())
		gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeN1SMInfo, payload,
			pduSessionID, nasMessage.Cause5GMMPayloadWasNotForwarded, nil, 0)
		return err
	}
	smContextUpdateData := models.SmContextUpdateData{
		N1SmMsg: &models.RefToBinaryData{
			ContentId: "N1SmMsg",
		},
	}
	response, errResponse, problemDetail, err := consumer.SendUpdateSmContextRequest(ue, smContext.SmfUri,
		smContext.PduSessionContext.SmContextRef, smContextUpdateData, payload, nil)
	if response != nil {
		logger.GmmLog.Infoln("AMF tansfer PDU Session Authentication Complete to SMF Success")
	} else if errResponse != nil {
		errJSON := errResponse.JsonData
		n1Msg := errResponse.BinaryDataN1SmMessage
		logger.GmmLog.Warnf("PDU Session Authentication Complete is rejected by SMF[pduSessionId:%d], Error[%s]",
			pduSessionID, errJSON.Error.Cause)
		if n1Msg != nil {
			gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeN1SMInfo,
				errResponse.BinaryDataN1SmMessage, pduSessionID, 0, nil, 0)
		}
	} else if err != nil {
		return err
	} else {
		// TODO: error handling
		err := fmt.Errorf("Failed to Update smContext[pduSessionID: %d], Error[%v]", pduSessionID, problemDetail)
		logger.GmmLog.Errorf(err.Error())
		return err
	}
	return nil
}

// Handle cleartext IEs of Registration Request, which cleattext IEs defined in TS 24.501 4.4.6
func HandleRegistrationRequest(ue *context.AmfUe, anType models.AccessType, procedureCode int64,
	registrationRequest *nasMessage.RegistrationRequest) error {

	logger.GmmLog.Info("[AMF] Handle Registration Request")

	util.StopT3513(ue)
	util.StopT3565(ue)

	var guamiFromUeGuti models.Guami
	amfSelf := context.AMF_Self()

	if ue == nil {
		return fmt.Errorf("AmfUe is nil")
	}

	if ue.RanUe[anType] == nil {
		return fmt.Errorf("RanUe is nil")
	}

	// TS 24.501 8.2.6.21: if the UE is sending a REGISTRATION REQUEST message as an initial NAS message,
	// the UE has a valid 5G NAS security context and the UE needs to send non-cleartext IEs
	// TS 24.501 4.4.6: When the UE sends a REGISTRATION REQUEST or SERVICE REQUEST message that includes a NAS message
	// container IE, the UE shall set the security header type of the initial NAS message to "integrity protected"
	if registrationRequest.NASMessageContainer != nil {
		contents := registrationRequest.NASMessageContainer.GetNASMessageContainerContents()

		// TS 24.501 4.4.6: When the UE sends a REGISTRATION REQUEST or SERVICE REQUEST message that includes a NAS
		// message container IE, the UE shall set the security header type of the initial NAS message to
		// "integrity protected"; then the AMF shall decipher the value part of the NAS message container IE
		err := security.NASEncrypt(ue.CipheringAlg, ue.KnasEnc, ue.ULCount.Get(), security.Bearer3GPP,
			security.DirectionUplink, contents)
		if err != nil {
			ue.SecurityContextAvailable = false
		} else {
			m := nas.NewMessage()
			if err := m.GmmMessageDecode(&contents); err != nil {
				return err
			}

			messageType := m.GmmMessage.GmmHeader.GetMessageType()
			if messageType != nas.MsgTypeRegistrationRequest {
				return errors.New("The payload of NAS Message Container is not Registration Request")
			}
			// TS 24.501 4.4.6: The AMF shall consider the NAS message that is obtained from the NAS message container
			// IE as the initial NAS message that triggered the procedure
			registrationRequest = m.RegistrationRequest
		}
		// TS 33.501 6.4.6 step 3: if the initial NAS message was protected but did not pass the integrity check
		ue.RetransmissionOfInitialNASMsg = ue.MacFailed
	}

	ue.RegistrationRequest = registrationRequest
	ue.RegistrationType5GS = registrationRequest.NgksiAndRegistrationType5GS.GetRegistrationType5GS()
	switch ue.RegistrationType5GS {
	case nasMessage.RegistrationType5GSInitialRegistration:
		logger.GmmLog.Debugf("RegistrationType: Initial Registration")
	case nasMessage.RegistrationType5GSMobilityRegistrationUpdating:
		logger.GmmLog.Debugf("RegistrationType: Mobility Registration Updating")
	case nasMessage.RegistrationType5GSPeriodicRegistrationUpdating:
		logger.GmmLog.Debugf("RegistrationType: Periodic Registration Updating")
	case nasMessage.RegistrationType5GSEmergencyRegistration:
		return fmt.Errorf("Not Supportted RegistrationType: Emergency Registration")
	case nasMessage.RegistrationType5GSReserved:
		ue.RegistrationType5GS = nasMessage.RegistrationType5GSInitialRegistration
		logger.GmmLog.Debugf("RegistrationType: Reserved")
	default:
		logger.GmmLog.Debugf("RegistrationType: %v, chage state to InitialRegistration", ue.RegistrationType5GS)
		ue.RegistrationType5GS = nasMessage.RegistrationType5GSInitialRegistration
	}

	mobileIdentity5GSContents := registrationRequest.MobileIdentity5GS.GetMobileIdentity5GSContents()
	ue.IdentityTypeUsedForRegistration = nasConvert.GetTypeOfIdentity(mobileIdentity5GSContents[0])
	switch ue.IdentityTypeUsedForRegistration { // get type of identity
	case nasMessage.MobileIdentity5GSTypeNoIdentity:
		logger.GmmLog.Debugf("No Identity")
	case nasMessage.MobileIdentity5GSTypeSuci:
		var plmnId string
		ue.Suci, plmnId = nasConvert.SuciToString(mobileIdentity5GSContents)
		ue.PlmnId = util.PlmnIdStringToModels(plmnId)
		logger.GmmLog.Debugf("SUCI: %s", ue.Suci)
	case nasMessage.MobileIdentity5GSType5gGuti:
		guamiFromUeGutiTmp, guti := nasConvert.GutiToString(mobileIdentity5GSContents)
		guamiFromUeGuti = guamiFromUeGutiTmp
		ue.Guti = guti
		logger.GmmLog.Debugf("GUTI: %s", guti)

		servedGuami := amfSelf.ServedGuamiList[0]
		if reflect.DeepEqual(guamiFromUeGuti, servedGuami) {
			ue.ServingAmfChanged = false
		} else {
			logger.GmmLog.Debugf("Serving AMF has changed")
			ue.ServingAmfChanged = true
		}
	case nasMessage.MobileIdentity5GSTypeImei:
		imei := nasConvert.PeiToString(mobileIdentity5GSContents)
		ue.Pei = imei
		logger.GmmLog.Debugf("PEI: %s", imei)
	case nasMessage.MobileIdentity5GSTypeImeisv:
		imeisv := nasConvert.PeiToString(mobileIdentity5GSContents)
		ue.Pei = imeisv
		logger.GmmLog.Debugf("PEI: %s", imeisv)
	}

	// NgKsi: TS 24.501 9.11.3.32
	switch registrationRequest.NgksiAndRegistrationType5GS.GetTSC() {
	case nasMessage.TypeOfSecurityContextFlagNative:
		ue.NgKsi.Tsc = models.ScType_NATIVE
	case nasMessage.TypeOfSecurityContextFlagMapped:
		ue.NgKsi.Tsc = models.ScType_MAPPED
	}
	ue.NgKsi.Ksi = int32(registrationRequest.NgksiAndRegistrationType5GS.GetNasKeySetIdentifiler())
	if ue.NgKsi.Tsc == models.ScType_NATIVE && ue.NgKsi.Ksi != 7 {

	} else {
		ue.NgKsi.Tsc = models.ScType_NATIVE
		ue.NgKsi.Ksi = 0
	}

	// Copy UserLocation from ranUe
	ue.Location = ue.RanUe[anType].Location
	ue.Tai = ue.RanUe[anType].Tai

	// Check TAI
	if !context.InTaiList(ue.Tai, amfSelf.SupportTaiLists) {
		gmm_message.SendRegistrationReject(ue.RanUe[anType], nasMessage.Cause5GMMTrackingAreaNotAllowed, "")
		return fmt.Errorf("Registration Reject[Tracking area not allowed]")
	}

	if registrationRequest.UESecurityCapability != nil {
		ue.UESecurityCapability = *registrationRequest.UESecurityCapability
	} else {
		gmm_message.SendRegistrationReject(ue.RanUe[anType], nasMessage.Cause5GMMProtocolErrorUnspecified, "")
		return fmt.Errorf("UESecurityCapability is nil")
	}

	// TODO (TS 23.502 4.2.2.2 step 4): if UE's 5g-GUTI is included & serving AMF has changed
	// since last registration procedure, new AMF may invoke Namf_Communication_UEContextTransfer
	// to old AMF, including the complete registration request nas msg, to request UE's SUPI & UE Context
	if ue.ServingAmfChanged {
		var transferReason models.TransferReason
		switch ue.RegistrationType5GS {
		case nasMessage.RegistrationType5GSInitialRegistration:
			transferReason = models.TransferReason_INIT_REG
		case nasMessage.RegistrationType5GSMobilityRegistrationUpdating:
			fallthrough
		case nasMessage.RegistrationType5GSPeriodicRegistrationUpdating:
			transferReason = models.TransferReason_MOBI_REG
		}

		searchOpt := Nnrf_NFDiscovery.SearchNFInstancesParamOpts{
			Guami: optional.NewInterface(guamiFromUeGuti),
		}
		err := consumer.SearchAmfCommunicationInstance(ue, amfSelf.NrfUri, models.NfType_AMF, models.NfType_AMF, &searchOpt)
		if err != nil {
			logger.GmmLog.Errorf("[GMM] %+v", err)
			return err
		}

		ueContextTransferRspData, problemDetails, err := consumer.UEContextTransferRequest(ue, anType, transferReason)
		if problemDetails != nil {
			if problemDetails.Cause == "INTEGRITY_CHECK_FAIL" || problemDetails.Cause == "CONTEXT_NOT_FOUND" {
				logger.GmmLog.Warnf("Can not retrive UE Context from old AMF[Cause: %s]", problemDetails.Cause)
			} else {
				logger.GmmLog.Warnf("UE Context Transfer Request Failed Problem[%+v]", problemDetails)
			}
			ue.SecurityContextAvailable = false // need to start authentication procedure later
		} else if err != nil {
			logger.GmmLog.Errorf("UE Context Transfer Request Error[%+v]", err)
		} else {
			ue.CopyDataFromUeContextModel(*ueContextTransferRspData.UeContext)
		}
	}
	return nil
}

func IdentityVerification(ue *context.AmfUe) bool {
	return ue.Supi != "" || len(ue.Suci) != 0
}

func HandleInitialRegistration(ue *context.AmfUe, anType models.AccessType) error {
	logger.GmmLog.Infoln("[AMF] Handle InitialRegistration")

	amfSelf := context.AMF_Self()

	// update Kgnb/Kn3iwf
	ue.UpdateSecurityContext(anType)

	// Registration with AMF re-allocation (TS 23.502 4.2.2.2.3)
	if len(ue.SubscribedNssai) == 0 {
		getSubscribedNssai(ue)
	}

	if err := handleRequestedNssai(ue, anType); err != nil {
		return err
	}

	if ue.RegistrationRequest.Capability5GMM != nil {
		ue.Capability5GMM = *ue.RegistrationRequest.Capability5GMM
	} else {
		gmm_message.SendRegistrationReject(ue.RanUe[anType], nasMessage.Cause5GMMProtocolErrorUnspecified, "")
		return fmt.Errorf("Capability5GMM is nil")
	}

	storeLastVisitedRegisteredTAI(ue, ue.RegistrationRequest.LastVisitedRegisteredTAI)

	if ue.RegistrationRequest.MICOIndication != nil {
		logger.GmmLog.Warnf("Receive MICO Indication[RAAI: %d], Not Supported",
			ue.RegistrationRequest.MICOIndication.GetRAAI())
	}

	// TODO: Negotiate DRX value if need (TS 23.501 5.4.5)
	negotiateDRXParameters(ue, ue.RegistrationRequest.RequestedDRXParameters)

	// TODO (step 10 optional): send Namf_Communication_RegistrationCompleteNotify to old AMF if need
	if ue.ServingAmfChanged {
		// If the AMF has changed the new AMF notifies the old AMF that the registration of the UE in the new AMF is completed
		req := models.UeRegStatusUpdateReqData{
			TransferStatus: models.UeContextTransferStatus_TRANSFERRED,
		}
		// TODO: based on locol policy, decide if need to change serving PCF for UE
		regStatusTransferComplete, problemDetails, err := consumer.RegistrationStatusUpdate(ue, req)
		if problemDetails != nil {
			logger.GmmLog.Errorf("Registration Status Update Failed Problem[%+v]", problemDetails)
		} else if err != nil {
			logger.GmmLog.Errorf("Registration Status Update Error[%+v]", err)
		} else {
			if regStatusTransferComplete {
				logger.GmmLog.Infof("[AMF] Registration Status Transfer complete")
			}
		}
	}

	if len(ue.Pei) == 0 {
		gmm_message.SendIdentityRequest(ue.RanUe[anType], nasMessage.MobileIdentity5GSTypeImei)
		return nil
	}

	// TODO (step 12 optional): the new AMF initiates ME identity check by invoking the
	// N5g-eir_EquipmentIdentityCheck_Get service operation

	if ue.ServingAmfChanged || ue.State[models.AccessType_NON_3_GPP_ACCESS].Is(context.Registered) ||
		!ue.ContextValid {
		if err := communicateWithUDM(ue, anType); err != nil {
			return err
		}
	}

	param := Nnrf_NFDiscovery.SearchNFInstancesParamOpts{
		Supi: optional.NewString(ue.Supi),
	}
	for {
		resp, err := consumer.SendSearchNFInstances(amfSelf.NrfUri, models.NfType_PCF, models.NfType_AMF, &param)
		if err != nil {
			logger.GmmLog.Error("AMF can not select an PCF by NRF")
		} else {
			// select the first PCF, TODO: select base on other info
			var pcfUri string
			for _, nfProfile := range resp.NfInstances {
				pcfUri = util.SearchNFServiceUri(nfProfile, models.ServiceName_NPCF_AM_POLICY_CONTROL,
					models.NfServiceStatus_REGISTERED)
				if pcfUri != "" {
					ue.PcfId = nfProfile.NfInstanceId
					break
				}
			}
			if ue.PcfUri = pcfUri; ue.PcfUri == "" {
				logger.GmmLog.Error("AMF can not select an PCF by NRF")
			} else {
				break
			}
		}
		time.Sleep(500 * time.Millisecond) // sleep a while when search NF Instance fail
	}

	problemDetails, err := consumer.AMPolicyControlCreate(ue, anType)
	if problemDetails != nil {
		logger.GmmLog.Errorf("AM Policy Control Create Failed Problem[%+v]", problemDetails)
	} else if err != nil {
		logger.GmmLog.Errorf("AM Policy Control Create Error[%+v]", err)
	}

	// Service Area Restriction are applicable only to 3GPP access
	if anType == models.AccessType__3_GPP_ACCESS {
		if ue.AmPolicyAssociation != nil && ue.AmPolicyAssociation.ServAreaRes != nil {
			servAreaRes := ue.AmPolicyAssociation.ServAreaRes
			if servAreaRes.RestrictionType == models.RestrictionType_ALLOWED_AREAS {
				numOfallowedTAs := 0
				for _, area := range servAreaRes.Areas {
					numOfallowedTAs += len(area.Tacs)
				}
				// if numOfallowedTAs < int(servAreaRes.MaxNumOfTAs) {
				// 	TODO: based on AMF Policy, assign additional allowed area for UE,
				// 	and the upper limit is servAreaRes.MaxNumOfTAs (TS 29.507 4.2.2.3)
				// }
			}
		}
	}

	// TODO (step 18 optional):
	// If the AMF has changed and the old AMF has indicated an existing NGAP UE association towards a N3IWF, the new AMF
	// creates an NGAP UE association towards the N3IWF to which the UE is connectedsend N2 AMF mobility request to N3IWF
	// if anType == models.AccessType_NON_3_GPP_ACCESS && ue.ServingAmfChanged {
	// 	TODO: send N2 AMF Mobility Request
	// }

	amfSelf.AllocateRegistrationArea(ue, anType)
	logger.GmmLog.Debugf("Use original GUTI[%s]", ue.Guti)

	assignLadnInfo(ue, anType)

	amfSelf.AddAmfUeToUePool(ue, ue.Supi)
	ue.T3502Value = amfSelf.T3502Value
	if anType == models.AccessType__3_GPP_ACCESS {
		ue.T3512Value = amfSelf.T3512Value
	} else {
		ue.Non3gppDeregistrationTimerValue = amfSelf.Non3gppDeregistrationTimerValue
	}

	if anType == models.AccessType__3_GPP_ACCESS {
		gmm_message.SendRegistrationAccept(ue, anType, nil, nil, nil, nil, nil)
	} else {
		// TS 23.502 4.12.2.2 10a ~ 13: if non-3gpp, AMF should send initial context setup request to N3IWF first,
		// and send registration accept after receiving initial context setup response
		ngap_message.SendInitialContextSetupRequest(ue, anType, nil, nil, nil, nil, nil)

		registrationAccept, err := gmm_message.BuildRegistrationAccept(ue, anType, nil, nil, nil, nil)
		if err != nil {
			logger.GmmLog.Errorf("Build Registration Accept: %+v", err)
			return nil
		}
		ue.RegistrationAcceptForNon3GPPAccess = registrationAccept
	}
	return nil
}

func HandleMobilityAndPeriodicRegistrationUpdating(ue *context.AmfUe, anType models.AccessType) error {
	logger.GmmLog.Infoln("[AMF] Handle MobilityAndPeriodicRegistrationUpdating")

	amfSelf := context.AMF_Self()

	if ue.RegistrationRequest.UpdateType5GS != nil {
		if ue.RegistrationRequest.UpdateType5GS.GetNGRanRcu() == nasMessage.NGRanRadioCapabilityUpdateNeeded {
			ue.UeRadioCapability = ""
			ue.UeRadioCapabilityForPaging = nil
		}
	}

	// Registration with AMF re-allocation (TS 23.502 4.2.2.2.3)
	if len(ue.SubscribedNssai) == 0 {
		getSubscribedNssai(ue)
	}

	if err := handleRequestedNssai(ue, anType); err != nil {
		return err
	}

	if ue.RegistrationRequest.Capability5GMM != nil {
		ue.Capability5GMM = *ue.RegistrationRequest.Capability5GMM
	} else {
		if ue.RegistrationType5GS != nasMessage.RegistrationType5GSPeriodicRegistrationUpdating {
			gmm_message.SendRegistrationReject(ue.RanUe[anType], nasMessage.Cause5GMMProtocolErrorUnspecified, "")
			return fmt.Errorf("Capability5GMM is nil")
		}
	}

	storeLastVisitedRegisteredTAI(ue, ue.RegistrationRequest.LastVisitedRegisteredTAI)

	if ue.RegistrationRequest.MICOIndication != nil {
		logger.GmmLog.Warnf("Receive MICO Indication[RAAI: %d], Not Supported",
			ue.RegistrationRequest.MICOIndication.GetRAAI())
	}

	// TODO: Negotiate DRX value if need (TS 23.501 5.4.5)
	negotiateDRXParameters(ue, ue.RegistrationRequest.RequestedDRXParameters)

	// TODO (step 10 optional): send Namf_Communication_RegistrationCompleteNotify to old AMF if need
	// if ue.ServingAmfChanged {
	// 	If the AMF has changed the new AMF notifies the old AMF that the registration of the UE in the new AMF is completed
	// }

	if len(ue.Pei) == 0 {
		gmm_message.SendIdentityRequest(ue.RanUe[anType], nasMessage.MobileIdentity5GSTypeImei)
		return nil
	}

	// TODO (step 12 optional): the new AMF initiates ME identity check by invoking the
	// N5g-eir_EquipmentIdentityCheck_Get service operation

	if ue.ServingAmfChanged || ue.State[models.AccessType_NON_3_GPP_ACCESS].Is(context.Registered) ||
		!ue.ContextValid {
		if err := communicateWithUDM(ue, anType); err != nil {
			return err
		}
	}

	var reactivationResult *[16]bool
	var errPduSessionId, errCause []uint8
	ctxList := ngapType.PDUSessionResourceSetupListCxtReq{}
	suList := ngapType.PDUSessionResourceSetupListSUReq{}

	if ue.RegistrationRequest.UplinkDataStatus != nil {
		uplinkDataPsi := nasConvert.PSIToBooleanArray(ue.RegistrationRequest.UplinkDataStatus.Buffer)
		reactivationResult = new([16]bool)
		allowReEstablishPduSession := true

		// determines that the UE is in non-allowed area or is not in allowed area
		if ue.AmPolicyAssociation != nil && ue.AmPolicyAssociation.ServAreaRes != nil {
			switch ue.AmPolicyAssociation.ServAreaRes.RestrictionType {
			case models.RestrictionType_ALLOWED_AREAS:
				allowReEstablishPduSession = context.TacInAreas(ue.Tai.Tac, ue.AmPolicyAssociation.ServAreaRes.Areas)
			case models.RestrictionType_NOT_ALLOWED_AREAS:
				allowReEstablishPduSession = !context.TacInAreas(ue.Tai.Tac, ue.AmPolicyAssociation.ServAreaRes.Areas)
			}
		}

		if !allowReEstablishPduSession {
			for pduSessionId, hasUplinkData := range uplinkDataPsi {
				if hasUplinkData {
					errPduSessionId = append(errPduSessionId, uint8(pduSessionId))
					errCause = append(errCause, nasMessage.Cause5GMMRestrictedServiceArea)
				}
			}
		} else {
			for idx, hasUplinkData := range uplinkDataPsi {
				pduSessionId := int32(idx)
				if _, exists := ue.SmContextList[pduSessionId]; !exists {
					continue
				}

				smContext := ue.SmContextList[pduSessionId]

				// uplink data are pending for the corresponding PDU session identity
				if hasUplinkData && smContext.PduSessionContext.AccessType == models.AccessType__3_GPP_ACCESS {
					response, errResponse, problemDetail, err := consumer.SendUpdateSmContextActivateUpCnxState(
						ue, pduSessionId, anType)
					if response == nil {
						reactivationResult[pduSessionId] = true
						errPduSessionId = append(errPduSessionId, uint8(pduSessionId))
						cause := nasMessage.Cause5GMMProtocolErrorUnspecified
						if errResponse != nil {
							switch errResponse.JsonData.Error.Cause {
							case "OUT_OF_LADN_SERVICE_AREA":
								cause = nasMessage.Cause5GMMLADNNotAvailable
							case "PRIORITIZED_SERVICES_ONLY":
								cause = nasMessage.Cause5GMMRestrictedServiceArea
							case "DNN_CONGESTION", "S-NSSAI_CONGESTION":
								cause = nasMessage.Cause5GMMInsufficientUserPlaneResourcesForThePDUSession
							}
						}
						errCause = append(errCause, cause)

						if problemDetail != nil {
							logger.GmmLog.Errorf("Update SmContext Failed Problem[%+v]", problemDetail)
						} else if err != nil {
							logger.GmmLog.Errorf("Update SmContext Error[%v]", err.Error())
						}
					} else {
						if ue.RanUe[anType].UeContextRequest {
							ngap_message.AppendPDUSessionResourceSetupListCxtReq(&ctxList, pduSessionId,
								*smContext.PduSessionContext.SNssai, response.BinaryDataN1SmMessage, response.BinaryDataN2SmInformation)
						} else {
							ngap_message.AppendPDUSessionResourceSetupListSUReq(&suList, pduSessionId,
								*smContext.PduSessionContext.SNssai, response.BinaryDataN1SmMessage, response.BinaryDataN2SmInformation)
						}
					}
				}
			}
		}
	}

	var pduSessionStatus *[16]bool
	if ue.RegistrationRequest.PDUSessionStatus != nil {
		pduSessionStatus = new([16]bool)
		psiArray := nasConvert.PSIToBooleanArray(ue.RegistrationRequest.PDUSessionStatus.Buffer)
		for psi := 1; psi <= 15; psi++ {
			pduSessionId := int32(psi)
			if _, exists := ue.SmContextList[pduSessionId]; !exists {
				continue
			}
			if !psiArray[psi] && ue.SmContextList[pduSessionId].PduSessionContext.AccessType == anType {
				cause := models.Cause_PDU_SESSION_STATUS_MISMATCH
				causeAll := &context.CauseAll{
					Cause: &cause,
				}
				releaseData := consumer.BuildReleaseSmContextRequest(ue, causeAll, "", nil)
				problemDetail, err := consumer.SendReleaseSmContextRequest(ue, pduSessionId, releaseData)
				if problemDetail != nil {
					pduSessionStatus[psi] = true
					logger.GmmLog.Errorf("Release SmContext Failed Problem[%+v]", problemDetail)
				} else if err != nil {
					pduSessionStatus[psi] = true
					logger.GmmLog.Errorf("Release SmContext Error[%v]", err.Error())
				} else {
					pduSessionStatus[psi] = false
				}
			} else {
				pduSessionStatus[psi] = false
			}
		}
	}

	if ue.RegistrationRequest.AllowedPDUSessionStatus != nil {
		allowedPsis := nasConvert.PSIToBooleanArray(ue.RegistrationRequest.AllowedPDUSessionStatus.Buffer)
		if ue.N1N2Message != nil {
			requestData := ue.N1N2Message.Request.JsonData
			n1Msg := ue.N1N2Message.Request.BinaryDataN1Message
			n2Info := ue.N1N2Message.Request.BinaryDataN2Information

			// downlink signalling
			if n2Info == nil {
				if len(suList.List) != 0 {
					nasPdu, err := gmm_message.BuildRegistrationAccept(ue, anType, pduSessionStatus,
						reactivationResult, errPduSessionId, errCause)
					if err != nil {
						return err
					}
					ngap_message.SendPDUSessionResourceSetupRequest(ue.RanUe[anType], nasPdu, suList)
				} else {
					gmm_message.SendRegistrationAccept(ue, anType, pduSessionStatus,
						reactivationResult, errPduSessionId, errCause, &ctxList)
				}
				switch requestData.N1MessageContainer.N1MessageClass {
				case models.N1MessageClass_SM:
					gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeN1SMInfo,
						n1Msg, requestData.PduSessionId, 0, nil, 0)
				case models.N1MessageClass_LPP:
					gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeLPP, n1Msg, 0, 0, nil, 0)
				case models.N1MessageClass_SMS:
					gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeSMS, n1Msg, 0, 0, nil, 0)
				case models.N1MessageClass_UPDP:
					gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeUEPolicy, n1Msg, 0, 0, nil, 0)
				}
				ue.N1N2Message = nil
				return nil
			}

			smInfo := requestData.N2InfoContainer.SmInfo
			smContext, exist := ue.SmContextList[requestData.PduSessionId]
			if !exist {
				ue.N1N2Message = nil
				return fmt.Errorf("Pdu Session Id not Exists")
			}

			if smContext.PduSessionContext.AccessType == models.AccessType_NON_3_GPP_ACCESS {
				if reactivationResult == nil {
					reactivationResult = new([16]bool)
				}
				if allowedPsis[requestData.PduSessionId] {
					// TODO: error handling
					response, errRes, _, err := consumer.SendUpdateSmContextChangeAccessType(ue,
						requestData.PduSessionId, true)
					if err != nil {
						return err
					} else if response == nil {
						reactivationResult[requestData.PduSessionId] = true
						errPduSessionId = append(errPduSessionId, uint8(requestData.PduSessionId))
						cause := nasMessage.Cause5GMMProtocolErrorUnspecified
						if errRes != nil {
							switch errRes.JsonData.Error.Cause {
							case "OUT_OF_LADN_SERVICE_AREA":
								cause = nasMessage.Cause5GMMLADNNotAvailable
							case "PRIORITIZED_SERVICES_ONLY":
								cause = nasMessage.Cause5GMMRestrictedServiceArea
							case "DNN_CONGESTION", "S-NSSAI_CONGESTION":
								cause = nasMessage.Cause5GMMInsufficientUserPlaneResourcesForThePDUSession
							}
						}
						errCause = append(errCause, cause)
					} else {
						smContext.UserLocation = deepcopy.Copy(ue.Location).(models.UserLocation)
						smContext.PduSessionContext.AccessType = models.AccessType__3_GPP_ACCESS
						if response.BinaryDataN2SmInformation != nil &&
							response.JsonData.N2SmInfoType == models.N2SmInfoType_PDU_RES_SETUP_REQ {
							ngap_message.AppendPDUSessionResourceSetupListSUReq(&suList, requestData.PduSessionId,
								*smContext.PduSessionContext.SNssai, nil, response.BinaryDataN2SmInformation)
						}
					}
				} else {
					logger.GmmLog.Warnf("UE was reachable but did not accept to re-activate the PDU Session[%d]",
						requestData.PduSessionId)
					callback.SendN1N2TransferFailureNotification(ue, models.N1N2MessageTransferCause_UE_NOT_REACHABLE_FOR_SESSION)
				}
			} else if smInfo.N2InfoContent.NgapIeType == models.NgapIeType_PDU_RES_SETUP_REQ {
				var nasPdu []byte
				var err error
				if n1Msg != nil {
					pduSessionId := uint8(smInfo.PduSessionId)
					nasPdu, err = gmm_message.BuildDLNASTransport(ue, nasMessage.PayloadContainerTypeN1SMInfo,
						n1Msg, pduSessionId, nil, nil, 0)
					if err != nil {
						return err
					}
				}
				ngap_message.AppendPDUSessionResourceSetupListSUReq(&suList, smInfo.PduSessionId,
					*smInfo.SNssai, nasPdu, n2Info)
			}
		}
	}

	if ue.LocationChanged && ue.RequestTriggerLocationChange {
		updateReq := models.PolicyAssociationUpdateRequest{}
		updateReq.Triggers = append(updateReq.Triggers, models.RequestTrigger_LOC_CH)
		updateReq.UserLoc = &ue.Location
		problemDetails, err := consumer.AMPolicyControlUpdate(ue, updateReq)
		if problemDetails != nil {
			logger.GmmLog.Errorf("AM Policy Control Update Failed Problem[%+v]", problemDetails)
		} else if err != nil {
			logger.GmmLog.Errorf("AM Policy Control Update Error[%v]", err)
		}
		ue.LocationChanged = false
	}

	// TODO (step 18 optional):
	// If the AMF has changed and the old AMF has indicated an existing NGAP UE association towards a N3IWF, the new AMF
	// creates an NGAP UE association towards the N3IWF to which the UE is connectedsend N2 AMF mobility request to N3IWF
	// if anType == models.AccessType_NON_3_GPP_ACCESS && ue.ServingAmfChanged {
	// 	TODO: send N2 AMF Mobility Request
	// }

	amfSelf.AllocateRegistrationArea(ue, anType)
	assignLadnInfo(ue, anType)

	// TODO: GUTI reassignment if need (based on operator poilcy)
	// TODO: T3512/Non3GPP de-registration timer reassignment if need (based on operator policy)

	if ue.RanUe[anType].UeContextRequest {
		if anType == models.AccessType__3_GPP_ACCESS {
			gmm_message.SendRegistrationAccept(ue, anType, pduSessionStatus, reactivationResult,
				errPduSessionId, errCause, &ctxList)
		} else {
			ngap_message.SendInitialContextSetupRequest(ue, anType, nil, &ctxList, nil, nil, nil)
			registrationAccept, err := gmm_message.BuildRegistrationAccept(ue, anType,
				pduSessionStatus, reactivationResult, errPduSessionId, errCause)
			if err != nil {
				logger.GmmLog.Errorf("Build Registration Accept: %+v", err)
				return nil
			}
			ue.RegistrationAcceptForNon3GPPAccess = registrationAccept
		}
		return nil
	} else {
		nasPdu, err := gmm_message.BuildRegistrationAccept(ue, anType, pduSessionStatus, reactivationResult,
			errPduSessionId, errCause)
		if err != nil {
			logger.GmmLog.Error(err.Error())
		}
		if len(suList.List) != 0 {
			ngap_message.SendPDUSessionResourceSetupRequest(ue.RanUe[anType], nasPdu, suList)
		} else {
			ngap_message.SendDownlinkNasTransport(ue.RanUe[anType], nasPdu, nil)
		}
		ue.ClearRegistrationRequestData(anType)
		return nil
	}
}

// TS 23.502 4.2.2.2.2 step 1
// If available, the last visited TAI shall be included in order to help the AMF produce Registration Area for the UE
func storeLastVisitedRegisteredTAI(ue *context.AmfUe, lastVisitedRegisteredTAI *nasType.LastVisitedRegisteredTAI) {
	if lastVisitedRegisteredTAI != nil {
		plmnID := nasConvert.PlmnIDToString(lastVisitedRegisteredTAI.Octet[1:4])
		nasTac := lastVisitedRegisteredTAI.GetTAC()
		tac := hex.EncodeToString(nasTac[:])

		tai := models.Tai{
			PlmnId: &models.PlmnId{
				Mcc: plmnID[:3],
				Mnc: plmnID[3:],
			},
			Tac: tac,
		}

		ue.LastVisitedRegisteredTai = tai
		logger.GmmLog.Debugf("Ue Last Visited Registered Tai; %v", ue.LastVisitedRegisteredTai)
	}
}

func negotiateDRXParameters(ue *context.AmfUe, requestedDRXParameters *nasType.RequestedDRXParameters) {
	if requestedDRXParameters != nil {
		switch requestedDRXParameters.GetDRXValue() {
		case nasMessage.DRXcycleParameterT32:
			logger.GmmLog.Tracef("Requested DRX: T = 32")
			ue.UESpecificDRX = nasMessage.DRXcycleParameterT32
		case nasMessage.DRXcycleParameterT64:
			logger.GmmLog.Tracef("Requested DRX: T = 64")
			ue.UESpecificDRX = nasMessage.DRXcycleParameterT64
		case nasMessage.DRXcycleParameterT128:
			logger.GmmLog.Tracef("Requested DRX: T = 128")
			ue.UESpecificDRX = nasMessage.DRXcycleParameterT128
		case nasMessage.DRXcycleParameterT256:
			logger.GmmLog.Tracef("Requested DRX: T = 256")
			ue.UESpecificDRX = nasMessage.DRXcycleParameterT256
		case nasMessage.DRXValueNotSpecified:
			fallthrough
		default:
			ue.UESpecificDRX = nasMessage.DRXValueNotSpecified
			logger.GmmLog.Tracef("Requested DRX: Value not specified")
		}
	}
}

func communicateWithUDM(ue *context.AmfUe, accessType models.AccessType) error {
	logger.GmmLog.Debugln("communicateWithUDM")
	amfSelf := context.AMF_Self()

	// UDM selection described in TS 23.501 6.3.8
	// TODO: consider udm group id, Routing ID part of SUCI, GPSI or External Group ID (e.g., by the NEF)
	param := Nnrf_NFDiscovery.SearchNFInstancesParamOpts{
		Supi: optional.NewString(ue.Supi),
	}
	resp, err := consumer.SendSearchNFInstances(amfSelf.NrfUri, models.NfType_UDM, models.NfType_AMF, &param)
	if err != nil {
		return fmt.Errorf("AMF can not select an UDM by NRF")
	}

	var uecmUri, sdmUri string
	for _, nfProfile := range resp.NfInstances {
		ue.UdmId = nfProfile.NfInstanceId
		uecmUri = util.SearchNFServiceUri(nfProfile, models.ServiceName_NUDM_UECM, models.NfServiceStatus_REGISTERED)
		sdmUri = util.SearchNFServiceUri(nfProfile, models.ServiceName_NUDM_SDM, models.NfServiceStatus_REGISTERED)
		if uecmUri != "" && sdmUri != "" {
			break
		}
	}
	ue.NudmUECMUri = uecmUri
	ue.NudmSDMUri = sdmUri
	if ue.NudmUECMUri == "" || ue.NudmSDMUri == "" {
		return fmt.Errorf("AMF can not select an UDM by NRF")
	}

	problemDetails, err := consumer.UeCmRegistration(ue, accessType, true)
	if problemDetails != nil {
		logger.GmmLog.Errorf("UECM_Registration Failed Problem[%+v]", problemDetails)
	} else if err != nil {
		logger.GmmLog.Errorf("UECM_Registration Error[%+v]", err)
	}

	problemDetails, err = consumer.SDMGetAmData(ue)
	if problemDetails != nil {
		logger.GmmLog.Errorf("SDM_Get AmData Failed Problem[%+v]", problemDetails)
	} else if err != nil {
		return fmt.Errorf("SDM_Get AmData Error[%+v]", err)
	}

	problemDetails, err = consumer.SDMGetSmfSelectData(ue)
	if problemDetails != nil {
		logger.GmmLog.Errorf("SDM_Get SmfSelectData Failed Problem[%+v]", problemDetails)
	} else if err != nil {
		return fmt.Errorf("SDM_Get SmfSelectData Error[%+v]", err)
	}

	problemDetails, err = consumer.SDMGetUeContextInSmfData(ue)
	if problemDetails != nil {
		logger.GmmLog.Errorf("SDM_Get UeContextInSmfData Failed Problem[%+v]", problemDetails)
	} else if err != nil {
		return fmt.Errorf("SDM_Get UeContextInSmfData Error[%+v]", err)
	}

	problemDetails, err = consumer.SDMSubscribe(ue)
	if problemDetails != nil {
		logger.GmmLog.Errorf("SDM Subscribe Failed Problem[%+v]", problemDetails)
	} else if err != nil {
		logger.GmmLog.Errorf("SDM Subscribe Error[%+v]", err)
		return fmt.Errorf("SDM Subscribe Error[%+v]", err)
	}
	ue.ContextValid = true
	return nil
}

func getSubscribedNssai(ue *context.AmfUe) {
	amfSelf := context.AMF_Self()
	if ue.NudmSDMUri == "" {
		param := Nnrf_NFDiscovery.SearchNFInstancesParamOpts{
			Supi: optional.NewString(ue.Supi),
		}
		for {
			err := consumer.SearchUdmSdmInstance(ue, amfSelf.NrfUri, models.NfType_UDM, models.NfType_AMF, &param)
			if err != nil {
				logger.GmmLog.Errorf("AMF can not select an Nudm_SDM Instance by NRF[Error: %+v]", err)
				time.Sleep(2 * time.Second)
			} else {
				break
			}
		}
	}
	problemDetails, err := consumer.SDMGetSliceSelectionSubscriptionData(ue)
	if problemDetails != nil {
		logger.GmmLog.Errorf("SDM_Get Slice Selection Subscription Data Failed Problem[%+v]", problemDetails)
	} else if err != nil {
		logger.GmmLog.Errorf("SDM_Get Slice Selection Subscription Data Error[%+v]", err)
	}
}

// TS 23.502 4.2.2.2.3 Registration with AMF Re-allocation
func handleRequestedNssai(ue *context.AmfUe, anType models.AccessType) error {
	amfSelf := context.AMF_Self()

	var requestedNssai []models.Snssai
	if ue.RegistrationRequest.RequestedNSSAI != nil {
		requestedNssai = nasConvert.RequestedNssaiToModels(ue.RegistrationRequest.RequestedNSSAI)
		logger.GmmLog.Debugf("RequestedNssai: %+v", requestedNssai)

		needSliceSelection := false
		for _, requestedSnssai := range requestedNssai {
			if ue.InSubscribedNssai(requestedSnssai) {
				allowedSnssai := models.AllowedSnssai{
					AllowedSnssai: &models.Snssai{
						Sst: requestedSnssai.Sst,
						Sd:  requestedSnssai.Sd,
					},
				}
				ue.AllowedNssai[anType] = append(ue.AllowedNssai[anType], allowedSnssai)
			} else {
				needSliceSelection = true
				break
			}
		}

		if needSliceSelection {
			if ue.NssfUri == "" {
				for {
					err := consumer.SearchNssfNSSelectionInstance(ue, amfSelf.NrfUri, models.NfType_NSSF, models.NfType_AMF, nil)
					if err != nil {
						logger.GmmLog.Errorf("AMF can not select an NSSF Instance by NRF[Error: %+v]", err)
						time.Sleep(2 * time.Second)
					} else {
						break
					}
				}
			}

			// Step 4
			problemDetails, err := consumer.NSSelectionGetForRegistration(ue, requestedNssai)
			if problemDetails != nil {
				logger.GmmLog.Errorf("NSSelection Get Failed Problem[%+v]", problemDetails)
				gmm_message.SendRegistrationReject(ue.RanUe[anType], nasMessage.Cause5GMMProtocolErrorUnspecified, "")
				return fmt.Errorf("Handle Requested Nssai of UE failed")
			} else if err != nil {
				logger.GmmLog.Errorf("NSSelection Get Error[%+v]", err)
				gmm_message.SendRegistrationReject(ue.RanUe[anType], nasMessage.Cause5GMMProtocolErrorUnspecified, "")
				return fmt.Errorf("Handle Requested Nssai of UE failed")
			}

			// Step 5: Initial AMF send Namf_Communication_RegistrationCompleteNotify to old AMF
			req := models.UeRegStatusUpdateReqData{
				TransferStatus: models.UeContextTransferStatus_NOT_TRANSFERRED,
			}
			_, problemDetails, err = consumer.RegistrationStatusUpdate(ue, req)
			if problemDetails != nil {
				logger.GmmLog.Errorf("Registration Status Update Failed Problem[%+v]", problemDetails)
			} else if err != nil {
				logger.GmmLog.Errorf("Registration Status Update Error[%+v]", err)
			}

			// Step 6
			searchTargetAmfQueryParam := Nnrf_NFDiscovery.SearchNFInstancesParamOpts{}
			if ue.NetworkSliceInfo != nil {
				netwotkSliceInfo := ue.NetworkSliceInfo
				if netwotkSliceInfo.TargetAmfSet != "" {
					// TS 29.531
					// TargetAmfSet format: ^[0-9]{3}-[0-9]{2-3}-[A-Fa-f0-9]{2}-[0-3][A-Fa-f0-9]{2}$
					// mcc-mnc-amfRegionId(8 bit)-AmfSetId(10 bit)
					targetAmfSetToken := strings.Split(netwotkSliceInfo.TargetAmfSet, "-")
					guami := amfSelf.ServedGuamiList[0]
					targetAmfPlmnId := models.PlmnId{
						Mcc: targetAmfSetToken[0],
						Mnc: targetAmfSetToken[1],
					}

					if !reflect.DeepEqual(guami.PlmnId, targetAmfPlmnId) {
						searchTargetAmfQueryParam.TargetPlmnList =
							optional.NewInterface(util.MarshToJsonString([]models.PlmnId{targetAmfPlmnId}))
						searchTargetAmfQueryParam.RequesterPlmnList =
							optional.NewInterface(util.MarshToJsonString([]models.PlmnId{*guami.PlmnId}))
					}

					searchTargetAmfQueryParam.AmfRegionId = optional.NewString(targetAmfSetToken[2])
					searchTargetAmfQueryParam.AmfSetId = optional.NewString(targetAmfSetToken[3])
				} else if len(netwotkSliceInfo.CandidateAmfList) > 0 {
					// TODO: select candidate Amf based on local poilcy
					searchTargetAmfQueryParam.TargetNfInstanceId = optional.NewInterface(netwotkSliceInfo.CandidateAmfList[0])
				}
			}

			err = consumer.SearchAmfCommunicationInstance(ue, amfSelf.NrfUri,
				models.NfType_AMF, models.NfType_AMF, &searchTargetAmfQueryParam)
			if err == nil {
				// Condition (A) Step 7: initial AMF find Target AMF via NRF ->
				// Send Namf_Communication_N1MessageNotify to Target AMF
				ueContext := consumer.BuildUeContextModel(ue)
				registerContext := models.RegistrationContextContainer{
					UeContext:        &ueContext,
					AnType:           anType,
					AnN2ApId:         int32(ue.RanUe[anType].RanUeNgapId),
					RanNodeId:        ue.RanUe[anType].Ran.RanId,
					InitialAmfName:   amfSelf.Name,
					UserLocation:     &ue.Location,
					RrcEstCause:      ue.RanUe[anType].RRCEstablishmentCause,
					UeContextRequest: ue.RanUe[anType].UeContextRequest,
					AnN2IPv4Addr:     ue.RanUe[anType].Ran.Conn.RemoteAddr().String(),
					AllowedNssai: &models.AllowedNssai{
						AllowedSnssaiList: ue.AllowedNssai[anType],
						AccessType:        anType,
					},
				}
				if len(ue.NetworkSliceInfo.RejectedNssaiInPlmn) > 0 {
					registerContext.RejectedNssaiInPlmn = ue.NetworkSliceInfo.RejectedNssaiInPlmn
				}
				if len(ue.NetworkSliceInfo.RejectedNssaiInTa) > 0 {
					registerContext.RejectedNssaiInTa = ue.NetworkSliceInfo.RejectedNssaiInTa
				}

				var n1Message bytes.Buffer
				ue.RegistrationRequest.EncodeRegistrationRequest(&n1Message)
				callback.SendN1MessageNotifyAtAMFReAllocation(ue, n1Message.Bytes(), &registerContext)
			} else {
				// Condition (B) Step 7: initial AMF can not find Target AMF via NRF -> Send Reroute NAS Request to RAN
				allowedNssaiNgap := ngapConvert.AllowedNssaiToNgap(ue.AllowedNssai[anType])
				ngap_message.SendRerouteNasRequest(ue, anType, nil, ue.RanUe[anType].InitialUEMessage, &allowedNssaiNgap)
			}
			return nil
		}
	}

	// if registration request has no requested nssai, or non of snssai in requested nssai is permitted by nssf
	// then use ue subscriped snssai which is marked as default as allowed nssai
	if len(ue.AllowedNssai[anType]) == 0 {
		for _, subscribedSnssai := range ue.SubscribedNssai {
			if subscribedSnssai.DefaultIndication {
				allowedSnssai := models.AllowedSnssai{
					AllowedSnssai: subscribedSnssai.SubscribedSnssai,
				}
				ue.AllowedNssai[anType] = append(ue.AllowedNssai[anType], allowedSnssai)
			}
		}
	}
	return nil
}

func assignLadnInfo(ue *context.AmfUe, accessType models.AccessType) {

	amfSelf := context.AMF_Self()

	ue.LadnInfo = nil
	if ue.RegistrationRequest.LADNIndication != nil {
		// request for LADN information
		if ue.RegistrationRequest.LADNIndication.GetLen() == 0 {
			if ue.HasWildCardSubscribedDNN() {
				for _, ladn := range amfSelf.LadnPool {
					if ue.TaiListInRegistrationArea(ladn.TaiLists, accessType) {
						ue.LadnInfo = append(ue.LadnInfo, *ladn)
					}
				}
			} else {
				for _, snssaiInfos := range ue.SmfSelectionData.SubscribedSnssaiInfos {
					for _, dnnInfo := range snssaiInfos.DnnInfos {
						if ladn, ok := amfSelf.LadnPool[dnnInfo.Dnn]; ok { // check if this dnn is a ladn
							if ue.TaiListInRegistrationArea(ladn.TaiLists, accessType) {
								ue.LadnInfo = append(ue.LadnInfo, *ladn)
							}
						}
					}
				}
			}
		} else {
			requestedLadnList := nasConvert.LadnToModels(ue.RegistrationRequest.LADNIndication.GetLADNDNNValue())
			for _, requestedLadn := range requestedLadnList {
				if ladn, ok := amfSelf.LadnPool[requestedLadn]; ok {
					if ue.TaiListInRegistrationArea(ladn.TaiLists, accessType) {
						ue.LadnInfo = append(ue.LadnInfo, *ladn)
					}
				}
			}
		}
	} else if ue.SmfSelectionData != nil {
		for _, snssaiInfos := range ue.SmfSelectionData.SubscribedSnssaiInfos {
			for _, dnnInfo := range snssaiInfos.DnnInfos {
				if dnnInfo.Dnn != "*" {
					if ladn, ok := amfSelf.LadnPool[dnnInfo.Dnn]; ok {
						if ue.TaiListInRegistrationArea(ladn.TaiLists, accessType) {
							ue.LadnInfo = append(ue.LadnInfo, *ladn)
						}
					}
				}
			}
		}
	}
}

func HandleIdentityResponse(ue *context.AmfUe, identityResponse *nasMessage.IdentityResponse) error {

	logger.GmmLog.Info("[AMF] Handle Identity Response")

	if ue == nil {
		return fmt.Errorf("AmfUe is nil")
	}

	mobileIdentityContents := identityResponse.MobileIdentity.GetMobileIdentityContents()
	switch nasConvert.GetTypeOfIdentity(mobileIdentityContents[0]) { // get type of identity
	case nasMessage.MobileIdentity5GSTypeSuci:
		var plmnId string
		ue.Suci, plmnId = nasConvert.SuciToString(mobileIdentityContents)
		ue.PlmnId = util.PlmnIdStringToModels(plmnId)
		logger.GmmLog.Debugf("get SUCI: %s", ue.Suci)
	case nasMessage.MobileIdentity5GSType5gGuti:
		if ue.MacFailed {
			return fmt.Errorf("NAS message integrity check failed")
		}
		_, guti := nasConvert.GutiToString(mobileIdentityContents)
		ue.Guti = guti
		logger.GmmLog.Debugf("get GUTI: %s", guti)
	case nasMessage.MobileIdentity5GSType5gSTmsi:
		if ue.MacFailed {
			return fmt.Errorf("NAS message integrity check failed")
		}
		sTmsi := hex.EncodeToString(mobileIdentityContents[1:])
		if tmp, err := strconv.ParseInt(sTmsi[4:], 10, 32); err != nil {
			return err
		} else {
			ue.Tmsi = int32(tmp)
		}
		logger.GmmLog.Debugf("get 5G-S-TMSI: %s", sTmsi)
	case nasMessage.MobileIdentity5GSTypeImei:
		if ue.MacFailed {
			return fmt.Errorf("NAS message integrity check failed")
		}
		imei := nasConvert.PeiToString(mobileIdentityContents)
		ue.Pei = imei
		logger.GmmLog.Debugf("get PEI: %s", imei)
	case nasMessage.MobileIdentity5GSTypeImeisv:
		if ue.MacFailed {
			return fmt.Errorf("NAS message integrity check failed")
		}
		imeisv := nasConvert.PeiToString(mobileIdentityContents)
		ue.Pei = imeisv
		logger.GmmLog.Debugf("get PEI: %s", imeisv)
	}
	return nil
}

// TS 24501 5.6.3.2
func HandleNotificationResponse(ue *context.AmfUe, notificationResponse *nasMessage.NotificationResponse) error {

	logger.GmmLog.Info("[AMF] Handle Notification Response")

	if ue.MacFailed {
		return fmt.Errorf("NAS message integrity check failed")
	}

	util.StopT3565(ue)

	if notificationResponse != nil && notificationResponse.PDUSessionStatus != nil {
		psiArray := nasConvert.PSIToBooleanArray(notificationResponse.PDUSessionStatus.Buffer)
		for psi := 1; psi <= 15; psi++ {
			pduSessionId := int32(psi)
			if _, exists := ue.SmContextList[pduSessionId]; !exists {
				continue
			}
			if !psiArray[psi] {
				cause := models.Cause_PDU_SESSION_STATUS_MISMATCH
				causeAll := &context.CauseAll{
					Cause: &cause,
				}
				releaseData := consumer.BuildReleaseSmContextRequest(ue, causeAll, "", nil)
				problemDetail, err := consumer.SendReleaseSmContextRequest(ue, pduSessionId, releaseData)
				if problemDetail != nil {
					logger.GmmLog.Errorf("Release SmContext Failed Problem[%+v]", problemDetail)
				} else if err != nil {
					logger.GmmLog.Errorf("Release SmContext Error[%v]", err.Error())

				}
			}
		}
	}
	return nil
}

func HandleConfigurationUpdateComplete(ue *context.AmfUe,
	configurationUpdateComplete *nasMessage.ConfigurationUpdateComplete) error {

	logger.GmmLog.Info("[AMF] Handle Configuration Update Complete")

	if ue.MacFailed {
		return fmt.Errorf("NAS message integrity check failed")
	}

	// TODO: Stop timer T3555 in TS 24.501 Figure 5.4.4.1.1 in handler
	// TODO: Send acknowledgment by Nudm_SMD_Info_Service to UDM in handler
	//		import "free5gc/lib/openapi/Nudm_SubscriberDataManagement" client.Info

	return nil
}

func AuthenticationProcedure(ue *context.AmfUe, accessType models.AccessType) (bool, error) {
	logger.GmmLog.Info("Authentication procedure")

	// Check whether UE has SUCI and SUPI
	if IdentityVerification(ue) {
		logger.GmmLog.Debugln("UE has SUCI / SUPI")
		if ue.SecurityContextIsValid() {
			logger.GmmLog.Debugln("UE has a valid security context - skip the authentication procedure")
			return true, nil
		}
	} else {
		// Request UE's SUCI by sending identity request
		gmm_message.SendIdentityRequest(ue.RanUe[accessType], nasMessage.MobileIdentity5GSTypeSuci)
		return false, nil
	}

	amfSelf := context.AMF_Self()

	// TODO: consider ausf group id, Routing ID part of SUCI
	param := Nnrf_NFDiscovery.SearchNFInstancesParamOpts{}
	resp, err := consumer.SendSearchNFInstances(amfSelf.NrfUri, models.NfType_AUSF, models.NfType_AMF, &param)
	if err != nil {
		logger.GmmLog.Error("AMF can not select an AUSF by NRF")
		return false, err
	}

	// select the first AUSF, TODO: select base on other info
	var ausfUri string
	for _, nfProfile := range resp.NfInstances {
		ue.AusfId = nfProfile.NfInstanceId
		ausfUri = util.SearchNFServiceUri(nfProfile, models.ServiceName_NAUSF_AUTH, models.NfServiceStatus_REGISTERED)
		if ausfUri != "" {
			break
		}
	}
	if ausfUri == "" {
		err = fmt.Errorf("AMF can not select an AUSF by NRF")
		logger.GmmLog.Errorf(err.Error())
		return false, err
	}
	ue.AusfUri = ausfUri

	response, problemDetails, err := consumer.SendUEAuthenticationAuthenticateRequest(ue, nil)
	if err != nil {
		logger.GmmLog.Errorf("Nausf_UEAU Authenticate Request Error: %+v", err)
		return false, errors.New("Authentication procedure failed")
	} else if problemDetails != nil {
		logger.GmmLog.Errorf("Nausf_UEAU Authenticate Request Failed: %+v", problemDetails)
		return false, nil
	}
	ue.AuthenticationCtx = response
	ue.ABBA = []uint8{0x00, 0x00} // set ABBA value as described at TS 33.501 Annex A.7.1

	ue.T3560RetryTimes = 0
	gmm_message.SendAuthenticationRequest(ue.RanUe[accessType])
	return false, nil
}

// TS 24501 5.6.1
func HandleServiceRequest(ue *context.AmfUe, anType models.AccessType,
	serviceRequest *nasMessage.ServiceRequest) error {
	logger.GmmLog.Info("Handle Service Reqeust")

	if ue == nil {
		return fmt.Errorf("AmfUe is nil")
	}

	util.StopT3513(ue)
	util.StopT3565(ue)

	// Send Authtication / Security Procedure not support
	if !ue.SecurityContextIsValid() {
		logger.GmmLog.Warnf("No Security Context : SUPI[%s]", ue.Supi)
		gmm_message.SendServiceReject(ue.RanUe[anType], nil, nasMessage.Cause5GMMUEIdentityCannotBeDerivedByTheNetwork)
		ngap_message.SendUEContextReleaseCommand(ue.RanUe[anType],
			context.UeContextN2NormalRelease, ngapType.CausePresentNas, ngapType.CauseNasPresentNormalRelease)
		return nil
	}

	serviceType := serviceRequest.GetServiceTypeValue()
	var reactivationResult, acceptPduSessionPsi *[16]bool
	var errPduSessionId, errCause []uint8
	var targetPduSessionId int32
	suList := ngapType.PDUSessionResourceSetupListSUReq{}
	ctxList := ngapType.PDUSessionResourceSetupListCxtReq{}

	if serviceType == nasMessage.ServiceTypeEmergencyServices ||
		serviceType == nasMessage.ServiceTypeEmergencyServicesFallback {
		logger.GmmLog.Warnf("emergency service is not supported")
	}

	if serviceType == nasMessage.ServiceTypeSignalling {
		err := sendServiceAccept(ue, anType, ctxList, suList, nil, nil, nil, nil)
		return err
	}
	if ue.N1N2Message != nil {
		requestData := ue.N1N2Message.Request.JsonData
		if ue.N1N2Message.Request.BinaryDataN2Information != nil {
			if requestData.N2InfoContainer.N2InformationClass == models.N2InformationClass_SM {
				targetPduSessionId = requestData.N2InfoContainer.SmInfo.PduSessionId
			} else {
				ue.N1N2Message = nil
				return fmt.Errorf("Service Request triggered by Network has not implemented about non SM N2Info")
			}
		}
	}

	if serviceRequest.UplinkDataStatus != nil {
		uplinkDataPsi := nasConvert.PSIToBooleanArray(serviceRequest.UplinkDataStatus.Buffer)
		reactivationResult = new([16]bool)
		for pduSessionId, smContext := range ue.SmContextList {
			if pduSessionId == targetPduSessionId {
				continue
			}
			if uplinkDataPsi[pduSessionId] && smContext.PduSessionContext.AccessType == models.AccessType__3_GPP_ACCESS {
				response, errRes, _, err := consumer.SendUpdateSmContextActivateUpCnxState(
					ue, pduSessionId, models.AccessType__3_GPP_ACCESS)
				if err != nil {
					return err
				} else if response == nil {
					reactivationResult[pduSessionId] = true
					errPduSessionId = append(errPduSessionId, uint8(pduSessionId))
					cause := nasMessage.Cause5GMMProtocolErrorUnspecified
					if errRes != nil {
						switch errRes.JsonData.Error.Cause {
						case "OUT_OF_LADN_SERVICE_AREA":
							cause = nasMessage.Cause5GMMLADNNotAvailable
						case "PRIORITIZED_SERVICES_ONLY":
							cause = nasMessage.Cause5GMMRestrictedServiceArea
						case "DNN_CONGESTION", "S-NSSAI_CONGESTION":
							cause = nasMessage.Cause5GMMInsufficientUserPlaneResourcesForThePDUSession
						}
					}
					errCause = append(errCause, cause)
				} else if ue.RanUe[anType].UeContextRequest {
					ngap_message.AppendPDUSessionResourceSetupListCxtReq(&ctxList,
						pduSessionId, *smContext.PduSessionContext.SNssai, nil, response.BinaryDataN2SmInformation)
				} else {
					ngap_message.AppendPDUSessionResourceSetupListSUReq(&suList,
						pduSessionId, *smContext.PduSessionContext.SNssai, nil, response.BinaryDataN2SmInformation)
				}
			}
		}
	}
	if serviceRequest.PDUSessionStatus != nil {
		acceptPduSessionPsi = new([16]bool)
		psiArray := nasConvert.PSIToBooleanArray(serviceRequest.PDUSessionStatus.Buffer)
		for pduSessionId, smContext := range ue.SmContextList {
			if smContext.PduSessionContext.AccessType == anType {
				if !psiArray[pduSessionId] {
					cause := models.Cause_PDU_SESSION_STATUS_MISMATCH
					causeAll := &context.CauseAll{
						Cause: &cause,
					}
					releaseData := consumer.BuildReleaseSmContextRequest(ue, causeAll, "", nil)
					problemDetail, err := consumer.SendReleaseSmContextRequest(ue, pduSessionId, releaseData)
					if problemDetail != nil {
						logger.GmmLog.Errorf("Release SmContext Failed Problem[%+v]", problemDetail)
					} else if err != nil {
						logger.GmmLog.Errorf("Release SmContext Error[%v]", err.Error())
					}
				} else {
					acceptPduSessionPsi[pduSessionId] = true
				}
			}
		}
	}
	switch serviceType {
	case nasMessage.ServiceTypeMobileTerminatedServices: // Trigger by Network
		if ue.N1N2Message != nil {
			requestData := ue.N1N2Message.Request.JsonData
			n1Msg := ue.N1N2Message.Request.BinaryDataN1Message
			n2Info := ue.N1N2Message.Request.BinaryDataN2Information

			// downlink signalling
			if n2Info == nil {
				err := sendServiceAccept(ue, anType, ctxList, suList, acceptPduSessionPsi,
					reactivationResult, errPduSessionId, errCause)
				if err != nil {
					return err
				}
				switch requestData.N1MessageContainer.N1MessageClass {
				case models.N1MessageClass_SM:
					gmm_message.SendDLNASTransport(ue.RanUe[anType],
						nasMessage.PayloadContainerTypeN1SMInfo, n1Msg, requestData.PduSessionId, 0, nil, 0)
				case models.N1MessageClass_LPP:
					gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeLPP, n1Msg, 0, 0, nil, 0)
				case models.N1MessageClass_SMS:
					gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeSMS, n1Msg, 0, 0, nil, 0)
				case models.N1MessageClass_UPDP:
					gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeUEPolicy, n1Msg, 0, 0, nil, 0)
				}
				ue.N1N2Message = nil
				return nil
			}
			// TODO: Area of validity for the N2 SM information
			smInfo := requestData.N2InfoContainer.SmInfo
			smContext, exist := ue.SmContextList[requestData.PduSessionId]
			if !exist {
				ue.N1N2Message = nil
				return fmt.Errorf("Service Request triggered by Network error for pduSessionId does not exist")
			}

			if smContext.PduSessionContext.AccessType == models.AccessType_NON_3_GPP_ACCESS {
				if serviceRequest.AllowedPDUSessionStatus != nil {
					allowPduSessionPsi := nasConvert.PSIToBooleanArray(serviceRequest.AllowedPDUSessionStatus.Buffer)
					if reactivationResult == nil {
						reactivationResult = new([16]bool)
					}
					if allowPduSessionPsi[requestData.PduSessionId] {
						response, errRes, _, err := consumer.SendUpdateSmContextChangeAccessType(
							ue, requestData.PduSessionId, true)
						if err != nil {
							return err
						} else if response == nil {
							reactivationResult[requestData.PduSessionId] = true
							errPduSessionId = append(errPduSessionId, uint8(requestData.PduSessionId))
							cause := nasMessage.Cause5GMMProtocolErrorUnspecified
							if errRes != nil {
								switch errRes.JsonData.Error.Cause {
								case "OUT_OF_LADN_SERVICE_AREA":
									cause = nasMessage.Cause5GMMLADNNotAvailable
								case "PRIORITIZED_SERVICES_ONLY":
									cause = nasMessage.Cause5GMMRestrictedServiceArea
								case "DNN_CONGESTION", "S-NSSAI_CONGESTION":
									cause = nasMessage.Cause5GMMInsufficientUserPlaneResourcesForThePDUSession
								}
							}
							errCause = append(errCause, cause)
						} else {
							smContext.UserLocation = deepcopy.Copy(ue.Location).(models.UserLocation)
							smContext.PduSessionContext.AccessType = models.AccessType__3_GPP_ACCESS
							if response.BinaryDataN2SmInformation != nil &&
								response.JsonData.N2SmInfoType == models.N2SmInfoType_PDU_RES_SETUP_REQ {
								if ue.RanUe[anType].UeContextRequest {
									ngap_message.AppendPDUSessionResourceSetupListCxtReq(&ctxList,
										requestData.PduSessionId, *smContext.PduSessionContext.SNssai, nil, response.BinaryDataN2SmInformation)
								} else {
									ngap_message.AppendPDUSessionResourceSetupListSUReq(&suList,
										requestData.PduSessionId, *smContext.PduSessionContext.SNssai, nil, response.BinaryDataN2SmInformation)
								}
							}
						}
					} else {
						logger.GmmLog.Warnf("UE was reachable but did not accept to re-activate the PDU Session[%d]",
							requestData.PduSessionId)
						callback.SendN1N2TransferFailureNotification(ue, models.N1N2MessageTransferCause_UE_NOT_REACHABLE_FOR_SESSION)
					}
				}
			} else if smInfo.N2InfoContent.NgapIeType == models.NgapIeType_PDU_RES_SETUP_REQ {
				var nasPdu []byte
				var err error
				if n1Msg != nil {
					pduSessionId := uint8(smInfo.PduSessionId)
					nasPdu, err = gmm_message.BuildDLNASTransport(ue, nasMessage.PayloadContainerTypeN1SMInfo,
						n1Msg, pduSessionId, nil, nil, 0)
					if err != nil {
						return err
					}
				}
				if ue.RanUe[anType].UeContextRequest {
					ngap_message.AppendPDUSessionResourceSetupListCxtReq(&ctxList, smInfo.PduSessionId, *smInfo.SNssai, nasPdu, n2Info)
				} else {
					ngap_message.AppendPDUSessionResourceSetupListSUReq(&suList, smInfo.PduSessionId, *smInfo.SNssai,
						nasPdu, n2Info)
				}
			}
			err := sendServiceAccept(ue, anType, ctxList, suList, acceptPduSessionPsi,
				reactivationResult, errPduSessionId, errCause)
			if err != nil {
				return err
			}
		}
		// downlink signaling
		if ue.ConfigurationUpdateMessage != nil {
			err := sendServiceAccept(ue, anType, ctxList, suList,
				acceptPduSessionPsi, reactivationResult, errPduSessionId, errCause)
			if err != nil {
				return err
			}
			mobilityRestrictionList := ngap_message.BuildIEMobilityRestrictionList(ue)
			ngap_message.SendDownlinkNasTransport(ue.RanUe[models.AccessType__3_GPP_ACCESS],
				ue.ConfigurationUpdateMessage, &mobilityRestrictionList)
			ue.ConfigurationUpdateMessage = nil
		}
	case nasMessage.ServiceTypeData:
		if anType == models.AccessType__3_GPP_ACCESS {
			if ue.AmPolicyAssociation != nil && ue.AmPolicyAssociation.ServAreaRes != nil {
				var accept bool
				switch ue.AmPolicyAssociation.ServAreaRes.RestrictionType {
				case models.RestrictionType_ALLOWED_AREAS:
					accept = context.TacInAreas(ue.Tai.Tac, ue.AmPolicyAssociation.ServAreaRes.Areas)
				case models.RestrictionType_NOT_ALLOWED_AREAS:
					accept = !context.TacInAreas(ue.Tai.Tac, ue.AmPolicyAssociation.ServAreaRes.Areas)
				}

				if !accept {
					gmm_message.SendServiceReject(ue.RanUe[anType], nil, nasMessage.Cause5GMMRestrictedServiceArea)
					return nil
				}
			}
			err := sendServiceAccept(ue, anType, ctxList, suList, acceptPduSessionPsi,
				reactivationResult, errPduSessionId, errCause)
			if err != nil {
				return err
			}
		} else {
			err := sendServiceAccept(ue, anType, ctxList, suList, acceptPduSessionPsi,
				reactivationResult, errPduSessionId, errCause)
			if err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("Service Type[%d] is not supported", serviceType)
	}
	if len(errPduSessionId) != 0 {
		logger.GmmLog.Info(errPduSessionId, errCause)
	}
	ue.N1N2Message = nil
	return nil
}

func sendServiceAccept(ue *context.AmfUe, anType models.AccessType, ctxList ngapType.PDUSessionResourceSetupListCxtReq,
	suList ngapType.PDUSessionResourceSetupListSUReq, pDUSessionStatus *[16]bool,
	reactivationResult *[16]bool, errPduSessionId, errCause []uint8) error {
	if ue.RanUe[anType].UeContextRequest {
		// update Kgnb/Kn3iwf
		ue.UpdateSecurityContext(anType)

		nasPdu, err := gmm_message.BuildServiceAccept(ue, pDUSessionStatus, reactivationResult,
			errPduSessionId, errCause)
		if err != nil {
			return err
		}
		if len(ctxList.List) != 0 {
			ngap_message.SendInitialContextSetupRequest(ue, anType, nasPdu, &ctxList, nil, nil, nil)
		} else {
			ngap_message.SendInitialContextSetupRequest(ue, anType, nasPdu, nil, nil, nil, nil)
		}
	} else if len(suList.List) != 0 {
		nasPdu, err := gmm_message.BuildServiceAccept(ue, pDUSessionStatus, reactivationResult,
			errPduSessionId, errCause)
		if err != nil {
			return err
		}
		ngap_message.SendPDUSessionResourceSetupRequest(ue.RanUe[anType], nasPdu, suList)
	} else {
		gmm_message.SendServiceAccept(ue.RanUe[anType], pDUSessionStatus, reactivationResult, errPduSessionId, errCause)
	}
	return nil
}

// TS 24.501 5.4.1
func HandleAuthenticationResponse(ue *context.AmfUe, accessType models.AccessType,
	authenticationResponse *nasMessage.AuthenticationResponse) error {

	logger.GmmLog.Info("[AMF] Handle Authentication Response")

	util.StopT3560(ue)

	if ue.AuthenticationCtx == nil {
		return fmt.Errorf("Ue Authentication Context is nil")
	}

	switch ue.AuthenticationCtx.AuthType {
	case models.AuthType__5_G_AKA:
		var av5gAka models.Av5gAka
		if err := mapstructure.Decode(ue.AuthenticationCtx.Var5gAuthData, &av5gAka); err != nil {
			return fmt.Errorf("Var5gAuthData Convert Type Error")
		}
		resStar := authenticationResponse.AuthenticationResponseParameter.GetRES()

		// Calculate HRES* (TS 33.501 Annex A.5)
		p0, err := hex.DecodeString(av5gAka.Rand)
		if err != nil {
			return err
		}
		p1 := resStar[:]
		concat := append(p0, p1...)
		hResStarBytes := sha256.Sum256(concat)
		hResStar := hex.EncodeToString(hResStarBytes[16:])

		if hResStar != av5gAka.HxresStar {
			logger.GmmLog.Errorf("HRES* Validation Failure (received: %s, expected: %s)", hResStar, av5gAka.HxresStar)

			if ue.IdentityTypeUsedForRegistration == nasMessage.MobileIdentity5GSType5gGuti {
				gmm_message.SendIdentityRequest(ue.RanUe[accessType], nasMessage.MobileIdentity5GSTypeSuci)
				return nil
			} else {
				gmm_message.SendAuthenticationReject(ue.RanUe[accessType], "")
				return GmmFSM.SendEvent(ue.State[accessType], AuthFailEvent, fsm.ArgsType{
					ArgAmfUe:      ue,
					ArgAccessType: accessType,
				})
			}
		}

		response, problemDetails, err := consumer.SendAuth5gAkaConfirmRequest(ue, hex.EncodeToString(resStar[:]))
		if err != nil {
			return err
		} else if problemDetails != nil {
			logger.GmmLog.Debugf("Auth5gAkaConfirm Error[Problem Detail: %+v]", problemDetails)
			return nil
		}
		switch response.AuthResult {
		case models.AuthResult_SUCCESS:
			ue.UnauthenticatedSupi = false
			ue.Kseaf = response.Kseaf
			ue.Supi = response.Supi
			ue.DerivateKamf()
			logger.GmmLog.Debugln("ue.DerivateKamf()", ue.Kamf)
			return GmmFSM.SendEvent(ue.State[accessType], AuthSuccessEvent, fsm.ArgsType{
				ArgAmfUe:      ue,
				ArgAccessType: accessType,
				ArgEAPSuccess: false,
				ArgEAPMessage: "",
			})
		case models.AuthResult_FAILURE:
			if ue.IdentityTypeUsedForRegistration == nasMessage.MobileIdentity5GSType5gGuti {
				gmm_message.SendIdentityRequest(ue.RanUe[accessType], nasMessage.MobileIdentity5GSTypeSuci)
				return nil
			} else {
				gmm_message.SendAuthenticationReject(ue.RanUe[accessType], "")
				return GmmFSM.SendEvent(ue.State[accessType], AuthFailEvent, fsm.ArgsType{
					ArgAmfUe:      ue,
					ArgAccessType: accessType,
				})
			}
		}
	case models.AuthType_EAP_AKA_PRIME:
		response, problemDetails, err := consumer.SendEapAuthConfirmRequest(ue, *authenticationResponse.EAPMessage)
		if err != nil {
			return err
		} else if problemDetails != nil {
			logger.GmmLog.Debugf("EapAuthConfirm Error[Problem Detail: %+v]", problemDetails)
			return nil
		}

		switch response.AuthResult {
		case models.AuthResult_SUCCESS:
			ue.UnauthenticatedSupi = false
			ue.Kseaf = response.KSeaf
			ue.Supi = response.Supi
			ue.DerivateKamf()
			// TODO: select enc/int algorithm based on ue security capability & amf's policy,
			// then generate KnasEnc, KnasInt
			return GmmFSM.SendEvent(ue.State[accessType], SecurityModeSuccessEvent, fsm.ArgsType{
				ArgAmfUe:      ue,
				ArgAccessType: accessType,
				ArgEAPSuccess: true,
				ArgEAPMessage: response.EapPayload,
			})
		case models.AuthResult_FAILURE:
			if ue.IdentityTypeUsedForRegistration == nasMessage.MobileIdentity5GSType5gGuti {
				gmm_message.SendAuthenticationResult(ue.RanUe[accessType], false, response.EapPayload)
				gmm_message.SendIdentityRequest(ue.RanUe[accessType], nasMessage.MobileIdentity5GSTypeSuci)
				return nil
			} else {
				gmm_message.SendAuthenticationReject(ue.RanUe[accessType], response.EapPayload)
				return GmmFSM.SendEvent(ue.State[accessType], AuthFailEvent, fsm.ArgsType{
					ArgAmfUe:      ue,
					ArgAccessType: accessType,
				})
			}
		case models.AuthResult_ONGOING:
			ue.AuthenticationCtx.Var5gAuthData = response.EapPayload
			if _, exists := response.Links["link"]; exists {
				ue.AuthenticationCtx.Links = response.Links
			}
			gmm_message.SendAuthenticationRequest(ue.RanUe[accessType])
		}
	}

	return nil
}

func HandleAuthenticationFailure(ue *context.AmfUe, anType models.AccessType,
	authenticationFailure *nasMessage.AuthenticationFailure) error {

	logger.GmmLog.Info("[AMF] Handle Authentication Failure")

	util.StopT3560(ue)

	cause5GMM := authenticationFailure.Cause5GMM.GetCauseValue()

	if ue.AuthenticationCtx.AuthType == models.AuthType__5_G_AKA {
		switch cause5GMM {
		case nasMessage.Cause5GMMMACFailure:
			logger.GmmLog.Warnln("Authentication Failure Cause: Mac Failure")
			gmm_message.SendAuthenticationReject(ue.RanUe[anType], "")
			return GmmFSM.SendEvent(ue.State[anType], AuthFailEvent, fsm.ArgsType{ArgAmfUe: ue, ArgAccessType: anType})
		case nasMessage.Cause5GMMNon5GAuthenticationUnacceptable:
			logger.GmmLog.Warnln("Authentication Failure Cause: Non-5G Authentication Unacceptable")
			gmm_message.SendAuthenticationReject(ue.RanUe[anType], "")
			return GmmFSM.SendEvent(ue.State[anType], AuthFailEvent, fsm.ArgsType{ArgAmfUe: ue, ArgAccessType: anType})
		case nasMessage.Cause5GMMngKSIAlreadyInUse:
			logger.GmmLog.Warnln("Authentication Failure Cause: NgKSI Already In Use")
			ue.AuthFailureCauseSynchFailureTimes = 0
			logger.GmmLog.Warnln("Select new NgKsi")
			// select new ngksi
			if ue.NgKsi.Ksi < 6 { // ksi is range from 0 to 6
				ue.NgKsi.Ksi += 1
			} else {
				ue.NgKsi.Ksi = 0
			}
			ue.T3560RetryTimes = 0
			gmm_message.SendAuthenticationRequest(ue.RanUe[anType])
		case nasMessage.Cause5GMMSynchFailure: // TS 24.501 5.4.1.3.7 case f
			logger.GmmLog.Warn("Authentication Failure 5GMM Cause: Synch Failure")

			ue.AuthFailureCauseSynchFailureTimes++
			if ue.AuthFailureCauseSynchFailureTimes >= 2 {
				logger.GmmLog.Warnf("2 consecutive Synch Failure, terminate authentication procedure")
				gmm_message.SendAuthenticationReject(ue.RanUe[anType], "")
				return GmmFSM.SendEvent(ue.State[anType], AuthFailEvent, fsm.ArgsType{ArgAmfUe: ue, ArgAccessType: anType})
			}

			auts := authenticationFailure.AuthenticationFailureParameter.GetAuthenticationFailureParameter()
			resynchronizationInfo := &models.ResynchronizationInfo{
				Auts: hex.EncodeToString(auts[:]),
			}

			response, problemDetails, err := consumer.SendUEAuthenticationAuthenticateRequest(ue, resynchronizationInfo)
			if err != nil {
				return err
			} else if problemDetails != nil {
				logger.GmmLog.Errorf("Nausf_UEAU Authenticate Request Error[Problem Detail: %+v]", problemDetails)
				return nil
			}
			ue.AuthenticationCtx = response
			ue.ABBA = []uint8{0x00, 0x00}

			ue.T3560RetryTimes = 0
			gmm_message.SendAuthenticationRequest(ue.RanUe[anType])
		}
	} else if ue.AuthenticationCtx.AuthType == models.AuthType_EAP_AKA_PRIME {
		switch cause5GMM {
		case nasMessage.Cause5GMMngKSIAlreadyInUse:
			logger.GmmLog.Warn("Authentication Failure 5GMM Cause: NgKSI Already In Use")
			if ue.NgKsi.Ksi < 6 { // ksi is range from 0 to 6
				ue.NgKsi.Ksi += 1
			} else {
				ue.NgKsi.Ksi = 0
			}
			ue.T3560RetryTimes = 0
			gmm_message.SendAuthenticationRequest(ue.RanUe[anType])
		}
	}

	return nil
}

func HandleRegistrationComplete(ue *context.AmfUe, accessType models.AccessType,
	registrationComplete *nasMessage.RegistrationComplete) error {

	logger.GmmLog.Info("[AMF] Handle Registration Complete")

	util.StopT3550(ue)

	// if registrationComplete.SORTransparentContainer != nil {
	// 	TODO: if at regsitration procedure 14b, udm provide amf Steering of Roaming info & request an ack,
	// 	AMF provides the UE's ack with Nudm_SDM_Info (SOR not supportted in this stage)
	// }

	// TODO: if
	//	1. AMF has evaluated the support of IMS Voice over PS Sessions (TS 23.501 5.16.3.2)
	//	2. AMF determines that it needs to update the Homogeneous Support of IMS Voice over PS Sessions (TS 23.501 5.16.3.3)
	// Then invoke Nudm_UECM_Update to send "Homogeneous Support of IMS Voice over PS Sessions" indication to udm

	if ue.RegistrationRequest.UplinkDataStatus == nil &&
		ue.RegistrationRequest.GetFOR() == nasMessage.FollowOnRequestNoPending {
		ngap_message.SendUEContextReleaseCommand(ue.RanUe[accessType], context.UeContextN2NormalRelease,
			ngapType.CausePresentNas, ngapType.CauseNasPresentNormalRelease)
	}
	return GmmFSM.SendEvent(ue.State[accessType], ContextSetupSuccessEvent, fsm.ArgsType{
		ArgAmfUe:      ue,
		ArgAccessType: accessType,
	})
}

// TS 33.501 6.7.2
func HandleSecurityModeComplete(ue *context.AmfUe, anType models.AccessType, procedureCode int64,
	securityModeComplete *nasMessage.SecurityModeComplete) error {

	logger.GmmLog.Info("[AMF] Handle Security Mode Complete")

	if ue.MacFailed {
		return fmt.Errorf("NAS message integrity check failed")
	}

	util.StopT3560(ue)

	if ue.SecurityContextIsValid() {
		// update Kgnb/Kn3iwf
		ue.UpdateSecurityContext(anType)
	}

	if securityModeComplete.IMEISV != nil {
		logger.GmmLog.Debugln("receieve IMEISV")
		ue.Pei = nasConvert.PeiToString(securityModeComplete.IMEISV.Octet[:])
	}

	// TODO: AMF shall set the NAS COUNTs to zero if horizontal derivation of KAMF is performed
	if securityModeComplete.NASMessageContainer != nil {
		contents := securityModeComplete.NASMessageContainer.GetNASMessageContainerContents()
		m := nas.NewMessage()
		if err := m.GmmMessageDecode(&contents); err != nil {
			return err
		}

		messageType := m.GmmMessage.GmmHeader.GetMessageType()
		if messageType != nas.MsgTypeRegistrationRequest && messageType != nas.MsgTypeServiceRequest {
			logger.GmmLog.Errorln("nas message container Iei type error")
			return errors.New("nas message container Iei type error")
		} else {
			return GmmFSM.SendEvent(ue.State[anType], SecurityModeSuccessEvent, fsm.ArgsType{
				ArgAmfUe:         ue,
				ArgAccessType:    anType,
				ArgProcedureCode: procedureCode,
				ArgNASMessage:    m.GmmMessage.RegistrationRequest,
			})
		}
	}
	return GmmFSM.SendEvent(ue.State[anType], SecurityModeSuccessEvent, fsm.ArgsType{
		ArgAmfUe:         ue,
		ArgAccessType:    anType,
		ArgProcedureCode: procedureCode,
		ArgNASMessage:    ue.RegistrationRequest,
	})
}

func HandleSecurityModeReject(ue *context.AmfUe, anType models.AccessType,
	securityModeReject *nasMessage.SecurityModeReject) error {

	logger.GmmLog.Info("[AMF] Handle Security Mode Reject")

	util.StopT3560(ue)

	cause := securityModeReject.Cause5GMM.GetCauseValue()
	logger.GmmLog.Warnf("Reject Cause: %s", nasMessage.Cause5GMMToString(cause))
	logger.GmmLog.Errorf("UE[%s] reject the security mode command, abort the ongoing procedure", ue.Supi)
	return nil
}

// TS 23.502 4.2.2.3
func HandleDeregistrationRequest(ue *context.AmfUe, anType models.AccessType,
	deregistrationRequest *nasMessage.DeregistrationRequestUEOriginatingDeregistration) error {

	logger.GmmLog.Info("[AMF] Handle Deregistration Request(UE Originating)")

	targetDeregistrationAccessType := deregistrationRequest.GetAccessType()
	for pduSessionId, smContext := range ue.SmContextList {
		if smContext.PduSessionContext.AccessType != anType &&
			targetDeregistrationAccessType != nasMessage.AccessTypeBoth {
			continue
		}

		releaseData := consumer.BuildReleaseSmContextRequest(ue, nil, "", nil)
		problemDetail, err := consumer.SendReleaseSmContextRequest(ue, pduSessionId, releaseData)
		if problemDetail != nil {
			logger.GmmLog.Errorf("Release SmContext Failed Problem[%+v]", problemDetail)
		} else if err != nil {
			logger.GmmLog.Errorf("Release SmContext Error[%v]", err.Error())
		}
	}

	if ue.AmPolicyAssociation != nil {
		terminateAmPolicyAssocaition := true
		switch anType {
		case models.AccessType__3_GPP_ACCESS:
			terminateAmPolicyAssocaition = ue.State[models.AccessType_NON_3_GPP_ACCESS].Is(context.Deregistered)
		case models.AccessType_NON_3_GPP_ACCESS:
			terminateAmPolicyAssocaition = ue.State[models.AccessType__3_GPP_ACCESS].Is(context.Deregistered)
		}

		if terminateAmPolicyAssocaition {
			problemDetails, err := consumer.AMPolicyControlDelete(ue)
			if problemDetails != nil {
				logger.GmmLog.Errorf("AM Policy Control Delete Failed Problem[%+v]", problemDetails)
			} else if err != nil {
				logger.GmmLog.Errorf("AM Policy Control Delete Error[%v]", err.Error())
			}
		}
	}

	// if Deregistration type is not switch-off, send Deregistration Accept
	if deregistrationRequest.GetSwitchOff() == 0 {
		gmm_message.SendDeregistrationAccept(ue.RanUe[anType])
	}

	// TS 23.502 4.2.6, 4.12.3
	switch targetDeregistrationAccessType {
	case nasMessage.AccessType3GPP:
		if ue.RanUe[models.AccessType__3_GPP_ACCESS] != nil {
			ngap_message.SendUEContextReleaseCommand(ue.RanUe[models.AccessType__3_GPP_ACCESS],
				context.UeContextReleaseUeContext, ngapType.CausePresentNas, ngapType.CauseNasPresentDeregister)
		}
		return GmmFSM.SendEvent(ue.State[models.AccessType__3_GPP_ACCESS], DeregistrationAcceptEvent, fsm.ArgsType{
			ArgAmfUe:      ue,
			ArgAccessType: anType,
		})
	case nasMessage.AccessTypeNon3GPP:
		if ue.RanUe[models.AccessType_NON_3_GPP_ACCESS] != nil {
			ngap_message.SendUEContextReleaseCommand(ue.RanUe[models.AccessType_NON_3_GPP_ACCESS],
				context.UeContextReleaseUeContext, ngapType.CausePresentNas, ngapType.CauseNasPresentDeregister)
		}
		return GmmFSM.SendEvent(ue.State[models.AccessType_NON_3_GPP_ACCESS], DeregistrationAcceptEvent, fsm.ArgsType{
			ArgAmfUe:      ue,
			ArgAccessType: anType,
		})
	case nasMessage.AccessTypeBoth:
		if ue.RanUe[models.AccessType__3_GPP_ACCESS] != nil {
			ngap_message.SendUEContextReleaseCommand(ue.RanUe[models.AccessType__3_GPP_ACCESS],
				context.UeContextReleaseUeContext, ngapType.CausePresentNas, ngapType.CauseNasPresentDeregister)
		}
		if ue.RanUe[models.AccessType_NON_3_GPP_ACCESS] != nil {
			ngap_message.SendUEContextReleaseCommand(ue.RanUe[models.AccessType_NON_3_GPP_ACCESS],
				context.UeContextReleaseUeContext, ngapType.CausePresentNas, ngapType.CauseNasPresentDeregister)
		}

		err := GmmFSM.SendEvent(ue.State[models.AccessType__3_GPP_ACCESS], DeregistrationAcceptEvent, fsm.ArgsType{
			ArgAmfUe:      ue,
			ArgAccessType: anType,
		})
		if err != nil {
			logger.GmmLog.Errorln(err)
		}
		return GmmFSM.SendEvent(ue.State[models.AccessType_NON_3_GPP_ACCESS], DeregistrationAcceptEvent, fsm.ArgsType{
			ArgAmfUe:      ue,
			ArgAccessType: anType,
		})
	}

	return nil
}

// TS 23.502 4.2.2.3
func HandleDeregistrationAccept(ue *context.AmfUe, anType models.AccessType,
	deregistrationAccept *nasMessage.DeregistrationAcceptUETerminatedDeregistration) error {

	logger.GmmLog.Info("[AMF] Handle Deregistration Accept(UE Terminated)")

	util.StopT3522(ue)

	switch ue.DeregistrationTargetAccessType {
	case nasMessage.AccessType3GPP:
		if ue.RanUe[models.AccessType__3_GPP_ACCESS] != nil {
			ngap_message.SendUEContextReleaseCommand(ue.RanUe[models.AccessType__3_GPP_ACCESS],
				context.UeContextReleaseUeContext, ngapType.CausePresentNas, ngapType.CauseNasPresentDeregister)
		}
	case nasMessage.AccessTypeNon3GPP:
		if ue.RanUe[models.AccessType_NON_3_GPP_ACCESS] != nil {
			ngap_message.SendUEContextReleaseCommand(ue.RanUe[models.AccessType_NON_3_GPP_ACCESS],
				context.UeContextReleaseUeContext, ngapType.CausePresentNas, ngapType.CauseNasPresentDeregister)
		}
	case nasMessage.AccessTypeBoth:
		if ue.RanUe[models.AccessType__3_GPP_ACCESS] != nil {
			ngap_message.SendUEContextReleaseCommand(ue.RanUe[models.AccessType__3_GPP_ACCESS],
				context.UeContextReleaseUeContext, ngapType.CausePresentNas, ngapType.CauseNasPresentDeregister)
		}
		if ue.RanUe[models.AccessType_NON_3_GPP_ACCESS] != nil {
			ngap_message.SendUEContextReleaseCommand(ue.RanUe[models.AccessType_NON_3_GPP_ACCESS],
				context.UeContextReleaseUeContext, ngapType.CausePresentNas, ngapType.CauseNasPresentDeregister)
		}
	}

	ue.DeregistrationTargetAccessType = 0
	return nil
}

func HandleStatus5GMM(ue *context.AmfUe, anType models.AccessType, status5GMM *nasMessage.Status5GMM) error {

	logger.GmmLog.Info("Handle Staus 5GMM")
	if ue.MacFailed {
		return fmt.Errorf("NAS message integrity check failed")
	}

	cause := status5GMM.Cause5GMM.GetCauseValue()
	logger.GmmLog.Errorf("Error condition [Cause Value: %s]", nasMessage.Cause5GMMToString(cause))
	return nil
}

func HandleStatus5GSM(ue *context.AmfUe, anType models.AccessType, payload []byte, pduSessionID int32) (err error) {

	logger.GmmLog.Info("[AMF] Handle Status5GSM")
	smContext, ok := ue.SmContextList[pduSessionID]
	if !ok {
		err = fmt.Errorf("PDU Session ID[%d] in Status 5GSM Procedure is not exist\n", pduSessionID)
		logger.GmmLog.Errorf(err.Error())
		gmm_message.SendDLNASTransport(ue.RanUe[anType], nasMessage.PayloadContainerTypeN1SMInfo,
			payload, pduSessionID, nasMessage.Cause5GMMPayloadWasNotForwarded, nil, 0)
		return
	}
	smContextUpdateData := models.SmContextUpdateData{
		N1SmMsg: &models.RefToBinaryData{
			ContentId: "N1SmMsg",
		},
	}

	_, _, _, err = consumer.SendUpdateSmContextRequest(ue, smContext.SmfUri, smContext.PduSessionContext.SmContextRef,
		smContextUpdateData, payload, nil)
	if err != nil {
		return err
	}

	return nil
}
