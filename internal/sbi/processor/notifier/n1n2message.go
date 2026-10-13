package callback

import (
	"strconv"

	"github.com/sirupsen/logrus"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"
	Namf_Communication "github.com/free5gc/openapi/amf/Comm"
	"github.com/free5gc/openapi/mediatype/multipart"
	"github.com/free5gc/openapi/models"
)

var HttpLog *logrus.Entry

func init() {
	HttpLog = logger.HttpLog
}

func SendN1N2TransferFailureNotification(ue *amf_context.AmfUe, cause models.Amf_Comm_N1N2MessageTransferCause) {
	if ue.N1N2Message == nil {
		return
	}
	n1n2Message := ue.N1N2Message
	uri := n1n2Message.Request.JsonData.N1n2FailureTxfNotifURI
	if n1n2Message.Status == models.Amf_Comm_N1N2MessageTransferCause_ATTEMPTING_TO_REACH_UE && uri != "" {
		configuration := Namf_Communication.NewConfiguration()
		client := Namf_Communication.NewAPIClient(configuration)

		n1N2MsgTxfrFailureNotificationReq := Namf_Communication.N1N2TransferFailureNotificationRequest{
			RequestBody: &models.Amf_Comm_N1N2MsgTxfrFailureNotification{
				Cause:          cause,
				N1n2MsgDataUri: n1n2Message.ResourceUri,
			},
		}

		ctx, pd, err := amf_context.GetSelf().GetTokenCtxForNFInstance(
			models.Nrf_NFMgmt_ServiceName("namf-callback"), models.Nrf_NFMgmt_NFType_SMF,
			n1n2Message.Request.JsonData.NfId)
		if err != nil {
			HttpLog.Warnf("SendN1N2TransferFailureNotification get token failed: %+v", pd)
			return
		}

		_, err = client.N1N2MessageCollectionCollectionApi.
			N1N2TransferFailureNotification(ctx, uri, &n1N2MsgTxfrFailureNotificationReq)

		if err != nil {
			HttpLog.Errorln(err.Error())
		} else {
			ue.N1N2Message = nil
		}
	}
}

func SendN1MessageNotify(ue *amf_context.AmfUe, n1class models.Amf_Comm_N1MessageClass, n1Msg []byte,
	registerContext *models.Amf_Comm_RegistrationContextContainer,
) {
	ue.N1N2MessageSubscription.Range(func(key, value interface{}) bool {
		subscriptionID := key.(int64)
		subscription := value.(models.Amf_Comm_UeN1N2InfoSubscriptionCreateData)

		if subscription.N1NotifyCallbackUri != "" && subscription.N1MessageClass == n1class {
			configuration := Namf_Communication.NewConfiguration()
			client := Namf_Communication.NewAPIClient(configuration)
			n1MessageNotify := models.N1MessageNotifyRequestBody{
				JsonData: &models.Amf_Comm_N1MessageNotification{
					N1NotifySubscriptionId: strconv.Itoa(int(subscriptionID)),
					N1MessageContainer: &models.Amf_Comm_N1MessageContainer{
						N1MessageClass: subscription.N1MessageClass,
						N1MessageContent: &models.RefToBinaryData{
							ContentId: "n1Msg",
						},
					},
					RegistrationCtxtContainer: registerContext,
				},
				BinaryDataN1Message: &multipart.RelatedContent{
					ContentID: "n1Msg",
					Content:   n1Msg,
				},
			}

			n1MessageNotifyReq := Namf_Communication.N1MessageNotifyRequest{
				RequestBody: &n1MessageNotify,
			}

			ctx, pd, err := amf_context.GetSelf().GetTokenCtxForNFInstance(
				models.Nrf_NFMgmt_ServiceName("namf-callback"), models.Nrf_NFMgmt_NFType_SMF, subscription.NfId)
			if err != nil {
				HttpLog.Warnf("SendN1MessageNotify get token failed: %+v", pd)
				return false
			}

			_, err = client.N1N2SubscriptionsCollectionForIndividualUEContextsCollectionApi.
				N1MessageNotify(ctx, subscription.N1NotifyCallbackUri, &n1MessageNotifyReq)
			if err != nil {
				HttpLog.Errorln(err.Error())
			}
		}
		return true
	})
}

// TS 29.518 5.2.2.3.5.2
func SendN1MessageNotifyAtAMFReAllocation(
	ue *amf_context.AmfUe, n1Msg []byte, registerContext *models.Amf_Comm_RegistrationContextContainer,
) error {
	logger.CommLog.Infoln("Send N1 Message Notify at AMF Re-allocation")
	configuration := Namf_Communication.NewConfiguration()
	client := Namf_Communication.NewAPIClient(configuration)

	n1MessageNotify := models.N1MessageNotifyRequestBody{
		JsonData: &models.Amf_Comm_N1MessageNotification{
			N1MessageContainer: &models.Amf_Comm_N1MessageContainer{
				N1MessageClass: models.Amf_Comm_N1MessageClass_5_GMM,
				N1MessageContent: &models.RefToBinaryData{
					ContentId: "n1Msg",
				},
			},
			RegistrationCtxtContainer: registerContext,
		},
		BinaryDataN1Message: &multipart.RelatedContent{
			ContentID: "n1Msg",
			Content:   n1Msg,
		},
	}

	n1MessageNotifyReq := Namf_Communication.N1MessageNotifyRequest{
		RequestBody: &n1MessageNotify,
	}

	var callbackUri string
	for _, subscription := range ue.TargetAmfProfile.DefaultNotificationSubscriptions {
		if subscription.NotificationType == models.Nrf_NFMgmt_NotificationType_N1_MESSAGES &&
			subscription.N1MessageClass == models.Amf_Comm_N1MessageClass_5_GMM {
			callbackUri = subscription.CallbackUri
			break
		}
	}

	ctx, pd, err := amf_context.GetSelf().GetTokenCtxForNFInstance(
		models.Nrf_NFMgmt_ServiceName("namf-callback"), models.Nrf_NFMgmt_NFType_AMF,
		ue.TargetAmfProfile.NfInstanceId)
	if err != nil {
		HttpLog.Warnf("SendN1MessageNotifyAtAMFReAllocation get token failed: %+v", pd)
		return err
	}

	_, err = client.N1N2SubscriptionsCollectionForIndividualUEContextsCollectionApi.
		N1MessageNotify(ctx, callbackUri, &n1MessageNotifyReq)
	if err != nil {
		HttpLog.Errorln(err.Error())
		return err
	}
	return nil
}

func SendN2InfoNotify(ue *amf_context.AmfUe, n2class models.Amf_Comm_N2InformationClass, n1Msg, n2Msg []byte) {
	ue.N1N2MessageSubscription.Range(func(key, value interface{}) bool {
		subscriptionID := key.(int64)
		subscription := value.(models.Amf_Comm_UeN1N2InfoSubscriptionCreateData)

		if subscription.N2NotifyCallbackUri != "" && subscription.N2InformationClass == n2class {
			configuration := Namf_Communication.NewConfiguration()
			client := Namf_Communication.NewAPIClient(configuration)

			n2InformationNotify := models.N2InfoNotifyRequestBody{
				JsonData: &models.Amf_Comm_N2InformationNotification{
					N2NotifySubscriptionId: strconv.Itoa(int(subscriptionID)),
					N2InfoContainer: &models.Amf_Comm_N2InfoContainer{
						N2InformationClass: n2class,
					},
				},
				BinaryDataN1Message: &multipart.RelatedContent{
					ContentID: "n1Msg",
					Content:   n1Msg,
				},
				BinaryDataN2Information: &multipart.RelatedContent{
					ContentID: "n2Info",
					Content:   n2Msg,
				},
			}
			if n2Msg == nil {
				HttpLog.Errorln("Send N2 Info Notify Error(N2 Info does not exist)")
			}
			switch n2class {
			case models.Amf_Comm_N2InformationClass_SM:
				n2InformationNotify.JsonData.N2InfoContainer.SmInfo = &models.Amf_Comm_N2SmInformation{
					N2InfoContent: &models.Amf_Comm_N2InfoContent{
						NgapData: &models.RefToBinaryData{
							ContentId: "n2Info",
						},
					},
				}
			case models.Amf_Comm_N2InformationClass_NRP_PA:
				n2InformationNotify.JsonData.N2InfoContainer.NrppaInfo = &models.Amf_Comm_NrppaInformation{
					NrppaPdu: &models.Amf_Comm_N2InfoContent{
						NgapData: &models.RefToBinaryData{
							ContentId: "n2Info",
						},
					},
				}
			case models.Amf_Comm_N2InformationClass_PWS,
				models.Amf_Comm_N2InformationClass_PWS_BCAL,
				models.Amf_Comm_N2InformationClass_PWS_RF:
				n2InformationNotify.JsonData.N2InfoContainer.PwsInfo = &models.Amf_Comm_PwsInformation{
					PwsContainer: &models.Amf_Comm_N2InfoContent{
						NgapData: &models.RefToBinaryData{
							ContentId: "n2Info",
						},
					},
				}
			case models.Amf_Comm_N2InformationClass_RAN:
				n2InformationNotify.JsonData.N2InfoContainer.RanInfo = &models.Amf_Comm_N2RanInformation{
					N2InfoContent: &models.Amf_Comm_N2InfoContent{
						NgapData: &models.RefToBinaryData{
							ContentId: "n2Info",
						},
					},
				}
			}

			n2InformationNotifyReq := Namf_Communication.N2InfoNotifyRequest{
				RequestBody: &n2InformationNotify,
			}

			ctx, pd, err := amf_context.GetSelf().GetTokenCtxForNFInstance(
				models.Nrf_NFMgmt_ServiceName("namf-callback"), models.Nrf_NFMgmt_NFType_SMF, subscription.NfId)
			if err != nil {
				HttpLog.Warnf("SendN2InfoNotify get token failed: %+v", pd)
				return false
			}

			_, err = client.N1N2SubscriptionsCollectionForIndividualUEContextsCollectionApi.
				N2InfoNotify(ctx, subscription.N2NotifyCallbackUri, &n2InformationNotifyReq)
			if err != nil {
				HttpLog.Errorln(err.Error())
			}
		}
		return true
	})
}
