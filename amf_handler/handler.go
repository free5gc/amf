package amf_handler

import (
	"free5gc/lib/nas/nasMessage"
	"free5gc/lib/openapi/models"
	"free5gc/src/amf/amf_handler/amf_message"
	"free5gc/src/amf/context"
	gmm_message "free5gc/src/amf/gmm/message"
	"free5gc/src/amf/gmm/state"
	"free5gc/src/amf/logger"
	"free5gc/src/amf/ngap"
	"free5gc/src/amf/ngap/message"
	"free5gc/src/amf/producer"
	"free5gc/src/amf/producer/callback"
	"free5gc/src/amf/util"
	"net"
	"time"

	"github.com/sirupsen/logrus"
)

var HandlerLog *logrus.Entry

func init() {
	// init Pool
	HandlerLog = logger.HandlerLog
}

func Handle() {
	for {
		select {
		case msg, ok := <-amf_message.AmfChannel:
			if ok {
				switch msg.Event {
				case amf_message.EventNGAPMessage:
					ngap.Dispatch(msg.NgapAddr, msg.Value.([]byte))

				case amf_message.EventNGAPAcceptConn:
					amfSelf := context.AMF_Self()
					amfSelf.NewAmfRan(msg.Value.(net.Conn))

				case amf_message.EventNGAPCloseConn:
					amfSelf := context.AMF_Self()
					ran, ok := amfSelf.AmfRanPool[msg.NgapAddr]
					if !ok {
						HandlerLog.Warn("Cannot find the coressponding RAN Context\n")
					} else {
						ran.Remove(msg.NgapAddr)
					}
				case amf_message.EventGMMT3513:
					amfUe, ok := msg.Value.(*context.AmfUe)
					if !ok || amfUe == nil {
						HandlerLog.Warn("Timer T3513 Parameter Error\n")
					}
					amfUe.PagingRetryTimes++
					logger.GmmLog.Infof("Paging UE[%s] expired for the %dth times", amfUe.Supi, amfUe.PagingRetryTimes)
					if amfUe.PagingRetryTimes >= context.MaxPagingRetryTime {
						logger.GmmLog.Warnf("Paging to UE[%s] failed. Stop paging", amfUe.Supi)
						if amfUe.OnGoing[models.AccessType__3_GPP_ACCESS].Procedure != context.OnGoingProcedureN2Handover {
							callback.SendN1N2TransferFailureNotification(amfUe, models.N1N2MessageTransferCause_UE_NOT_RESPONDING)
						}
						util.ClearT3513(amfUe)
					} else {
						ngap_message.SendPaging(amfUe, amfUe.LastPagingPkg)
					}
				case amf_message.EventGMMT3565:
					ranUe, ok := msg.Value.(*context.RanUe)
					if !ok || ranUe == nil {
						HandlerLog.Warn("Timer T3565 Parameter Error")
						return
					}
					amfUe := ranUe.AmfUe
					if amfUe == nil {
						HandlerLog.Warn("AmfUe is nil")
						return
					}
					amfUe.NotificationRetryTimes++
					logger.GmmLog.Infof("UE[%s] Notification expired for the %dth times", amfUe.Supi, amfUe.NotificationRetryTimes)
					if amfUe.NotificationRetryTimes >= context.MaxNotificationRetryTime {
						logger.GmmLog.Warnf("UE[%s] Notification failed. Stop Notification", amfUe.Supi)
						if amfUe.OnGoing[models.AccessType__3_GPP_ACCESS].Procedure != context.OnGoingProcedureN2Handover {
							callback.SendN1N2TransferFailureNotification(amfUe, models.N1N2MessageTransferCause_UE_NOT_RESPONDING)
						}
						util.ClearT3565(amfUe)
					} else {
						gmm_message.SendNotification(ranUe, amfUe.LastNotificationPkg)
					}
				case amf_message.EventGMMT3560ForAuthenticationRequest:
					ranUe, ok := msg.Value.(*context.RanUe)
					if !ok || ranUe == nil {
						HandlerLog.Warn("Timer T3560 Parameter Error")
						return
					}
					amfUe := ranUe.AmfUe
					if amfUe == nil {
						HandlerLog.Warn("AmfUe is nil")
						return
					}
					if amfUe.T3560RetryTimes >= context.MaxT3560RetryTimes {
						logger.GmmLog.Warnf("T3560 Expires 5 times, abort authentication procedure & ongoing 5GMM procedure")
						util.ClearT3560(amfUe)
						amfUe.Remove() // release n1 nas signalling connection
					} else {
						amfUe.T3560RetryTimes++
						gmm_message.SendAuthenticationRequest(ranUe)
					}
				case amf_message.EventGMMT3560ForSecurityModeCommand:
					value, ok := msg.Value.(amf_message.EventGMMT3560ValueForSecurityCommand)
					if !ok || value.RanUe == nil {
						HandlerLog.Warn("Timer T3560 Parameter Error")
						return
					}
					amfUe := value.RanUe.AmfUe
					if amfUe == nil {
						HandlerLog.Warn("AmfUe is nil")
						return
					}
					if amfUe.T3560RetryTimes >= context.MaxT3560RetryTimes {
						logger.GmmLog.Warnf("T3560 Expires 5 times, abort security mode procedure")
						util.ClearT3560(amfUe)
					} else {
						amfUe.T3560RetryTimes++
						gmm_message.SendSecurityModeCommand(value.RanUe, value.EapSuccess, value.EapMessage)
					}
				case amf_message.EventGMMT3550:
					value, ok := msg.Value.(amf_message.EventGMMT3550Value)
					if !ok || value.AmfUe == nil {
						HandlerLog.Warn("Timer T3550 Parameter Error\n")
					}
					amfUe := value.AmfUe
					if amfUe.T3550RetryTimes >= context.MaxT3550RetryTimes {
						logger.GmmLog.Warnf("T3550 Expires 5 times, abort retransmission")
						if amfUe.RegistrationType5GS == nasMessage.RegistrationType5GSInitialRegistration {
							if err := amfUe.Sm[value.AccessType].Transfer(state.REGISTERED, nil); err != nil {
								HandlerLog.Errorf("Fsm Error[%+v]", err)
							}
						}
						amfUe.ClearRegistrationRequestData()
						util.ClearT3550(amfUe)
					} else {
						amfUe.T3550RetryTimes++
						gmm_message.SendRegistrationAccept(amfUe, value.AccessType, value.PDUSessionStatus,
							value.ReactivationResult, value.ErrPduSessionId, value.ErrCause, value.PduSessionResourceSetupList)
					}
				case amf_message.EventGMMT3522:
					value, ok := msg.Value.(amf_message.EventGMMT3522Value)
					if !ok || value.RanUe == nil {
						HandlerLog.Warn("Timer T3522 Parameter Error")
						return
					}
					amfUe := value.RanUe.AmfUe
					if amfUe == nil {
						HandlerLog.Warn("AmfUe is nil")
						return
					}
					if amfUe.T3522RetryTimes >= context.MaxT3522RetryTimes {
						logger.GmmLog.Warnf("T3522 Expires 5 times, abort deregistration procedure")
						if value.AccessType == nasMessage.AccessType3GPP {
							if err := amfUe.Sm[models.AccessType__3_GPP_ACCESS].Transfer(state.DE_REGISTERED, nil); err != nil {
								HandlerLog.Errorf("Fsm Error[%+v]", err)
							}
						} else if value.AccessType == nasMessage.AccessTypeNon3GPP {
							if err := amfUe.Sm[models.AccessType_NON_3_GPP_ACCESS].Transfer(state.DE_REGISTERED, nil); err != nil {
								HandlerLog.Errorf("Fsm Error[%+v]", err)
							}
						} else {
							if err := amfUe.Sm[models.AccessType__3_GPP_ACCESS].Transfer(state.DE_REGISTERED, nil); err != nil {
								HandlerLog.Errorf("Fsm Error[%+v]", err)
							}
							if err := amfUe.Sm[models.AccessType_NON_3_GPP_ACCESS].Transfer(state.DE_REGISTERED, nil); err != nil {
								HandlerLog.Errorf("Fsm Error[%+v]", err)
							}
						}
						util.ClearT3522(amfUe)
					} else {
						amfUe.T3522RetryTimes++
						gmm_message.SendDeregistrationRequest(value.RanUe, value.AccessType, value.ReRegistrationRequired, value.Cause5GMM)
					}
				case amf_message.EventN1N2MessageTransfer:
					ueContextId := msg.HTTPRequest.Params["ueContextId"]
					reqUri := msg.HTTPRequest.Params["reqUri"]
					producer.HandleN1N2MessageTransferRequest(msg.ResponseChan, ueContextId, reqUri, msg.HTTPRequest.Body.(models.N1N2MessageTransferRequest))
				case amf_message.EventN1N2MessageTransferStatus:
					ueContextId := msg.HTTPRequest.Params["ueContextId"]
					reqUri := msg.HTTPRequest.Params["reqUri"]
					producer.HandleN1N2MessageTransferStatusRequest(msg.ResponseChan, ueContextId, reqUri)
				case amf_message.EventProvideDomainSelectionInfo:
					infoClass := msg.HTTPRequest.Query.Get("info-class")
					ueContextId := msg.HTTPRequest.Params["ueContextId"]
					HandlerLog.Traceln("handle Provide Domain Selection Start")
					producer.HandleProvideDomainSelectionInfoRequest(msg.ResponseChan, ueContextId, infoClass)
					HandlerLog.Traceln("handle Provide Domain Selection End")
				case amf_message.EventProvideLocationInfo:
					ueContextId := msg.HTTPRequest.Params["ueContextId"]
					producer.HandleProvideLocationInfoRequest(msg.ResponseChan, ueContextId, msg.HTTPRequest.Body.(models.RequestLocInfo))
				case amf_message.EventN1N2MessageSubscribe:
					ueContextId := msg.HTTPRequest.Params["ueContextId"]
					producer.HandleN1N2MessageSubscirbeRequest(msg.ResponseChan, ueContextId, msg.HTTPRequest.Body.(models.UeN1N2InfoSubscriptionCreateData))
				case amf_message.EventN1N2MessageUnSubscribe:
					ueContextId := msg.HTTPRequest.Params["ueContextId"]
					subscriptionId := msg.HTTPRequest.Params["subscriptionId"]
					producer.HandleN1N2MessageUnSubscribeRequest(msg.ResponseChan, ueContextId, subscriptionId)
				case amf_message.EventCreateUEContext:
					ueContextId := msg.HTTPRequest.Params["ueContextId"]
					producer.HandleCreateUeContextRequest(msg.ResponseChan, ueContextId, msg.HTTPRequest.Body.(models.CreateUeContextRequest))
				case amf_message.EventSmContextStatusNotify:
					guti := msg.HTTPRequest.Params["guti"]
					pduSessionId := msg.HTTPRequest.Params["pduSessionId"]
					producer.HandleSmContextStatusNotify(msg.ResponseChan, guti, pduSessionId, msg.HTTPRequest.Body.(models.SmContextStatusNotification))
				case amf_message.EventUEContextRelease:
					ueContextId := msg.HTTPRequest.Params["ueContextId"]
					producer.HandleUEContextReleaseRequest(msg.ResponseChan, ueContextId, msg.HTTPRequest.Body.(models.UeContextRelease))
				case amf_message.EventUEContextTransfer:
					ueContextId := msg.HTTPRequest.Params["ueContextId"]
					producer.HandleUEContextTransferRequest(msg.ResponseChan, ueContextId, msg.HTTPRequest.Body.(models.UeContextTransferRequest))
				case amf_message.EventEBIAssignment:
					ueContextId := msg.HTTPRequest.Params["ueContextId"]
					producer.HandleAssignEbiDataRequest(msg.ResponseChan, ueContextId, msg.HTTPRequest.Body.(models.AssignEbiData))
				case amf_message.EventAMFStatusChangeSubscribe:
					producer.HandleAMFStatusChangeSubscribeRequest(msg.ResponseChan, msg.HTTPRequest.Body.(models.SubscriptionData))
				case amf_message.EventAMFStatusChangeUnSubscribe:
					subscriptionId := msg.HTTPRequest.Params["subscriptionId"]
					producer.HandleAMFStatusChangeUnSubscribeRequest(msg.ResponseChan, subscriptionId)
				case amf_message.EventAMFStatusChangeSubscribeModfy:
					subscriptionId := msg.HTTPRequest.Params["subscriptionId"]
					producer.HandleAMFStatusChangeSubscribeModfy(msg.ResponseChan, subscriptionId, msg.HTTPRequest.Body.(models.SubscriptionData))
				case amf_message.EventRegistrationStatusUpdate:
					ueContextId := msg.HTTPRequest.Params["ueContextId"]
					producer.HandleRegistrationStatusUpdateRequest(msg.ResponseChan, ueContextId, msg.HTTPRequest.Body.(models.UeRegStatusUpdateReqData))
				case amf_message.EventAmPolicyControlUpdateNotifyUpdate:
					polAssoId := msg.HTTPRequest.Params["polAssoId"]
					producer.HandleAmPolicyControlUpdateNotifyUpdate(msg.ResponseChan, polAssoId, msg.HTTPRequest.Body.(models.PolicyUpdate))
				case amf_message.EventAmPolicyControlUpdateNotifyTerminate:
					polAssoId := msg.HTTPRequest.Params["polAssoId"]
					producer.HandleAmPolicyControlUpdateNotifyTerminate(msg.ResponseChan, polAssoId, msg.HTTPRequest.Body.(models.TerminationNotification))
				case amf_message.EventOAMRegisteredUEContext:
					supi := msg.HTTPRequest.Params["supi"]
					producer.HandleOAMRegisteredUEContext(msg.ResponseChan, supi)
				case amf_message.EventN1MessageNotify:
					producer.HandleN1MessageNotify(msg.ResponseChan, msg.HTTPRequest.Body.(models.N1MessageNotify))
				default:
					HandlerLog.Warnf("Event[%d] has not implemented", msg.Event)
				}
			} else {
				HandlerLog.Errorln("Channel closed!")
			}

		case <-time.After(time.Second * 1):

		}
	}
}
