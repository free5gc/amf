package handler

import (
	"free5gc/lib/nas/nasMessage"
	"free5gc/lib/openapi/models"
	"free5gc/src/amf/context"
	gmm_message "free5gc/src/amf/gmm/message"
	"free5gc/src/amf/gmm/state"
	amf_message "free5gc/src/amf/handler/message"
	"free5gc/src/amf/logger"
	"free5gc/src/amf/ngap"
	ngap_message "free5gc/src/amf/ngap/message"
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
					value, ok := amfSelf.AmfRanPool.Load(msg.NgapAddr)
					if !ok {
						HandlerLog.Warn("Cannot find the coressponding RAN Context\n")
					} else {
						ran := value.(*context.AmfRan)
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
						continue
					}
					amfUe := ranUe.AmfUe
					if amfUe == nil {
						HandlerLog.Warn("AmfUe is nil")
						continue
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
						continue
					}
					amfUe := ranUe.AmfUe
					if amfUe == nil {
						HandlerLog.Warn("AmfUe is nil")
						continue
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
						continue
					}
					amfUe := value.RanUe.AmfUe
					if amfUe == nil {
						HandlerLog.Warn("AmfUe is nil")
						continue
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
						continue
					}
					amfUe := value.RanUe.AmfUe
					if amfUe == nil {
						HandlerLog.Warn("AmfUe is nil")
						continue
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
