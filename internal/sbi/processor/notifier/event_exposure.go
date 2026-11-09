package callback

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	amf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	Nnrf_NFDiscovery "github.com/free5gc/openapi/nrf/NFDisc"
)

var eventNotifyClient = &http.Client{
	Timeout: 5 * time.Second,
	// The destination is a subscriber-supplied callback URI (TS 29.518
	// eventNotifyUri); following a redirect would let it retarget the
	// OAuth-bearing POST to a host we never validated.
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// SendAmfEventNotify delivers a Namf_EventExposure notification (TS 29.518
// §5.2.3, Nnwdaf... callback naming in the generated model aside, this is
// the AmfEventNotification body) to sub's callback URI.
//
// sub.EventNotifyUri is attacker-controlled input: it is whatever the
// subscriber supplied when creating the subscription. Before sending
// anything to it - and in particular before attaching an OAuth2 token to
// the request - this:
//  1. requires https,
//  2. rejects hosts that resolve to loopback/private/link-local/multicast
//     addresses (closes SSRF to internal services and cloud metadata
//     endpoints),
//  3. verifies the host against the subscribing NF's own profile on file at
//     the NRF (fqdn/ipv4Addresses/ipv6Addresses) rather than trusting
//     anything derived from the URI itself, and only then
//  4. requests an OAuth2 token scoped to that NRF-verified NF type.
//
// A request that fails any of these is dropped; it never reaches the
// network, and no token is ever requested for it.
func SendAmfEventNotify(sub *models.Amf_Comm_ExtAmfEventSubscription, reportList []models.Amf_EvtExpos_AmfEventReport) {
	if sub == nil || sub.EventNotifyUri == "" || len(reportList) == 0 {
		return
	}

	parsedURI, err := url.Parse(sub.EventNotifyUri)
	if err != nil || parsedURI.Scheme != "https" {
		HttpLog.Warnf("SendAmfEventNotify: rejecting notifyUri %q (must be a valid https URL)", sub.EventNotifyUri)
		return
	}
	host := parsedURI.Hostname()
	if !isNotifyDestinationSafe(sub, host) {
		HttpLog.Warnf("SendAmfEventNotify: rejecting notifyUri %q (failed destination check)", sub.EventNotifyUri)
		return
	}

	amfSelf := amf_context.GetSelf()

	body, err := json.Marshal(models.Amf_EvtExpos_AmfEventNotification{
		NotifyCorrelationId: sub.NotifyCorrelationId,
		ReportList:          reportList,
	})
	if err != nil {
		HttpLog.Errorf("SendAmfEventNotify marshal failed: %+v", err)
		return
	}

	// The destination host is now NRF-verified; sub.SourceNfType (also
	// self-reported, like NfId) only picks the token's audience, it does
	// not influence where the request goes.
	ctx, pd, err := amfSelf.GetTokenCtx("", sub.SourceNfType)
	if err != nil {
		HttpLog.Warnf("SendAmfEventNotify get token failed: %+v", pd)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sub.EventNotifyUri, bytes.NewReader(body))
	if err != nil {
		HttpLog.Errorf("SendAmfEventNotify build request failed: %+v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if tokSrc, ok := ctx.Value(openapi.ContextOAuth2).(oauth2.TokenSource); ok {
		if tok, errTok := tokSrc.Token(); errTok == nil {
			tok.SetAuthHeader(req)
		}
	}

	resp, err := eventNotifyClient.Do(req)
	if err != nil {
		HttpLog.Errorln(err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusBadRequest {
		HttpLog.Warnf("SendAmfEventNotify to %s returned status %d", sub.EventNotifyUri, resp.StatusCode)
	}
}

// isNotifyDestinationSafe is the production notify-destination guard: the
// host must not be a private/loopback/link-local address, and must match
// the subscribing NF's own NRF profile. Tests substitute this to exercise
// scheduling against a local httptest server without a live NRF; it is not
// a knob production code should ever touch.
var isNotifyDestinationSafe = func(sub *models.Amf_Comm_ExtAmfEventSubscription, host string) bool {
	return !isDisallowedNotifyHost(host) && verifyNotifyHostAgainstNrf(sub.NfId, sub.SourceNfType, host)
}

// isDisallowedNotifyHost reports whether host is, or resolves to, a
// loopback/private/link-local/unspecified/multicast address - the ranges an
// SSRF callback would target to reach internal infrastructure or a cloud
// metadata endpoint instead of a real external subscriber.
func isDisallowedNotifyHost(host string) bool {
	if host == "" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return isDisallowedIP(ip)
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return true
	}
	for _, ip := range ips {
		if isDisallowedIP(ip) {
			return true
		}
	}
	return false
}

func isDisallowedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// verifyNotifyHostAgainstNrf confirms host is one of the addresses the NRF
// has on file for nfId, instead of trusting anything derived from the
// caller-supplied notify URI. nfId and nfType are themselves self-reported
// by the subscriber at subscription creation, same as NfId always was in
// this API - but the NRF only returns the profile actually registered under
// that instance ID, so an attacker who does not control that NF's NRF
// registration cannot make this check pass for a host of their choosing.
func verifyNotifyHostAgainstNrf(nfId string, nfType models.Nrf_NFMgmt_NFType, host string) bool {
	if nfId == "" || nfType == "" {
		return false
	}
	amfSelf := amf_context.GetSelf()
	param := &Nnrf_NFDiscovery.SearchNFInstancesRequest{}
	param.SetTargetNfInstanceId(nfId)
	result, err := consumer.GetConsumer().SendSearchNFInstances(
		amfSelf.NrfUri, nfType, models.Nrf_NFMgmt_NFType_AMF, param)
	if err != nil || result == nil {
		return false
	}
	for _, profile := range result.NfInstances {
		if profile.NfInstanceId != nfId {
			continue
		}
		if profile.Fqdn != "" && strings.EqualFold(profile.Fqdn, host) {
			return true
		}
		for _, addr := range profile.Ipv4Addresses {
			if addr == host {
				return true
			}
		}
		for _, addr := range profile.Ipv6Addresses {
			if addr == host {
				return true
			}
		}
	}
	return false
}
