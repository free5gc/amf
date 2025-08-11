package util

import (
	"fmt"
	"net/netip"

	"github.com/free5gc/amf/internal/logger"
	"github.com/free5gc/openapi/models"
)

func SearchNFServiceUri(nfProfile *models.NrfNfDiscoveryNfProfile, serviceName models.ServiceName,
	nfServiceStatus models.NfServiceStatus,
) (nfUri string) {
	if nfProfile.NfServices != nil {
		for _, service := range nfProfile.NfServices {
			if service.ServiceName == serviceName && service.NfServiceStatus == nfServiceStatus {
				if nfProfile.Fqdn != "" {
					nfUri = nfProfile.Fqdn
				} else if service.Fqdn != "" {
					nfUri = service.Fqdn
				} else if service.ApiPrefix != "" {
					nfUri = service.ApiPrefix
				} else if service.IpEndPoints != nil {
					point := (service.IpEndPoints)[0]
					if point.Ipv6Address != "" {
						nfUri = getSbiUri(service.Scheme, point.Ipv6Address, point.Port)
					} else if len(nfProfile.Ipv6Addresses) != 0 {
						nfUri = getSbiUri(service.Scheme, nfProfile.Ipv6Addresses[0], point.Port)
					} else if point.Ipv4Address != "" {
						nfUri = getSbiUri(service.Scheme, point.Ipv4Address, point.Port)
					} else if len(nfProfile.Ipv4Addresses) != 0 {
						nfUri = getSbiUri(service.Scheme, nfProfile.Ipv4Addresses[0], point.Port)
					}
				}
			}
			if nfUri != "" {
				break
			}
		}
	}
	return nfUri
}

func getSbiUri(scheme models.UriScheme, ipAddress string, port int32) (uri string) {
	addr, err := netip.ParseAddr(ipAddress)
	if err != nil {
		logger.InitLog.Errorf("Parse RegisterIP hostname %s failed: %+v", ipAddress, err)
	}
	if port != 0 {
		uri = fmt.Sprintf("%s://%s", scheme, netip.AddrPortFrom(addr, uint16(port)).String())
	} else {
		switch scheme {
		case models.UriScheme_HTTP:
			uri = fmt.Sprintf("%s://%s", scheme, netip.AddrPortFrom(addr, 80).String())
		case models.UriScheme_HTTPS:
			uri = fmt.Sprintf("%s://%s", scheme, netip.AddrPortFrom(addr, 443).String())
		}
	}
	return
}
