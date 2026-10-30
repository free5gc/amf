package context

import (
	"testing"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/serviceuri"
)

// The registered NFService must follow TS 29.510 (no URL in apiPrefix, a
// hostname as fqdn, an IP literal in ipEndPoints) and resolve back to the AMF
// API root.
func TestInitNFServiceAddressing(t *testing.T) {
	tests := []struct {
		registerAddr string
		wantFQDN     string
		wantIPv4     string
		wantAPIRoot  string
	}{
		{"10.0.0.28", "", "10.0.0.28", "http://10.0.0.28:8000"},
		{"amf.free5gc.org", "amf.free5gc.org", "", "http://amf.free5gc.org:8000"},
	}

	for _, tt := range tests {
		t.Run(tt.registerAddr, func(t *testing.T) {
			c := &AMFContext{
				UriScheme:    models.UriScheme_HTTP,
				RegisterIPv4: tt.registerAddr,
				SBIPort:      8000,
				NfService:    make(map[models.Nrf_NFMgmt_ServiceName]models.Nrf_NFMgmt_NFService),
			}
			c.InitNFService([]string{string(models.Nrf_NFMgmt_ServiceName_NAMF_COMM)}, "1.0.0")
			s := c.NfService[models.Nrf_NFMgmt_ServiceName_NAMF_COMM]

			if s.ApiPrefix != "" || s.Fqdn != tt.wantFQDN ||
				len(s.IpEndPoints) != 1 || s.IpEndPoints[0].Ipv4Address != tt.wantIPv4 {
				t.Fatalf("unexpected NFService addressing: %+v", s)
			}

			profile := &models.Nrf_NFDisc_NFProfile{NfServices: []models.Nrf_NFDisc_NFService{{
				ServiceName:     s.ServiceName,
				NfServiceStatus: s.NfServiceStatus,
				Scheme:          s.Scheme,
				Fqdn:            s.Fqdn,
				IpEndPoints:     s.IpEndPoints,
			}}}
			got, err := serviceuri.ResolveNFServiceURI(profile, s.ServiceName, serviceuri.Options{})
			if err != nil || got.APIRoot != tt.wantAPIRoot {
				t.Fatalf("resolved %q, error %v; want %q", got.APIRoot, err, tt.wantAPIRoot)
			}
		})
	}
}
