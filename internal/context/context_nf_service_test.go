package context

import (
	"encoding/json"
	"testing"

	"github.com/free5gc/openapi/models"
)

func TestAMFNFService(t *testing.T) {
	c := &AMFContext{
		NfService: make(
			map[models.Nrf_NFMgmt_ServiceName]models.Nrf_NFMgmt_NFService,
		),
		UriScheme:    models.UriScheme_HTTP,
		RegisterIPv4: "10.101.200.28",
		SBIPort:      8000,
	}

	c.InitNFService(
		[]string{string(models.Nrf_NFMgmt_ServiceName_NAMF_COMM)},
		"1.0.0",
	)

	service, ok := c.NfService[models.Nrf_NFMgmt_ServiceName_NAMF_COMM]
	if !ok {
		t.Fatal("namf-comm service not found")
	}

	if service.Scheme != models.UriScheme_HTTP {
		t.Fatalf("Unexpected scheme: %s", service.Scheme)
	}

	if service.ApiPrefix != "" {
		t.Fatalf(
			"Nonstandard apiPrefix: %q",
			service.ApiPrefix,
		)
	}

	if len(service.IpEndPoints) != 1 {
		t.Fatalf(
			"Expected one endpoint, got %d",
			len(service.IpEndPoints),
		)
	}

	endpoint := service.IpEndPoints[0]

	if endpoint.Ipv4Address != "10.101.200.28" ||
		endpoint.Port != 8000 {
		t.Fatalf("Unexpected endpoint: %+v", endpoint)
	}

	if service.NfServiceStatus != models.Nrf_NFMgmt_NFServiceStatus_REGISTERED {
		t.Fatal("NFService status is not REGISTERED")
	}

	raw, err := json.Marshal(service)
	if err != nil {
		t.Fatal(err)
	}

	var fields map[string]interface{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}

	if _, exists := fields["apiPrefix"]; exists {
		t.Fatalf(
			"apiPrefix should be omitted: %s",
			string(raw),
		)
	}

	if _, exists := fields["scheme"]; !exists {
		t.Fatal("Missing scheme field")
	}

	if _, exists := fields["ipEndPoints"]; !exists {
		t.Fatal("Missing ipEndPoints field")
	}

	t.Log("Standard AMF NFService registration: PASS")
}
