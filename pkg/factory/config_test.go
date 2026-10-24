/*
 * AMF Configuration Factory
 */

package factory

import (
	tlsContext "context"
	tlsX509 "crypto/x509"
	tlsErrors "errors"
	tlsIO "io"
	tlsLog "log"
	tlsHTTP "net/http"
	tlsServer "net/http/httptest"
	tlsAtomic "sync/atomic"
	"testing"

	"github.com/asaskevich/govalidator"
	tlsYAML "gopkg.in/yaml.v2"

	tlsOpenAPI "github.com/free5gc/openapi"
	tlsNFM "github.com/free5gc/openapi/nrf/NFMgmt"
)

func TestSctp_validate(t *testing.T) {
	type fields struct {
		NumOstreams    uint
		MaxInstreams   uint
		MaxAttempts    uint
		MaxInitTimeout uint
	}
	tests := []struct {
		name    string
		fields  fields
		want    bool
		wantErr bool
		numErr  int
	}{
		{
			name: "test OK -- Default",
			fields: fields{
				NumOstreams:    sctpDefaultNumOstreams,
				MaxInstreams:   sctpDefaultMaxInstreams,
				MaxAttempts:    sctpDefaultMaxAttempts,
				MaxInitTimeout: sctpDefaultMaxInitTimeout,
			},
			want:    true,
			wantErr: false,
			numErr:  0,
		},
		{
			name: "test OK -- Max",
			fields: fields{
				NumOstreams:    10,
				MaxInstreams:   10,
				MaxAttempts:    5,
				MaxInitTimeout: 5,
			},
			want:    true,
			wantErr: false,
			numErr:  0,
		},
		{
			name: "test OK -- Min",
			fields: fields{
				NumOstreams:    1,
				MaxInstreams:   1,
				MaxAttempts:    1,
				MaxInitTimeout: 1,
			},
			want:    true,
			wantErr: false,
			numErr:  0,
		},
		{
			name: "test Error -- zeros",
			fields: fields{
				NumOstreams:    0,
				MaxInstreams:   0,
				MaxAttempts:    0,
				MaxInitTimeout: 0,
			},
			want:    false,
			wantErr: true,
			numErr:  4,
		},
		{
			name: "test Error -- upperbound",
			fields: fields{
				NumOstreams:    11,
				MaxInstreams:   11,
				MaxAttempts:    6,
				MaxInitTimeout: 6,
			},
			want:    false,
			wantErr: true,
			numErr:  4,
		},
		{
			name: "test Error -- not set",
			fields: fields{
				MaxInstreams: 10,
			},
			want:    false,
			wantErr: true,
			numErr:  3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Sctp{
				NumOstreams:    tt.fields.NumOstreams,
				MaxInstreams:   tt.fields.MaxInstreams,
				MaxAttempts:    tt.fields.MaxAttempts,
				MaxInitTimeout: tt.fields.MaxInitTimeout,
			}
			got, err := n.validate()

			if (err != nil) != tt.wantErr {
				t.Errorf("Sctp.validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				errs := err.(govalidator.Errors)
				if len(errs) != tt.numErr {
					t.Errorf("Sctp.validate() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
			}
			if got != tt.want {
				t.Errorf("Sctp.validate() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Exercise parsed NF config through the same startup configuration API and
// generated NRF client used in production. No deployment files are modified.
func TestSBIConfigTLSVerification(t *testing.T) {
	t.Cleanup(func() {
		if err := tlsOpenAPI.ConfigureHTTP2Clients(
			tlsOpenAPI.TransportReadIdleTimeout, tlsOpenAPI.TransportPingTimeout, false,
		); err != nil {
			t.Errorf("restore HTTP clients: %v", err)
		}
	})
	var requests tlsAtomic.Int32
	server := tlsServer.NewUnstartedServer(tlsHTTP.HandlerFunc(func(w tlsHTTP.ResponseWriter, r *tlsHTTP.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if _, err := tlsIO.WriteString(w, `{}`); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	server.EnableHTTP2 = true
	server.Config.ErrorLog = tlsLog.New(tlsIO.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	for _, value := range []string{"", "false", "true"} {
		t.Run("verify="+value, func(t *testing.T) {
			data := "configuration:\n  sbi:\n    scheme: https\n"
			if value != "" {
				data += "    tls:\n      verify: " + value + "\n"
			}
			var cfg Config
			if err := tlsYAML.Unmarshal([]byte(data), &cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.GetTLSVerify() != (value == "true") {
				t.Fatal("verify parsing mismatch")
			}
			if err := tlsOpenAPI.ConfigureHTTP2Clients(
				cfg.GetReadIdleTimeout(), cfg.GetPingTimeout(), cfg.GetTLSVerify(),
			); err != nil {
				t.Fatal(err)
			}
			apiCfg := tlsNFM.NewConfiguration()
			apiCfg.SetBasePath(server.URL)
			client := tlsNFM.NewAPIClient(apiCfg)
			req := &tlsNFM.GetNFInstanceRequest{}
			req.SetNfInstanceID("tls-test")
			before := requests.Load()
			_, err := client.NFInstanceIDDocumentApi.GetNFInstance(tlsContext.Background(), req)
			if value == "true" {
				var unknown tlsX509.UnknownAuthorityError
				if !tlsErrors.As(err, &unknown) {
					t.Fatalf("expected unknown authority, got %v", err)
				}
				if requests.Load() != before {
					t.Fatal("HTTP handler reached despite rejected certificate")
				}
			} else if err != nil {
				t.Fatal(err)
			} else if requests.Load() != before+1 {
				t.Fatal("request not received")
			}
		})
	}
}
