/*
 * AMF Configuration Factory
 */

package factory

import (
	"testing"

	"github.com/asaskevich/govalidator"

	"github.com/free5gc/util/nfheartbeat"
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
		// TODO: Add test cases.
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

func TestGetNfHeartBeatTimer(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want int32
	}{
		{
			name: "no configuration section",
			cfg:  &Config{},
			want: nfheartbeat.DefaultTimer,
		},
		{
			name: "option absent",
			cfg:  &Config{Configuration: &Configuration{}},
			want: nfheartbeat.DefaultTimer,
		},
		{
			name: "option set",
			cfg:  &Config{Configuration: &Configuration{NfHeartBeatTimer: 45}},
			want: 45,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.GetNfHeartBeatTimer(); got != tt.want {
				t.Errorf("GetNfHeartBeatTimer() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestNfHeartBeatTimerRange(t *testing.T) {
	// The range(1|3600) struct tag cannot reference constants; keep it aligned
	// with the bounds the NRF profile validator enforces.
	if nfheartbeat.MinTimer != 1 || nfheartbeat.MaxTimer != 3600 {
		t.Fatalf("range(1|3600) tag out of sync with nfheartbeat bounds [%d, %d]",
			nfheartbeat.MinTimer, nfheartbeat.MaxTimer)
	}

	tests := []struct {
		name    string
		timer   int32
		wantErr bool
	}{
		{name: "absent is optional", timer: 0},
		{name: "lower bound", timer: nfheartbeat.MinTimer},
		{name: "upper bound of 1 hour", timer: nfheartbeat.MaxTimer},
		{name: "above the upper bound", timer: nfheartbeat.MaxTimer + 1, wantErr: true},
		{name: "negative", timer: -1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := govalidator.ValidateStruct(&Configuration{NfHeartBeatTimer: tt.timer})

			fieldErr := govalidator.ErrorByField(err, "NfHeartBeatTimer")
			if gotErr := fieldErr != ""; gotErr != tt.wantErr {
				t.Errorf("nfHeartBeatTimer %d: field error = %q, want error %v", tt.timer, fieldErr, tt.wantErr)
			}
		})
	}
}
