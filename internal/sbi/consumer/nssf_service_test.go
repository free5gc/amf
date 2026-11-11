package consumer

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRetryWithTimeout(t *testing.T) {
	errFail := errors.New("nssf not found")

	tests := []struct {
		name     string
		timeout  time.Duration
		interval time.Duration
		// failures is the number of leading calls that fail; -1 means every call fails
		failures     int
		wantErr      bool
		minCalls     int
		maxCalls     int
		wantErrInMsg string
	}{
		{
			name:     "success on first attempt",
			timeout:  50 * time.Millisecond,
			interval: 10 * time.Millisecond,
			failures: 0,
			minCalls: 1,
			maxCalls: 1,
		},
		{
			name:     "success after retries",
			timeout:  500 * time.Millisecond,
			interval: 5 * time.Millisecond,
			failures: 2,
			minCalls: 3,
			maxCalls: 3,
		},
		{
			name:         "give up after timeout and wraps last error",
			timeout:      50 * time.Millisecond,
			interval:     20 * time.Millisecond,
			failures:     -1,
			wantErr:      true,
			minCalls:     2,
			maxCalls:     4,
			wantErrInMsg: "NSSF selection timeout after 50ms",
		},
		{
			name:         "interval longer than timeout tries exactly once",
			timeout:      10 * time.Millisecond,
			interval:     time.Second,
			failures:     -1,
			wantErr:      true,
			minCalls:     1,
			maxCalls:     1,
			wantErrInMsg: "NSSF selection timeout after 10ms",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			start := time.Now()
			err := retryWithTimeout(tt.timeout, tt.interval, func() error {
				calls++
				if tt.failures < 0 || calls <= tt.failures {
					return errFail
				}
				return nil
			})

			if tt.wantErr {
				assert.ErrorIs(t, err, errFail)
				assert.ErrorContains(t, err, tt.wantErrInMsg)
			} else {
				assert.NoError(t, err)
			}
			assert.GreaterOrEqual(t, calls, tt.minCalls)
			assert.LessOrEqual(t, calls, tt.maxCalls)
			assert.Less(t, time.Since(start), time.Second)
		})
	}
}

// The product budget must allow at least one retry, otherwise a transient
// NRF hiccup would immediately reject the UE.
func TestNssfSelectionBudget(t *testing.T) {
	assert.Positive(t, nssfSelectionRetryInterval)
	assert.Greater(t, nssfSelectionTimeout, nssfSelectionRetryInterval)
}
