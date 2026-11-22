package main

// Public, fictional observations of native GitHub Actions failures.
// These tests exercise the real read-only observer and cannot dispatch work.
import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestObserveNativeHTTPFailureNoBlindRetryOrBodyReflection(t *testing.T) {
	for _, status := range []int{
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusTooManyRequests,
		http.StatusServiceUnavailable,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var attempts atomic.Int32
			const sentinel = "fictional-sensitive-response-sentinel"
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != "/40448376152" {
					t.Errorf("unexpected Actions observation request method/path")
				}
				w.WriteHeader(status)
				_, _ = w.Write([]byte(sentinel))
			}))
			defer s.Close()

			result, err := observe(context.Background(), s.Client(), s.URL+"/", "40448376152")
			if err == nil || result.ControlState != "" {
				t.Fatalf("HTTP %d falsely became normalized observation: %+v err=%v", status, result, err)
			}
			if strings.Contains(err.Error(), sentinel) {
				t.Fatal("untrusted HTTP body reflected into durable error")
			}
			if got := attempts.Load(); got != 1 {
				t.Fatalf("unknown native HTTP failure triggered blind retry: %d requests", got)
			}
		})
	}
}

func TestObserveNativeOversizedAndMalformedJSONFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"oversized_response", strings.Repeat("X", int(maxJSON)+1)},
		{"malformed_response", "{\"id\":"},
		{"not_an_actions_run", "{}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var attempts atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer s.Close()

			result, err := observe(context.Background(), s.Client(), s.URL+"/", "40448376152")
			if err == nil || result.ControlState != "" || result.ScienceState != "" {
				t.Fatalf("malformed native response became accepted evidence: %+v err=%v", result, err)
			}
			if attempts.Load() != 1 {
				t.Fatalf("invalid provider response retried: %d", attempts.Load())
			}
		})
	}
}
