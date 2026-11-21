package claude

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/toshi0607/agent-factory/internal/claudeauth"
)

type retryTransport func(*http.Request) (*http.Response, error)

func (f retryTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestTransientRequests(t *testing.T) {
	const events = "/v1/sessions/test/events?beta=true"
	for _, tt := range []struct {
		name, method, path, retryAfter string
		responses                      []int
		delays                         []time.Duration
		wantStatus                     int
		cancel                         bool
	}{
		{"events after two 503s", http.MethodGet, events, "", []int{503, 503, 200}, []time.Duration{time.Second, 2 * time.Second}, 200, false},
		{"429 retry after", http.MethodGet, events, "6", []int{429, 200}, []time.Duration{6 * time.Second}, 200, false},
		{"retry after capped", http.MethodGet, events, "90", []int{429, 200}, []time.Duration{30 * time.Second}, 200, false},
		{"transport error", http.MethodDelete, "/v1/sessions/test", "", []int{0, 200}, []time.Duration{time.Second}, 200, false},
		{"attempt limit", http.MethodGet, events, "", []int{503, 503, 503, 503, 503},
			[]time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}, 503, false},
		{"POST once", http.MethodPost, events, "", []int{503}, nil, 503, false},
		{"cancel backoff", http.MethodGet, events, "", []int{503}, []time.Duration{time.Second}, 0, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			client := &http.Client{Transport: retryTransport(func(req *http.Request) (*http.Response, error) {
				if calls >= len(tt.responses) || req.Method != tt.method || req.URL.RequestURI() != tt.path {
					t.Fatalf("unexpected request %d: %s %s", calls+1, req.Method, req.URL.RequestURI())
				}
				code := tt.responses[calls]
				calls++
				if code == 0 {
					return nil, errors.New("transport failed")
				}
				return &http.Response{StatusCode: code, Header: http.Header{"Retry-After": {tt.retryAfter}},
					Body: io.NopCloser(strings.NewReader("{}"))}, nil
			})}
			c := New("", client, claudeauth.Static{Header: "X-Test-Auth", Value: "fake-auth-placeholder"})
			var delays []time.Duration
			c.sleep = func(_ context.Context, delay time.Duration) error {
				delays = append(delays, delay)
				if tt.cancel {
					cancel()
				}
				return nil
			}
			status, err := c.json(ctx, tt.method, tt.path, nil, nil)
			if status != tt.wantStatus || calls != len(tt.responses) || !slices.Equal(delays, tt.delays) {
				t.Fatalf("status %d, calls %d, delays %v", status, calls, delays)
			}
			if tt.cancel {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled request = %v", err)
				}
			} else if status == 200 {
				if err != nil {
					t.Fatal(err)
				}
			} else if apiErr, ok := errors.AsType[*HTTPError](err); !ok || apiErr.StatusCode != status {
				t.Fatalf("request error = %v", err)
			}
		})
	}
}
