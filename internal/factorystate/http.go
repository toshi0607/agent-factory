package factorystate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

const (
	stsURL         = "https://sts.googleapis.com/v1/token"
	iamURL         = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
	storageBase    = "https://storage.googleapis.com"
	requestTimeout = 30 * time.Second
	errorBodyLimit = 16 << 10
)

var allowedHosts = map[string]bool{
	"sts.googleapis.com":            true,
	"iamcredentials.googleapis.com": true,
	"storage.googleapis.com":        true,
}

// HTTPError keeps only the status and a short error code; Google error
// messages can echo the provider, service account, or bucket.
type HTTPError struct {
	Operation  string
	StatusCode int
	Code       string
}

func (e *HTTPError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s: HTTP %d: %s", e.Operation, e.StatusCode, e.Code)
	}
	return fmt.Sprintf("%s: HTTP %d", e.Operation, e.StatusCode)
}

func statusOf(err error) int {
	if httpErr, ok := errors.AsType[*HTTPError](err); ok {
		return httpErr.StatusCode
	}
	return 0
}

type googleHTTP struct {
	http    http.Client
	sleep   func(context.Context, time.Duration) error
	timeout time.Duration // per attempt
}

func newGoogleHTTP(client *http.Client) *googleHTTP {
	if client == nil {
		client = http.DefaultClient
	}
	g := &googleHTTP{http: *client, sleep: sleepContext, timeout: requestTimeout}
	g.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return g
}

// errTransport marks a failure without an HTTP response, where the request
// may or may not have reached the server.
var errTransport = errors.New("request failed")

// do sends req to an allowed Google host. Transport errors are replaced
// because they carry the request URL. A per-attempt timeout counts as a
// transport failure: the request may have reached the server.
func (g *googleHTTP) do(req *http.Request, operation string) (*http.Response, error) {
	u := req.URL
	if u.Scheme != "https" || u.User != nil || u.Port() != "" || !allowedHosts[u.Host] {
		return nil, fmt.Errorf("%s: refusing a request to a host outside the Google allowlist", operation)
	}
	resp, err := g.http.Do(req)
	if err != nil {
		if errors.Is(req.Context().Err(), context.Canceled) {
			return nil, fmt.Errorf("%s: %w", operation, context.Canceled)
		}
		return nil, fmt.Errorf("%s: %w", operation, errTransport)
	}
	return resp, nil
}

var errorCodePattern = regexp.MustCompile(`^[A-Za-z_]{1,64}$`)

// responseError reads a short error code from a Google error body and
// drains the rest without retaining it.
func responseError(resp *http.Response, operation string) error {
	data, _ := io.ReadAll(io.LimitReader(resp.Body, errorBodyLimit))
	var body struct {
		Error json.RawMessage `json:"error"`
	}
	var code string
	if json.Unmarshal(data, &body) == nil {
		var nested struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(body.Error, &code) != nil && json.Unmarshal(body.Error, &nested) == nil {
			code = nested.Status
		}
	}
	if !errorCodePattern.MatchString(code) {
		code = ""
	}
	return &HTTPError{Operation: operation, StatusCode: resp.StatusCode, Code: code}
}

func retryable(err error) bool {
	status := statusOf(err)
	return errors.Is(err, errTransport) || status == http.StatusTooManyRequests || (status >= 500 && status < 600)
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
