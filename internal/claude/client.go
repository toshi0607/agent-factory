// Package claude implements the Managed Agents API used by the work stage.
package claude

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	DefaultBaseURL = "https://api.anthropic.com"
	apiVersion     = "2026-10-21"
	apiBeta        = "managed-agents-2026-04-01"
	requestTimeout = 30 * time.Second
	fileTimeout    = 5 * time.Minute
)

type Authenticator interface {
	Authorize(context.Context, *http.Request) error
}

type Client struct {
	base  string
	http  http.Client
	auth  Authenticator
	sleep func(context.Context, time.Duration) error
}

func New(base string, client *http.Client, auth Authenticator) *Client {
	if base == "" {
		base = DefaultBaseURL
	}
	if client == nil {
		client = http.DefaultClient
	}
	c := &Client{base: strings.TrimRight(base, "/"), http: *client, auth: auth, sleep: sleepContext}
	c.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

type HTTPError struct {
	StatusCode int
	Body       string
}

var credentialPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{20,}|sk-ant-`)

func (e *HTTPError) Error() string {
	status := fmt.Sprintf("Managed Agents API: HTTP %d", e.StatusCode)
	if body := diagnosticText(e.Body); body != "" {
		return status + ": " + body
	}
	return status
}

// diagnosticText collapses whitespace, drops credential-like text, and caps the length.
func diagnosticText(text string) string {
	text = strings.Join(strings.FieldsFunc(text, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}), " ")
	if credentialPattern.MatchString(text) {
		return ""
	}
	runes := []rune(text)
	return string(runes[:min(len(runes), 300)])
}

func (c *Client) json(ctx context.Context, method, path string, body io.Reader, result any) (int, error) {
	return c.request(ctx, method, path, "application/json", body, -1, requestTimeout, func(r io.Reader) error {
		if result == nil {
			_, err := io.Copy(io.Discard, r)
			return err
		}
		if err := json.NewDecoder(r).Decode(result); err != nil {
			return errors.New("invalid Managed Agents JSON response")
		}
		return nil
	}, nil)
}

func (c *Client) request(ctx context.Context, method, path, contentType string, body io.Reader, size int64, timeout time.Duration, read func(io.Reader) error, messages *MessagesCheck) (int, error) {
	attempts := 1
	if method == http.MethodGet || method == http.MethodDelete {
		attempts = 5
	}
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		status, retry, retryAfter, err := c.requestOnce(ctx, method, path, contentType, body, size, timeout, read, messages)
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		if !retry || attempt == attempts-1 {
			return status, err
		}
		if err := c.sleep(ctx, max(time.Second<<attempt, retryAfter)); err != nil {
			return 0, err
		}
	}
}

func (c *Client) requestOnce(ctx context.Context, method, path, contentType string, body io.Reader, size int64, timeout time.Duration, read func(io.Reader) error, messages *MessagesCheck) (int, bool, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil || req.URL.User != nil || req.URL.Hostname() == "" ||
		(req.URL.Scheme != "https" && req.URL.Scheme != "http") {
		return 0, false, 0, errors.New("invalid Managed Agents request URL")
	}
	if c.auth == nil {
		return 0, false, 0, errors.New("Managed Agents authenticator is required")
	}
	if err := c.auth.Authorize(ctx, req); err != nil {
		return 0, false, 0, fmt.Errorf("authorize Managed Agents request: %w", err)
	}
	authHeaders := req.Header.Clone()
	req.Header.Set("anthropic-version", apiVersion)
	if messages == nil {
		req.Header.Set("anthropic-beta", apiBeta)
	} else if messages.stream != nil {
		req.Header.Set("anthropic-version", messagesStreamVersion)
		req.Header.Set("anthropic-beta", messagesStreamBeta)
		req.Header.Set("Accept", "application/json")
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if size >= 0 {
		req.ContentLength = size
	}

	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, true, 0, ctx.Err()
		}
		return 0, true, 0, fmt.Errorf("Managed Agents %s %s: request failed", method, path)
	}
	defer resp.Body.Close()
	code := resp.StatusCode
	if messages != nil {
		return code, false, 0, messages.readResponse(resp, authHeaders)
	}
	if code >= 200 && code < 300 {
		return code, false, 0, read(resp.Body)
	}
	retry := code == http.StatusTooManyRequests || (code >= 500 && code < 600)
	var delay time.Duration
	if seconds, err := strconv.ParseUint(resp.Header.Get("Retry-After"), 10, 64); err == nil || errors.Is(err, strconv.ErrRange) {
		delay = time.Duration(min(seconds, 30)) * time.Second
	}
	return code, retry, delay, &HTTPError{code, errorBody(resp.Body, authHeaders)}
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

// Redact authentication headers before retaining the diagnostic prefix.
func errorBody(r io.Reader, authHeaders http.Header) string {
	const limit = 2 << 10
	var secrets []string
	readLimit := limit
	for _, headers := range authHeaders {
		for _, value := range headers {
			if value == "" {
				continue
			}
			secrets = append(secrets, value)
			if _, token, ok := strings.Cut(value, " "); ok && token != "" {
				secrets = append(secrets, token)
			}
			readLimit = max(readLimit, limit+len(value)-1)
		}
	}
	prefix, _ := io.ReadAll(io.LimitReader(r, int64(readLimit)))
	body := string(prefix)
	for _, secret := range secrets {
		body = strings.ReplaceAll(body, secret, "[redacted]")
	}
	return body[:min(len(body), limit)]
}

func jsonBody(value any) (*bytes.Reader, error) {
	data, err := json.Marshal(value)
	return bytes.NewReader(data), err
}
