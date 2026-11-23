// Package cfsandbox implements the authenticated Cloudflare Sandbox run API.
package cfsandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	requestTimeout = 30 * time.Second
	fileTimeout    = 5 * time.Minute
	// Matches the Worker's 10-minute stream timeout for outputs and the egress log.
	downloadTimeout = 10 * time.Minute
	maxUploadBytes  = 95 << 20
)

var runID = regexp.MustCompile(`^p0-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$`)
var fileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

func ValidRunID(id string) bool { return runID.MatchString(id) }

type Authenticator interface {
	Authorize(context.Context, *http.Request) error
}

type Client struct {
	base  string
	http  http.Client
	auth  Authenticator
	sleep func(context.Context, time.Duration) error
}

func New(base string, client *http.Client, auth Authenticator) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
		u.ForceQuery || u.RawQuery != "" || strings.Contains(base, "#") {
		return nil, errors.New("worker URL must be HTTPS with a host and without userinfo, query, or fragment")
	}
	if auth == nil {
		return nil, errors.New("worker authenticator is required")
	}
	if client == nil {
		client = http.DefaultClient
	}
	c := &Client{base: strings.TrimRight(u.String(), "/"), http: *client, auth: auth, sleep: sleepContext}
	c.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c, nil
}

type HTTPError struct {
	StatusCode int
	Code       string
}

func (e *HTTPError) Error() string {
	msg := fmt.Sprintf("worker: HTTP %d", e.StatusCode)
	if e.Code != "" {
		msg += ": " + e.Code
	}
	return msg
}

func IsNotFound(err error) bool {
	e, ok := errors.AsType[*HTTPError](err)
	return ok && e.StatusCode == http.StatusNotFound
}

// Only retain codes issued by the worker. Proxies and untrusted error bodies can echo credentials.
func errorCode(body io.Reader, authorization string) string {
	var result struct {
		Error string `json:"error"`
	}
	if json.NewDecoder(io.LimitReader(body, 4<<10)).Decode(&result) != nil ||
		strings.TrimPrefix(authorization, "Bearer ") == result.Error {
		return ""
	}
	switch result.Error {
	case "misconfigured", "invalid_token", "wrong_audience", "wrong_repository", "wrong_workflow", "expired",
		"wrong_ref", "wrong_run", "not_found", "method_not_allowed", "forbidden", "length_required",
		"invalid_length", "body_too_large",
		"invalid_start", "invalid_token_request", "invalid_stop", "internal_error", "destroyed", "length_mismatch",
		"no_token", "missing_files", "launch_failed", "already_started":
		return result.Error
	default:
		return ""
	}
}

type uploadDigest struct {
	mu   sync.Mutex
	hash hash.Hash
	size int64
}

func (d *uploadDigest) Write(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n, err := d.hash.Write(p)
	d.size += int64(n)
	return n, err
}

func (d *uploadDigest) matches(hash string, size int64) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return size == d.size && strings.EqualFold(hash, fmt.Sprintf("%x", d.hash.Sum(nil)))
}

func (c *Client) PutFile(ctx context.Context, id, name string, reader io.Reader, size int64) error {
	if !fileName.MatchString(name) {
		return errors.New("invalid worker upload name")
	}
	if reader == nil || size < 0 || size > maxUploadBytes {
		return errors.New("invalid worker upload size or body")
	}
	digest := uploadDigest{hash: sha256.New()}
	body := io.TeeReader(io.LimitReader(reader, size+1), &digest)
	req, err := c.newRequest(ctx, http.MethodPut, id, "/files/"+name, body)
	if err != nil {
		return err
	}
	req.ContentLength = size
	if size == 0 {
		if n, err := io.Copy(io.Discard, body); err != nil || n != 0 {
			return errors.New("worker upload body differs from Content-Length")
		}
		req.Body = http.NoBody
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	var result struct {
		SHA256 string `json:"sha256"`
		Bytes  *int64 `json:"bytes"`
	}
	if err := c.send(req, http.StatusOK, 1, fileTimeout, readJSON(&result)); err != nil {
		return err
	}
	if result.Bytes == nil || *result.Bytes != size || !digest.matches(result.SHA256, size) {
		return errors.New("worker upload checksum or size mismatch")
	}
	return nil
}

func (c *Client) PutToken(ctx context.Context, id, token string, expiresIn int) error {
	return c.sendJSON(ctx, http.MethodPut, id, "/token", struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}{token, expiresIn}, http.StatusOK, requestTimeout)
}

func (c *Client) Start(ctx context.Context, id string, start StartRequest) (StartResponse, error) {
	var result StartResponse
	body, err := json.Marshal(start)
	if err != nil {
		return result, errors.New("encode worker start request")
	}
	req, err := c.newRequest(ctx, http.MethodPost, id, "/start", bytes.NewReader(body))
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", "application/json")
	err = c.send(req, http.StatusAccepted, 1, requestTimeout, readJSON(&result))
	result.RequestSHA256 = fmt.Sprintf("%x", sha256.Sum256(body))
	return result, err
}

func (c *Client) Status(ctx context.Context, id string) (Status, error) {
	var result Status
	req, err := c.newRequest(ctx, http.MethodGet, id, "", nil)
	if err != nil {
		return result, err
	}
	err = c.send(req, http.StatusOK, 5, requestTimeout, readJSON(&result))
	return result, err
}

func (c *Client) Stop(ctx context.Context, id, reason string) error {
	return c.sendJSON(ctx, http.MethodPost, id, "/stop", struct {
		Reason string `json:"reason"`
	}{reason}, http.StatusOK, 3*time.Minute)
}

func (c *Client) Delete(ctx context.Context, id string) error {
	req, err := c.newRequest(ctx, http.MethodDelete, id, "", nil)
	if err != nil {
		return err
	}
	err = c.send(req, http.StatusNoContent, 5, requestTimeout, nil)
	if IsNotFound(err) {
		return nil
	}
	return err
}

func (c *Client) sendJSON(ctx context.Context, method, id, resource string, value any, status int, timeout time.Duration) error {
	body, err := json.Marshal(value)
	if err != nil {
		return errors.New("encode worker request")
	}
	req, err := c.newRequest(ctx, method, id, resource, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.send(req, status, 1, timeout, nil)
}

func (c *Client) newRequest(ctx context.Context, method, id, resource string, body io.Reader) (*http.Request, error) {
	if !ValidRunID(id) {
		return nil, errors.New("invalid worker run ID")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+"/runs/"+id+resource, body)
	if err != nil {
		return nil, errors.New("construct worker request")
	}
	return req, nil
}

func (c *Client) send(req *http.Request, status, attempts int, timeout time.Duration, read func(*http.Response) error) error {
	ctx := req.Context()
	for attempt := range attempts {
		if err := ctx.Err(); err != nil {
			return err
		}
		attemptCtx, cancel := context.WithTimeout(ctx, timeout)
		retry, delay, err := c.sendOnce(req.Clone(attemptCtx), status, read)
		cancel()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !retry || attempt == attempts-1 {
			return err
		}
		if err := c.sleep(ctx, max(time.Second<<attempt, delay)); err != nil {
			return err
		}
	}
	panic("worker request requires at least one attempt")
}

func (c *Client) sendOnce(req *http.Request, status int, read func(*http.Response) error) (bool, time.Duration, error) {
	if err := c.auth.Authorize(req.Context(), req); err != nil {
		return false, 0, errors.New("authorize worker request failed")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return true, 0, errors.New("worker request failed")
	}
	defer resp.Body.Close()
	if code := resp.StatusCode; code != status {
		retry := code == http.StatusTooManyRequests || code >= 500 && code < 600
		seconds, _ := strconv.ParseUint(resp.Header.Get("Retry-After"), 10, 64)
		return retry, time.Duration(min(seconds, 30)) * time.Second, &HTTPError{code, errorCode(resp.Body, req.Header.Get("Authorization"))}
	}
	if read == nil {
		return false, 0, nil
	}
	err = read(resp)
	return errors.Is(err, errReadResponse), 0, err
}

var errReadResponse = errors.New("read worker response failed")

func readJSON(out any) func(*http.Response) error {
	return func(resp *http.Response) error {
		const limit = 64 << 10
		body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err != nil {
			return errReadResponse
		}
		if len(body) > limit || json.Unmarshal(body, out) != nil {
			return errors.New("invalid worker JSON response")
		}
		return nil
	}
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
