package cfsandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/toshi0607/agent-factory/internal/claudeauth"
)

const testID = "p0-20261123T000000Z-01234567"
const testBearer = "synthetic-bearer-placeholder"
const testBase = "https://worker.example.invalid"

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func recorderClient(handler http.HandlerFunc) *http.Client {
	return &http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
		if req.Body != nil {
			defer req.Body.Close()
		}
		w := httptest.NewRecorder()
		handler(w, req)
		return w.Result(), nil
	})}
}

func testClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	c, err := New(testBase, recorderClient(handler), claudeauth.Static{Header: "Authorization", Value: "Bearer " + testBearer})
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	return c
}

func TestWorkerURLValidation(t *testing.T) {
	auth := claudeauth.Static{}
	for _, base := range []string{
		"", strings.Replace(testBase, "https:", "http:", 1), "https:///path",
		strings.Replace(testBase, "://", "://user:placeholder@", 1), testBase + "?token=placeholder", testBase + "?", testBase + "#",
	} {
		_, err := New(base, nil, auth)
		if err == nil || (base != "" && strings.Contains(err.Error(), base)) {
			t.Fatal("accepted or exposed invalid worker URL")
		}
	}
}

func TestWorkerErrorSanitizationAndRedirect(t *testing.T) {
	const target = "https://redirect.example.invalid"
	opaque := strings.Repeat("s", 25)
	var response atomic.Int32
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host != "worker.example.invalid" {
			t.Error("followed a redirect from the worker")
			w.WriteHeader(500)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+testBearer {
			t.Error("missing worker authorization")
		}
		switch response.Load() {
		case 0:
			w.WriteHeader(400)
			fmt.Fprintf(w, `{"error":"invalid_token_request","message":%q}`,
				r.Header.Get("Authorization")+" "+opaque+" "+target)
		case 1:
			w.WriteHeader(400)
			fmt.Fprintf(w, `{"error":%q}`, opaque)
		case 2:
			http.Redirect(w, r, target, http.StatusTemporaryRedirect)
		case 3:
			w.WriteHeader(401)
			fmt.Fprint(w, `{"error":"wrong_ref"}`)
		case 4:
			w.WriteHeader(403)
			fmt.Fprint(w, `{"error":"wrong_run"}`)
		}
	})
	for i, want := range []struct {
		status int
		code   string
	}{{400, "invalid_token_request"}, {400, ""}, {307, ""}, {401, "wrong_ref"}, {403, "wrong_run"}} {
		response.Store(int32(i))
		err := c.PutToken(t.Context(), testID, opaque, 600)
		apiErr, ok := errors.AsType[*HTTPError](err)
		if !ok || apiErr.StatusCode != want.status || apiErr.Code != want.code {
			t.Fatalf("expected sanitized typed worker error for status %d", want.status)
		}
		for _, forbidden := range []string{testBearer, opaque, target, c.base, "Authorization"} {
			if strings.Contains(err.Error(), forbidden) {
				t.Fatal("worker error exposed sensitive data")
			}
		}
	}
}

func TestWorkerUploadIntegrity(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		badHash    bool
		badSize    bool
	}{
		{name: "valid", body: "upload data"},
		{name: "empty"},
		{name: "bad hash", body: "upload data", badHash: true},
		{name: "bad size", body: "upload data", badSize: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				data, err := io.ReadAll(r.Body)
				if err != nil || r.Method != http.MethodPut || r.URL.Path != "/runs/"+testID+"/files/task.md" ||
					r.ContentLength != int64(len(tc.body)) || string(data) != tc.body {
					t.Error("incorrect upload request or content length")
				}
				hash := sha256.Sum256(data)
				if tc.badHash {
					hash[0] ^= 1
				}
				size := len(data)
				if tc.badSize {
					size++
				}
				fmt.Fprintf(w, `{"name":"task.md","bytes":%d,"sha256":"%x"}`, size, hash)
			})
			err := c.PutFile(t.Context(), testID, "task.md", strings.NewReader(tc.body), int64(len(tc.body)))
			if (err != nil) != (tc.badHash || tc.badSize) {
				t.Fatalf("upload integrity check returned %v", err)
			}
		})
	}
}

func TestWorkerRetries(t *testing.T) {
	for _, tc := range []struct {
		method, resource string
		wantAttempts     int32
		call             func(context.Context, *Client) error
	}{
		{"GET", "", 5, func(ctx context.Context, c *Client) error { _, err := c.Status(ctx, testID); return err }},
		{"DELETE", "", 5, func(ctx context.Context, c *Client) error { return c.Delete(ctx, testID) }},
		{"POST", "/start", 1, func(ctx context.Context, c *Client) error { _, err := c.Start(ctx, testID, StartRequest{}); return err }},
		{"PUT", "/files/task.md", 1, func(ctx context.Context, c *Client) error {
			return c.PutFile(ctx, testID, "task.md", strings.NewReader("file"), 4)
		}},
	} {
		t.Run(tc.method, func(t *testing.T) {
			var attempts atomic.Int32
			c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != tc.method || r.URL.Path != "/runs/"+testID+tc.resource {
					t.Error("incorrect worker route")
				}
				if attempts.Load() == 3 {
					w.Header().Set("Retry-After", "4")
					w.WriteHeader(429)
				} else {
					w.WriteHeader(503)
				}
			})
			transport := c.http.Transport
			c.http.Transport = transportFunc(func(req *http.Request) (*http.Response, error) {
				if attempts.Add(1) == 2 {
					return nil, errors.New("simulated network error")
				}
				return transport.RoundTrip(req)
			})
			var backoff []time.Duration
			c.sleep = func(_ context.Context, d time.Duration) error {
				backoff = append(backoff, d)
				return nil
			}
			if err := tc.call(t.Context(), c); err == nil || attempts.Load() != tc.wantAttempts {
				t.Fatalf("worker attempts = %d, want %d; error = %v", attempts.Load(), tc.wantAttempts, err)
			}
			if tc.wantAttempts == 5 && fmt.Sprint(backoff) != "[1s 2s 4s 8s]" {
				t.Fatalf("worker backoff = %v", backoff)
			}
		})
	}
}

func TestWorkerDownloadRetriesAndLimits(t *testing.T) {
	var calls atomic.Int32
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/runs/" + testID + "/outputs/events.jsonl":
			if calls.Add(1) == 1 {
				w.Header().Set("Content-Length", "10")
				fmt.Fprint(w, "short")
				return
			}
			fmt.Fprint(w, "complete")
		case "/runs/" + testID + "/egress":
			w.Header().Set("X-Egress-Dropped", "3")
			fmt.Fprint(w, "{}\n")
		default:
			t.Error("wrong download route")
		}
	})
	transport := c.http.Transport
	c.http.Transport = transportFunc(func(req *http.Request) (*http.Response, error) {
		resp, err := transport.RoundTrip(req)
		if resp != nil && calls.Load() == 1 {
			resp.Body = io.NopCloser(io.MultiReader(resp.Body, iotest.ErrReader(io.ErrUnexpectedEOF)))
		}
		return resp, err
	})
	var out bytes.Buffer
	if truncated, err := c.Output(t.Context(), testID, "events.jsonl", &out, 10); err != nil || truncated || out.String() != "complete" || calls.Load() != 2 {
		t.Fatalf("download after interrupted body = %q, requests = %d, error = %v", &out, calls.Load(), err)
	}
	out.Reset()
	if truncated, err := c.Output(t.Context(), testID, "events.jsonl", &out, 7); err != nil || !truncated || out.String() != "complet" || calls.Load() != 3 {
		t.Fatal("worker log was not saved at the byte limit")
	}
	out.Reset()
	if _, err := c.Egress(t.Context(), testID, &out, 2); !errors.Is(err, errOutputLimit) || out.Len() != 0 {
		t.Fatal("egress limit was not enforced before publishing")
	}
	dropped, err := c.Egress(t.Context(), testID, &out, 3)
	if err != nil || dropped != 3 || out.String() != "{}\n" {
		t.Fatalf("egress dropped = %d, error = %v", dropped, err)
	}
}

func TestWorkerDownloadTruncatedHeader(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Factory-Truncated", "1")
		fmt.Fprint(w, "prefix")
	})
	for _, name := range []string{"patch.diff", "changed-paths.txt", "events.jsonl", "stderr.log", "probe.txt"} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			truncated, err := c.Output(t.Context(), testID, name, &out, -1)
			if name == "patch.diff" || name == "changed-paths.txt" {
				if err == nil || truncated || out.Len() != 0 {
					t.Fatal("truncated patch output was accepted")
				}
			} else if err != nil || !truncated || out.String() != "prefix" {
				t.Fatal("truncated diagnostic output was not saved and reported")
			}
		})
	}
}

func TestWorkerOIDCRefresh(t *testing.T) {
	const audience = "worker-test-audience"
	workflowSHA := strings.Repeat("9", 40)
	now := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	epoch := now
	var requests atomic.Int32
	client := recorderClient(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("audience") != audience || r.URL.Query().Get("api-version") != "2" ||
			r.Header.Get("Authorization") != "Bearer "+testBearer {
			t.Error("wrong Actions runtime token request")
		}
		n := requests.Add(1)
		lifetime := 15 * time.Minute
		if n >= 2 {
			lifetime = 2 * time.Minute
		}
		sha := workflowSHA
		if n == 4 {
			sha = strings.Repeat("8", 40)
		}
		issuedAt := epoch.Add(4 * time.Minute)
		if n == 1 {
			issuedAt = epoch
		}
		payload := fmt.Sprintf(`{"exp":%d,"job_workflow_sha":%q}`, issuedAt.Add(lifetime).Unix(), sha)
		fmt.Fprintf(w, `{"value":"header.%s.signature%d"}`, base64.RawURLEncoding.EncodeToString([]byte(payload)), n)
	})
	auth := NewOIDCAuthenticator(client, claudeauth.Config{
		OIDCURL: testBase + "?api-version=2", OIDCRequestToken: testBearer, Audience: audience,
		ExpectedWorkflowSHA: workflowSHA, Now: func() time.Time { return now },
	})
	for _, tc := range []struct {
		age   time.Duration
		count int32
	}{
		{0, 1}, {3 * time.Minute, 1}, {4 * time.Minute, 2}, {4*time.Minute + 30*time.Second, 2}, {5 * time.Minute, 3},
	} {
		now = epoch.Add(tc.age)
		req := httptest.NewRequest("GET", testBase, nil)
		if err := auth.Authorize(t.Context(), req); err != nil || requests.Load() != tc.count ||
			!strings.HasSuffix(req.Header.Get("Authorization"), fmt.Sprint(".signature", tc.count)) {
			t.Fatalf("wrong worker token at %s, requests = %d, error = %v", tc.age, requests.Load(), err)
		}
	}
	req := httptest.NewRequest("GET", testBase, nil)
	if err := auth.Authorize(t.Context(), req); err == nil || req.Header.Get("Authorization") != "" || requests.Load() != 4 {
		t.Fatal("worker OIDC accepted a mismatched job_workflow_sha")
	}
}
