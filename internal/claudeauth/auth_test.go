package claudeauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func respond(code int, body string) (*http.Response, error) {
	return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
}

const factorySHA = "abcdef0123456789abcdef0123456789abcdef01"

func testAssertion(claims, signature string) string {
	return "fake-header." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + "." + signature
}

func factoryAssertion(signature string) string {
	return testAssertion(`{"job_workflow_sha":"`+factorySHA+`"}`, signature)
}

func testConfig() Config {
	return Config{
		OIDCURL:          "https://oidc.example.invalid/token?api-version=2.0&audience=replace-me",
		OIDCRequestToken: "fake-oidc-request-placeholder", FederationRuleID: "rule_test", OrganizationID: "org_test",
		ExpectedWorkflowSHA: factorySHA,
	}
}

func TestFederationRefresh(t *testing.T) {
	var oidc, exchanges int
	cfg := testConfig()
	cfg.ServiceAccountID, cfg.WorkspaceID = "service_test", "workspace_test"
	client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		if _, ok := r.Context().Deadline(); !ok {
			t.Fatal("auth request has no deadline")
		}
		switch r.URL.Host {
		case "oidc.example.invalid":
			if r.Method != "GET" || r.URL.Path != "/token" || r.URL.Query().Get("audience") != "https://api.anthropic.com" ||
				r.URL.Query().Get("api-version") != "2.0" || r.Header.Get("Authorization") != "Bearer "+cfg.OIDCRequestToken {
				t.Fatal("wrong OIDC method, path, query, or header")
			}
			oidc++
			return respond(200, fmt.Sprintf(`{"value":%q}`, factoryAssertion(fmt.Sprint(oidc))))
		case "api.example.invalid":
			if r.Method != "POST" || r.URL.RequestURI() != "/v1/oauth/token" ||
				r.Header.Get("Authorization") != "" || r.Header.Get("Content-Type") != "application/json" {
				t.Fatal("wrong exchange endpoint or headers")
			}
			defer r.Body.Close()
			exchanges++
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal("invalid exchange JSON")
			}
			want := map[string]string{
				"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": factoryAssertion(fmt.Sprint(exchanges)),
				"federation_rule_id": "rule_test", "organization_id": "org_test",
				"service_account_id": "service_test", "workspace_id": "workspace_test",
			}
			if !reflect.DeepEqual(body, want) || oidc != exchanges {
				t.Fatal("exchange requires a fresh OIDC assertion and exact JSON fields")
			}
			return respond(200, fmt.Sprintf(`{"access_token":"fake-access-%d","token_type":"Bearer","expires_in":300,"scope":"managed-agents"}`, exchanges))
		default:
			t.Fatal("unexpected authentication host")
			return nil, nil
		}
	})}
	auth := NewFederation("https://api.example.invalid", client, cfg)
	now := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	auth.now = func() time.Time { return now }
	authorize := func(expected string) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), "GET", "https://api.example.invalid/v1/agents", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := auth.Authorize(t.Context(), req); err != nil {
			t.Fatal(err)
		}
		if req.Header.Get("Authorization") != "Bearer "+expected {
			t.Fatal("wrong cached or refreshed credential")
		}
	}
	authorize("fake-access-1")
	now = now.Add(4 * time.Minute)
	authorize("fake-access-1")
	now = now.Add(time.Second)
	authorize("fake-access-2")
	if oidc != 2 || exchanges != 2 {
		t.Fatalf("OIDC requests = %d, exchanges = %d", oidc, exchanges)
	}
	if info, ok := auth.Info(); !ok || info.ExpiresIn != 300 || info.Scope != "managed-agents" {
		t.Fatal("wrong exchange metadata")
	}
}

func TestConcurrentFederation(t *testing.T) {
	var oidc, exchanges atomic.Int64
	cfg := testConfig()
	cfg.Audience = "custom audience"
	client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.Host {
		case "oidc.example.invalid":
			oidc.Add(1)
			if r.URL.Query().Get("audience") != cfg.Audience {
				t.Error("custom audience was not sent")
			}
			return respond(200, fmt.Sprintf(`{"value":%q}`, factoryAssertion("fake-signature")))
		case "api.example.invalid":
			exchanges.Add(1)
			defer r.Body.Close()
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 4 ||
				body["federation_rule_id"] == "" || body["organization_id"] == "" || body["assertion"] == "" || body["grant_type"] == "" {
				t.Error("expected the four required exchange fields")
			}
			return respond(200, `{"access_token":"fake-access-placeholder","token_type":"Bearer","expires_in":300,"scope":"managed-agents"}`)
		default:
			return nil, errors.New("unexpected authentication host")
		}
	})}
	auth := NewFederation("https://api.example.invalid", client, cfg)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 32 {
		wg.Go(func() {
			<-start
			req, err := http.NewRequestWithContext(t.Context(), "GET", "https://api.example.invalid/v1/agents", nil)
			if err != nil {
				t.Error(err)
				return
			}
			if err := auth.Authorize(t.Context(), req); err != nil {
				t.Error(err)
				return
			}
			if req.Header.Get("Authorization") != "Bearer fake-access-placeholder" {
				t.Error("wrong authorization header")
			}
		})
	}
	close(start)
	wg.Wait()
	if oidc.Load() != 1 || exchanges.Load() != 1 {
		t.Fatalf("OIDC requests = %d, exchanges = %d", oidc.Load(), exchanges.Load())
	}
}

func TestAuthenticationErrorsRedactSecrets(t *testing.T) {
	for _, tt := range []struct {
		name      string
		transport transportFunc
	}{
		{"OIDC response", func(*http.Request) (*http.Response, error) {
			return respond(401, "fake-oidc-request-placeholder")
		}},
		{"exchange response", func(r *http.Request) (*http.Response, error) {
			if r.URL.Host == "oidc.example.invalid" {
				return respond(200, fmt.Sprintf(`{"value":%q}`, factoryAssertion("fake-signature")))
			}
			defer r.Body.Close()
			return respond(403, factoryAssertion("fake-signature")+" fake-access-placeholder")
		}},
		{"malformed exchange response", func(r *http.Request) (*http.Response, error) {
			if r.URL.Host == "oidc.example.invalid" {
				return respond(200, fmt.Sprintf(`{"value":%q}`, factoryAssertion("fake-signature")))
			}
			defer r.Body.Close()
			return respond(200, factoryAssertion("fake-signature")+" fake-access-placeholder")
		}},
		{"transport error", func(*http.Request) (*http.Response, error) {
			return nil, errors.New("fake-oidc-request-placeholder")
		}},
		{"OIDC redirect", func(r *http.Request) (*http.Response, error) {
			if r.URL.Host != "oidc.example.invalid" {
				t.Error("OIDC redirect was followed")
			}
			resp, err := respond(307, "fake-oidc-request-placeholder")
			resp.Header.Set("Location", "https://other.example.invalid")
			return resp, err
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			auth := NewFederation("https://api.example.invalid", &http.Client{Transport: tt.transport}, testConfig())
			req, err := http.NewRequestWithContext(t.Context(), "GET", "https://api.example.invalid/v1/agents", nil)
			if err != nil {
				t.Fatal(err)
			}
			err = auth.Authorize(t.Context(), req)
			if err == nil || req.Header.Get("Authorization") != "" {
				t.Fatal("expected authentication to fail without setting the header")
			}
			if strings.Contains(fmt.Sprintf("%+v", err), "fake-") {
				t.Fatal("credential leaked in authentication error")
			}
		})
	}
}

func TestAuthenticationErrorDiagnostics(t *testing.T) {
	const requestToken = "fake-oidc-request-placeholder"
	assertion := factoryAssertion("fake-signature")
	const access = "fake-access-placeholder"
	const previous = "fake-previous-access-placeholder"
	for _, tt := range []struct {
		name, failureHost, body, want string
	}{
		{"OIDC fields", "oidc.example.invalid",
			`{"error":"request_failed","error_description":"denied ` + requestToken + `","message":"retry later"}`,
			"GitHub Actions OIDC request: HTTP 403: request_failed: denied [redacted]: retry later"},
		{"exchange fields", "api.example.invalid",
			`{"access_token":"` + access + `","error":{"type":"access_denied","message":"` + requestToken + " " + assertion + " " + access + " " + previous + `"}}`,
			"Anthropic federation exchange: HTTP 403: access_denied: [redacted] [redacted] [redacted] [redacted]"},
		{"unknown JWT", "api.example.invalid",
			`{"error":{"type":"denied","message":"echo eyJ` + strings.Repeat("a", 22) + `"}}`,
			"Anthropic federation exchange: HTTP 403"},
		{"unknown key past truncation", "api.example.invalid",
			`{"message":"` + strings.Repeat("x", 400) + ` sk-ant-fake-placeholder"}`,
			"Anthropic federation exchange: HTTP 403"},
		{"truncate after redacting", "api.example.invalid",
			`{"message":"` + strings.Repeat("日", 291) + access + ` tail","access_token":"` + access + `"}`,
			"Anthropic federation exchange: HTTP 403: " + strings.Repeat("日", 291) + "[redacted",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			auth := NewFederation("https://api.example.invalid", &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
				if r.Body != nil {
					defer r.Body.Close()
				}
				if r.URL.Host == tt.failureHost {
					return respond(http.StatusForbidden, tt.body)
				}
				return respond(http.StatusOK, `{"value":"`+assertion+`"}`)
			})}, testConfig())
			auth.token = previous
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.example.invalid/v1/agents", nil)
			if err != nil {
				t.Fatal(err)
			}
			err = auth.Authorize(t.Context(), req)
			if err == nil || !utf8.ValidString(err.Error()) || err.Error() != tt.want {
				t.Fatal("authentication error did not contain the expected safe diagnostic")
			}
		})
	}
}

func TestExchangeRequiresMatchingWorkflowSHA(t *testing.T) {
	other := strings.Repeat("a", 40)
	for _, tt := range []struct{ name, expected, claim, diagnostic string }{
		{"case insensitive", factorySHA, strings.ToUpper(factorySHA), ""},
		{"empty expected", "", factorySHA, `job_workflow_sha "` + factorySHA + `" does not match FACTORY_COMMIT ""`},
		{"missing claim", factorySHA, "", `job_workflow_sha "" does not match FACTORY_COMMIT "` + factorySHA + `"`},
		{"mismatch", factorySHA, other, `job_workflow_sha "` + other + `" does not match FACTORY_COMMIT "` + factorySHA + `"`},
		{"short claim", factorySHA, factorySHA[:39], `job_workflow_sha "<invalid SHA>"`},
		{"nonhex expected", strings.Repeat("z", 40), factorySHA, `FACTORY_COMMIT "<invalid SHA>"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.ExpectedWorkflowSHA = tt.expected
			claims := "{}"
			if tt.claim != "" {
				claims = fmt.Sprintf(`{"job_workflow_sha":%q}`, tt.claim)
			}
			exchanges := 0
			auth := NewFederation("https://api.example.invalid", &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Host == "oidc.example.invalid" {
					return respond(200, fmt.Sprintf(`{"value":%q}`, testAssertion(claims, "fake-signature")))
				}
				if r.Body != nil {
					defer r.Body.Close()
				}
				exchanges++
				return respond(200, `{"access_token":"fake-access-placeholder","token_type":"Bearer","expires_in":300}`)
			})}, cfg)
			req, err := http.NewRequestWithContext(t.Context(), "GET", "https://api.example.invalid/v1/agents", nil)
			if err != nil {
				t.Fatal(err)
			}
			err = auth.Authorize(t.Context(), req)
			if tt.diagnostic == "" {
				if err != nil || exchanges != 1 {
					t.Fatalf("matching SHA: %v, exchanges = %d", err, exchanges)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.diagnostic) || exchanges != 0 {
				t.Fatalf("invalid SHA: %v, exchanges = %d", err, exchanges)
			}
		})
	}
}
