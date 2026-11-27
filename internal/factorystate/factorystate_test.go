package factorystate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/toshi0607/agent-factory/internal/claudeauth"
)

const (
	testProvider       = "projects/123456789/locations/global/workloadIdentityPools/factory-pool/providers/github-main"
	testServiceAccount = "factory-work@factory-project.iam.gserviceaccount.com"
	testBucket         = "factory-state-test"
	testCommit         = "abcdef0123456789abcdef0123456789abcdef01"
	testRequestToken   = "fake-actions-request-placeholder"
	testFederated      = "fake-federated-placeholder"
	testAccess         = "fake-storage-access-placeholder"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type fakeObject struct {
	data       []byte
	generation int64
}

// fakeGoogle serves the GitHub OIDC endpoint, STS, IAM Credentials, and a
// Cloud Storage bucket with generation preconditions.
type fakeGoogle struct {
	t         *testing.T
	now       time.Time
	objects   map[string]fakeObject
	nextGen   int64
	requests  []string
	oidc      int
	exchanges int
	sleeps    []time.Duration
	expiresIn time.Duration
	// override, when it returns a response, replaces the normal handling.
	override func(*http.Request) *http.Response
}

func newFake(t *testing.T) *fakeGoogle {
	return &fakeGoogle{t: t, now: time.Date(2026, 11, 28, 9, 0, 0, 0, time.UTC), objects: map[string]fakeObject{},
		nextGen: 1000, expiresIn: 10 * time.Minute}
}

func response(status int, header http.Header, body string) *http.Response {
	if header == nil {
		header = make(http.Header)
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body))}
}

func (f *fakeGoogle) RoundTrip(req *http.Request) (*http.Response, error) {
	f.requests = append(f.requests, req.Method+" "+req.URL.Host+req.URL.RequestURI())
	if f.override != nil {
		if resp := f.override(req); resp != nil {
			return resp, nil
		}
	}
	var body []byte
	if req.Body != nil {
		var err error
		if body, err = io.ReadAll(req.Body); err != nil {
			f.t.Fatal(err)
		}
	}
	switch req.URL.Host {
	case "github.example.invalid":
		f.oidc++
		if req.Header.Get("Authorization") != "Bearer "+testRequestToken ||
			req.URL.Query().Get("audience") != "https://iam.googleapis.com/"+testProvider {
			f.t.Fatal("incorrect Actions OIDC request")
		}
		claims := fmt.Sprintf(`{"exp":%d,"job_workflow_sha":%q}`, f.now.Add(5*time.Minute).Unix(), testCommit)
		return response(200, nil, fmt.Sprintf(`{"value":"fake-header.%s.fake-signature"}`,
			base64.RawURLEncoding.EncodeToString([]byte(claims)))), nil
	case "sts.googleapis.com":
		form, err := url.ParseQuery(string(body))
		if err != nil || req.Method != http.MethodPost || req.URL.Path != "/v1/token" || req.Header.Get("Authorization") != "" ||
			req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" ||
			form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" ||
			form.Get("subject_token_type") != "urn:ietf:params:oauth:token-type:jwt" ||
			form.Get("requested_token_type") != "urn:ietf:params:oauth:token-type:access_token" ||
			form.Get("scope") != "https://www.googleapis.com/auth/cloud-platform" ||
			form.Get("audience") != "//iam.googleapis.com/"+testProvider ||
			!strings.HasSuffix(form.Get("subject_token"), ".fake-signature") || len(form) != 6 {
			f.t.Fatal("incorrect STS token exchange")
		}
		return response(200, nil, `{"access_token":"`+testFederated+`","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600}`), nil
	case "iamcredentials.googleapis.com":
		f.exchanges++
		if req.Method != http.MethodPost || req.URL.EscapedPath() != "/v1/projects/-/serviceAccounts/"+testServiceAccount+":generateAccessToken" ||
			req.Header.Get("Authorization") != "Bearer "+testFederated ||
			string(body) != `{"scope":["https://www.googleapis.com/auth/devstorage.read_write"],"lifetime":"600s"}` {
			f.t.Fatal("incorrect impersonation request")
		}
		token := fmt.Sprintf("%s-%d", testAccess, f.exchanges)
		return response(200, nil, fmt.Sprintf(`{"accessToken":%q,"expireTime":%q}`, token, f.now.Add(f.expiresIn).Format(time.RFC3339))), nil
	case "storage.googleapis.com":
		if !strings.HasPrefix(req.Header.Get("Authorization"), "Bearer "+testAccess+"-") {
			f.t.Fatal("storage request without the impersonated token")
		}
		return f.storage(req, body), nil
	default:
		f.t.Fatalf("request to unexpected host %q", req.URL.Host)
		return nil, nil
	}
}

func (f *fakeGoogle) storage(req *http.Request, body []byte) *http.Response {
	query := req.URL.Query()
	objectPrefix := "/storage/v1/b/" + testBucket + "/o/"
	switch {
	case req.Method == http.MethodPost && req.URL.EscapedPath() == "/upload/storage/v1/b/"+testBucket+"/o":
		if query.Get("uploadType") != "media" || req.Header.Get("Content-Type") != "application/json" {
			f.t.Fatal("incorrect upload request")
		}
		name := query.Get("name")
		want, err := strconv.ParseInt(query.Get("ifGenerationMatch"), 10, 64)
		if err != nil {
			f.t.Fatal("upload without ifGenerationMatch")
		}
		current, exists := f.objects[name]
		if (want == 0 && exists) || (want != 0 && (!exists || current.generation != want)) {
			return response(412, nil, `{"error":{"code":412,"message":"conditionNotMet","status":"FAILED_PRECONDITION"}}`)
		}
		f.nextGen++
		f.objects[name] = fakeObject{data: body, generation: f.nextGen}
		return response(200, nil, fmt.Sprintf(`{"generation":"%d"}`, f.nextGen))
	case strings.HasPrefix(req.URL.EscapedPath(), objectPrefix):
		escaped := strings.TrimPrefix(req.URL.EscapedPath(), objectPrefix)
		if strings.Contains(escaped, "/") {
			f.t.Fatal("object name was not escaped")
		}
		name, err := url.PathUnescape(escaped)
		if err != nil {
			f.t.Fatal(err)
		}
		current, exists := f.objects[name]
		switch req.Method {
		case http.MethodGet:
			if query.Get("alt") != "media" {
				f.t.Fatal("object read without alt=media")
			}
			if !exists {
				return response(404, nil, `{"error":{"code":404,"message":"No such object","status":"NOT_FOUND"}}`)
			}
			header := make(http.Header)
			header.Set("x-goog-generation", strconv.FormatInt(current.generation, 10))
			return response(200, header, string(current.data))
		case http.MethodDelete:
			want, err := strconv.ParseInt(query.Get("ifGenerationMatch"), 10, 64)
			if err != nil || want <= 0 {
				f.t.Fatal("delete without a generation precondition")
			}
			if !exists {
				return response(404, nil, "")
			}
			if current.generation != want {
				return response(412, nil, "")
			}
			delete(f.objects, name)
			return response(204, nil, "")
		}
	}
	f.t.Fatalf("unexpected storage request %s %s", req.Method, req.URL.RequestURI())
	return nil
}

func (f *fakeGoogle) store(t *testing.T) *Store {
	t.Helper()
	s, err := New(Config{Provider: testProvider, ServiceAccount: testServiceAccount, Bucket: testBucket},
		&http.Client{Transport: f}, claudeauth.Config{
			OIDCURL: "https://github.example.invalid/oidc", OIDCRequestToken: testRequestToken,
			ExpectedWorkflowSHA: testCommit, Now: func() time.Time { return f.now },
		})
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return f.now }
	s.objects.tokens.(*tokenSource).now = func() time.Time { return f.now }
	s.objects.google.sleep = func(_ context.Context, d time.Duration) error {
		f.sleeps = append(f.sleeps, d)
		return nil
	}
	return s
}

func TestConfigFromEnv(t *testing.T) {
	valid := map[string]string{EnvProvider: testProvider, EnvServiceAccount: testServiceAccount, EnvBucket: testBucket}
	env := func(values map[string]string) func(string) string {
		return func(name string) string { return values[name] }
	}
	if _, ok, err := ConfigFromEnv(env(nil)); ok || err != nil {
		t.Fatalf("empty environment = %v, %v; want unconfigured", ok, err)
	}
	cfg, ok, err := ConfigFromEnv(env(valid))
	if !ok || err != nil || cfg != (Config{testProvider, testServiceAccount, testBucket}) {
		t.Fatalf("valid environment = %+v, %v, %v", cfg, ok, err)
	}
	for _, name := range []string{EnvProvider, EnvServiceAccount, EnvBucket} {
		partial := map[string]string{name: valid[name]}
		_, ok, err := ConfigFromEnv(env(partial))
		if ok || err == nil || strings.Contains(err.Error(), valid[name]) {
			t.Fatalf("partial configuration with only %s = %v, %v", name, ok, err)
		}
	}
	for name, bad := range map[string]string{
		EnvProvider:       "projects/abc/locations/global/workloadIdentityPools/factory-pool/providers/github-main",
		EnvServiceAccount: "factory-work@factory-project.example.com",
		EnvBucket:         "Factory_State",
	} {
		values := map[string]string{}
		for k, v := range valid {
			values[k] = v
		}
		values[name] = bad
		_, _, err := ConfigFromEnv(env(values))
		if err == nil || !strings.Contains(err.Error(), name) || strings.Contains(err.Error(), bad) {
			t.Fatalf("invalid %s = %v", name, err)
		}
	}
}

func TestTokenExchangeCacheAndRefresh(t *testing.T) {
	f := newFake(t)
	s := f.store(t)
	for range 3 {
		if _, err := s.Stopped(t.Context()); err != nil {
			t.Fatal(err)
		}
		f.now = f.now.Add(2 * time.Minute)
	}
	// Six minutes after the exchange, four remain: still cached.
	if f.exchanges != 1 || f.oidc != 1 {
		t.Fatalf("exchanges = %d, OIDC requests = %d; want one cached token", f.exchanges, f.oidc)
	}
	f.now = f.now.Add(2*time.Minute + time.Second)
	if _, err := s.Stopped(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.exchanges != 2 || f.oidc != 2 {
		t.Fatalf("exchanges = %d; want a refresh with under two minutes left", f.exchanges)
	}
	f.expiresIn = time.Hour
	f.now = f.now.Add(9 * time.Minute)
	if _, err := s.Stopped(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(9 * time.Minute)
	if _, err := s.Stopped(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.exchanges != 4 {
		t.Fatalf("exchanges = %d; the cache must not outlive the requested 600s lifetime", f.exchanges)
	}
}

func TestTokenRequiresFactoryCommit(t *testing.T) {
	f := newFake(t)
	s := f.store(t)
	s.objects.tokens.(*tokenSource).oidc.ExpectedWorkflowSHA = ""
	if _, err := s.Stopped(t.Context()); err == nil || !strings.Contains(err.Error(), "FACTORY_COMMIT") {
		t.Fatalf("Stopped = %v; want a missing FACTORY_COMMIT error", err)
	}
	if len(f.requests) != 0 {
		t.Fatalf("requests = %v; want none without FACTORY_COMMIT", f.requests)
	}
}

func TestHostAllowlistAndRedirects(t *testing.T) {
	f := newFake(t)
	s := f.store(t)
	for _, target := range []string{
		"http://storage.googleapis.com/storage/v1/b",
		"https://storage.googleapis.com:8443/storage/v1/b",
		"https://user@storage.googleapis.com/storage/v1/b",
		"https://storage.googleapis.com.example.invalid/storage/v1/b",
		"https://oauth2.googleapis.com/token",
	} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.objects.google.do(req, "test"); err == nil || !strings.Contains(err.Error(), "allowlist") {
			t.Fatalf("%s: error = %v; want an allowlist refusal", target, err)
		}
	}
	if len(f.requests) != 0 {
		t.Fatalf("disallowed hosts were contacted: %v", f.requests)
	}
	f.override = func(req *http.Request) *http.Response {
		if req.URL.Host == "storage.googleapis.com" {
			header := make(http.Header)
			header.Set("Location", "https://attacker.example.invalid/steal")
			return response(302, header, "")
		}
		return nil
	}
	if _, err := s.Stopped(t.Context()); statusOf(err) != 302 {
		t.Fatalf("redirect = %v; want an HTTP 302 error", err)
	}
	for _, r := range f.requests {
		if strings.Contains(r, "attacker") {
			t.Fatal("redirect was followed")
		}
	}
}

func TestErrorsAreSanitized(t *testing.T) {
	for _, tc := range []struct {
		host, body, want string
	}{
		{"sts.googleapis.com", `{"error":"invalid_grant","error_description":"bad token eyJhbGciOiJSUzI1NiJ9abcdefghijklmnop for ` + testProvider + `"}`, "HTTP 400: invalid_grant"},
		{"iamcredentials.googleapis.com", `{"error":{"code":403,"message":"Permission denied on ` + testServiceAccount + ` with ` + testFederated + `","status":"PERMISSION_DENIED"}}`, "HTTP 400: PERMISSION_DENIED"},
		{"storage.googleapis.com", `{"error":{"code":400,"message":"` + testBucket + ` ` + testAccess + `","status":"bad status with spaces"}}`, "HTTP 400"},
	} {
		t.Run(tc.host, func(t *testing.T) {
			f := newFake(t)
			s := f.store(t)
			f.override = func(req *http.Request) *http.Response {
				if req.URL.Host == tc.host {
					return response(400, nil, tc.body)
				}
				return nil
			}
			_, err := s.Stopped(t.Context())
			if err == nil || !strings.HasSuffix(err.Error(), tc.want) {
				t.Fatalf("error = %v; want suffix %q", err, tc.want)
			}
			for _, secret := range []string{"eyJ", testProvider, testServiceAccount, testFederated, testAccess, testBucket, testRequestToken} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error %q contains %q", err, secret)
				}
			}
		})
	}
	f := newFake(t)
	s := f.store(t)
	s.objects.google.http.Transport = transportFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "storage.googleapis.com" {
			return nil, errors.New("dial " + req.URL.String() + " " + req.Header.Get("Authorization"))
		}
		return f.RoundTrip(req)
	})
	_, err := s.Stopped(t.Context())
	if err == nil || strings.Contains(err.Error(), "storage.googleapis.com") || strings.Contains(err.Error(), testAccess) ||
		!errors.Is(err, errTransport) {
		t.Fatalf("transport error = %v; want a generic failure", err)
	}
}

func TestStopFlag(t *testing.T) {
	f := newFake(t)
	s := f.store(t)
	flag, err := s.Stopped(t.Context())
	if err != nil || flag != nil {
		t.Fatalf("Stopped on an empty bucket = %+v, %v", flag, err)
	}
	already, err := s.Stop(t.Context(), "judge infrastructure failed twice", "collect", "p0-20261128T090000Z-abcdef01")
	if err != nil || already {
		t.Fatalf("first Stop = %v, %v", already, err)
	}
	f.now = f.now.Add(time.Hour)
	already, err = s.Stop(t.Context(), "second reason", "reflect", "")
	if err != nil || !already {
		t.Fatalf("second Stop = %v, %v; want already set", already, err)
	}
	flag, err = s.Stopped(t.Context())
	want := StopFlag{Reason: "judge infrastructure failed twice", SetBy: "collect", WorkID: "p0-20261128T090000Z-abcdef01",
		SetAt: time.Date(2026, 11, 28, 9, 0, 0, 0, time.UTC)}
	if err != nil || flag == nil || *flag != want {
		t.Fatalf("Stopped = %+v, %v; want the first flag unchanged", flag, err)
	}
	if !strings.Contains(strings.Join(f.requests, "\n"), "/o/stop%2Fflag.json?alt=media") {
		t.Fatalf("flag name was not escaped: %v", f.requests)
	}
	for _, tc := range []struct{ reason, stage, workID string }{
		{"", "collect", ""},
		{"two\nlines", "collect", ""},
		{"escape \x1b[31m", "collect", ""},
		{strings.Repeat("x", 201), "collect", ""},
		{"ok", "Collect", ""},
		{"ok", "collect", "bad id"},
	} {
		if _, err := s.Stop(t.Context(), tc.reason, tc.stage, tc.workID); err == nil {
			t.Errorf("Stop(%q, %q, %q) accepted invalid input", tc.reason, tc.stage, tc.workID)
		}
	}
	if _, err := s.Stop(t.Context(), strings.Repeat("é", 200), "collect", ""); err != nil {
		t.Fatalf("200-character reason rejected: %v", err)
	}
}

func TestStoppedFailsClosed(t *testing.T) {
	for name, data := range map[string]string{
		"malformed": `{"reason":`, "null": "null", "array": `[]`, "bad time": `{"set_at":"yesterday"}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.objects[stopObject] = fakeObject{data: []byte(data), generation: 7}
			flag, err := f.store(t).Stopped(t.Context())
			if err == nil || flag != nil {
				t.Fatalf("Stopped = %+v, %v; want an error", flag, err)
			}
		})
	}
	f := newFake(t)
	f.objects[stopObject] = fakeObject{data: []byte(`{}`), generation: 7}
	if flag, err := f.store(t).Stopped(t.Context()); err != nil || flag == nil {
		t.Fatalf("hand-written empty flag = %+v, %v; want stopped", flag, err)
	}
}

func TestInProgressRecord(t *testing.T) {
	f := newFake(t)
	s := f.store(t)
	rec := InProgress{WorkID: "p0-20261128T090000Z-abcdef01", Role: "fixer", Task: "sm-versions", BaseCommit: "base",
		Candidate: "managed-agents", BudgetCents: 300, MinutesLimit: 30, StartedAt: f.now, RunID: "42", RunAttempt: "1"}
	if existing, err := s.Begin(t.Context(), rec); err != nil || existing != nil {
		t.Fatalf("Begin = %+v, %v", existing, err)
	}
	other := rec
	other.WorkID = "p0-20261128T090500Z-00000002"
	existing, err := s.Begin(t.Context(), other)
	if err != nil || existing == nil || *existing != rec {
		t.Fatalf("second Begin = %+v, %v; want the first record", existing, err)
	}
	current, generation, err := s.Current(t.Context())
	if err != nil || current == nil || *current != rec || generation != f.objects[inProgressObject].generation {
		t.Fatalf("Current = %+v, %d, %v", current, generation, err)
	}
	updated := rec
	updated.SessionID = "session-1"
	if err := s.Update(t.Context(), updated, generation); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(t.Context(), updated, generation); err == nil || !strings.Contains(err.Error(), "changed since it was read") {
		t.Fatalf("stale Update = %v; want a precondition error", err)
	}
	if current, _, _ := s.Current(t.Context()); current == nil || current.SessionID != "session-1" {
		t.Fatalf("record after Update = %+v", current)
	}
	if err := s.End(t.Context(), other.WorkID); err != nil || len(f.objects) != 1 {
		t.Fatalf("End for another unit = %v; want the record kept", err)
	}
	if err := s.End(t.Context(), rec.WorkID); err != nil || len(f.objects) != 0 {
		t.Fatalf("End = %v, objects = %v", err, f.objects)
	}
	if err := s.End(t.Context(), rec.WorkID); err != nil {
		t.Fatalf("End on an absent record = %v", err)
	}
	if !strings.Contains(strings.Join(f.requests, "\n"), "DELETE storage.googleapis.com/storage/v1/b/"+testBucket+"/o/in-progress%2Fcurrent.json?ifGenerationMatch=") {
		t.Fatalf("End did not delete with a generation precondition: %v", f.requests)
	}
	if _, err := s.Begin(t.Context(), InProgress{WorkID: "bad id"}); err == nil {
		t.Fatal("Begin accepted an invalid work ID")
	}
	f.objects[inProgressObject] = fakeObject{data: []byte(`{"work_id":""}`), generation: 3}
	if _, err := s.Begin(t.Context(), rec); err == nil {
		t.Fatal("Begin accepted a malformed existing record")
	}
	if err := s.End(t.Context(), rec.WorkID); err == nil || len(f.objects) != 1 {
		t.Fatal("End removed a malformed record")
	}
}

func TestEndDeleteChangedSinceRead(t *testing.T) {
	f := newFake(t)
	s := f.store(t)
	f.objects[inProgressObject] = fakeObject{data: []byte(`{"work_id":"work-1"}`), generation: 5}
	f.override = func(req *http.Request) *http.Response {
		if req.Method == http.MethodDelete {
			return response(412, nil, "")
		}
		return nil
	}
	if err := s.End(t.Context(), "work-1"); err == nil || !strings.Contains(err.Error(), "changed since it was read") {
		t.Fatalf("End = %v; want a precondition error", err)
	}
}

func TestReadRetries(t *testing.T) {
	for _, tc := range []struct {
		name     string
		statuses []int
		attempts int
		wantErr  bool
	}{
		{"recovers", []int{503, 429}, 3, false},
		{"gives up", []int{500, 502, 503, 504, 500}, 4, true},
		{"forbidden", []int{403}, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			s := f.store(t)
			var attempts int
			f.override = func(req *http.Request) *http.Response {
				if req.URL.Host != "storage.googleapis.com" {
					return nil
				}
				attempts++
				if attempts <= len(tc.statuses) {
					return response(tc.statuses[attempts-1], nil, "")
				}
				return nil
			}
			_, err := s.Stopped(t.Context())
			if (err != nil) != tc.wantErr || attempts != tc.attempts {
				t.Fatalf("Stopped = %v after %d attempts; want error %v after %d", err, attempts, tc.wantErr, tc.attempts)
			}
			if want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}[:tc.attempts-1]; !slices.Equal(f.sleeps, want) {
				t.Fatalf("backoff = %v, want %v", f.sleeps, want)
			}
		})
	}
	f := newFake(t)
	s := f.store(t)
	f.objects[inProgressObject] = fakeObject{data: []byte(`{"work_id":"work-1"}`), generation: 5}
	var deletes int
	f.override = func(req *http.Request) *http.Response {
		if req.Method == http.MethodDelete {
			deletes++
			if deletes == 1 {
				delete(f.objects, inProgressObject)
				return response(503, nil, "")
			}
		}
		return nil
	}
	if err := s.End(t.Context(), "work-1"); err != nil || deletes != 2 {
		t.Fatalf("End = %v after %d deletes; want a retried delete that finds the object gone", err, deletes)
	}
}

func TestUploadIsNotRetriedAndAmbiguityIsResolved(t *testing.T) {
	rec := InProgress{WorkID: "work-1"}
	for _, tc := range []struct {
		name      string
		apply     bool
		transport bool
		existing  bool
		wantErr   bool
		wantFound bool
	}{
		{"applied before 503", true, false, false, false, false},
		{"lost before 503", false, false, false, true, false},
		{"applied before transport error", true, true, false, false, false},
		{"other writer won", false, true, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			s := f.store(t)
			if tc.existing {
				f.objects[inProgressObject] = fakeObject{data: []byte(`{"work_id":"work-2"}`), generation: 9}
			}
			var uploads int
			transport := s.objects.google.http.Transport
			s.objects.google.http.Transport = transportFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodPost || req.URL.Host != "storage.googleapis.com" {
					return transport.RoundTrip(req)
				}
				uploads++
				if tc.apply {
					resp, _ := transport.RoundTrip(req)
					resp.Body.Close()
				}
				if tc.transport {
					return nil, errors.New("connection reset")
				}
				return response(503, nil, ""), nil
			})
			existing, err := s.Begin(t.Context(), rec)
			if uploads != 1 {
				t.Fatalf("uploads = %d; an upload must be sent once", uploads)
			}
			if (err != nil) != tc.wantErr || (existing != nil) != tc.wantFound {
				t.Fatalf("Begin = %+v, %v", existing, err)
			}
			if tc.wantFound && existing.WorkID != "work-2" {
				t.Fatalf("Begin returned %+v, want the other writer's record", existing)
			}
		})
	}
}

func TestReadLimitsAndGeneration(t *testing.T) {
	f := newFake(t)
	s := f.store(t)
	f.objects[stopObject] = fakeObject{data: []byte(`{"reason":"` + strings.Repeat("x", maxObjectBytes) + `"}`), generation: 2}
	if _, err := s.Stopped(t.Context()); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized flag = %v", err)
	}
	f.override = func(req *http.Request) *http.Response {
		if req.URL.Host == "storage.googleapis.com" {
			return response(200, nil, `{}`)
		}
		return nil
	}
	if _, err := s.Stopped(t.Context()); err == nil || !strings.Contains(err.Error(), "generation") {
		t.Fatalf("read without a generation = %v", err)
	}
	f.override = nil
	big := InProgress{WorkID: "work-1", Task: strings.Repeat("x", maxObjectBytes)}
	if _, err := s.Begin(t.Context(), big); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized upload = %v", err)
	}
	if err := s.Update(t.Context(), InProgress{WorkID: "work-1"}, 0); err == nil {
		t.Fatal("Update accepted generation 0, which would mean create-only")
	}
}

func TestStateDoesNotLeakTokens(t *testing.T) {
	f := newFake(t)
	s := f.store(t)
	if _, err := s.Stop(t.Context(), "reason", "collect", ""); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(f.objects)
	if err != nil {
		t.Fatal(err)
	}
	for _, object := range f.objects {
		for _, secret := range []string{testAccess, testFederated, testRequestToken, "fake-signature"} {
			if strings.Contains(string(object.data), secret) || strings.Contains(string(data), secret) {
				t.Fatal("stored object contains a credential")
			}
		}
	}
}

func TestAttemptTimeoutIsATransportFailure(t *testing.T) {
	hang := func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}
	f := newFake(t)
	s := f.store(t)
	s.objects.google.timeout = 20 * time.Millisecond
	transport := s.objects.google.http.Transport
	var reads int
	s.objects.google.http.Transport = transportFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodGet && req.URL.Host == "storage.googleapis.com" {
			reads++
			if reads < 3 {
				return hang(req)
			}
		}
		return transport.RoundTrip(req)
	})
	if flag, err := s.Stopped(t.Context()); err != nil || flag != nil || reads != 3 {
		t.Fatalf("Stopped = %+v, %v after %d reads; want timed-out reads retried", flag, err, reads)
	}

	f = newFake(t)
	s = f.store(t)
	s.objects.google.timeout = 20 * time.Millisecond
	transport = s.objects.google.http.Transport
	var uploads int
	s.objects.google.http.Transport = transportFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPost && req.URL.Host == "storage.googleapis.com" {
			uploads++
			resp, err := transport.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			return hang(req)
		}
		return transport.RoundTrip(req)
	})
	if existing, err := s.Begin(t.Context(), InProgress{WorkID: "work-1"}); err != nil || existing != nil || uploads != 1 {
		t.Fatalf("Begin = %+v, %v after %d uploads; want the landed write resolved by one read", existing, err, uploads)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := f.store(t).Stopped(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Stopped = %v, want context.Canceled", err)
	}
}
