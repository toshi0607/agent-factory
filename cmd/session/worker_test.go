package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/toshi0607/agent-factory/internal/cfsandbox"
	"github.com/toshi0607/agent-factory/internal/claudeauth"
	"github.com/toshi0607/agent-factory/internal/delivery"
	"github.com/toshi0607/agent-factory/poc/record"
)

const (
	testWorkerBase     = "https://worker.example.invalid"
	testWorkerAudience = "factory-worker-test"
	testRuntimeToken   = "synthetic-runtime-credential"
	testAccessToken    = "synthetic-claude-credential"
)

func workerTestRunner(t *testing.T, clock *fakeClock, handle http.HandlerFunc) runner {
	t.Helper()
	httpClient := &http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
		if req.Body != nil {
			defer req.Body.Close()
		}
		w := httptest.NewRecorder()
		switch req.URL.Path {
		case "/oidc":
			if req.Header.Get("Authorization") != "Bearer "+testRuntimeToken || req.Method != http.MethodGet ||
				req.URL.Query().Get("api-version") != "2" {
				t.Fatal("incorrect Actions OIDC request")
			}
			claims := fmt.Sprintf(`{"exp":%d,"job_workflow_sha":%q}`, clock.Now().Add(5*time.Minute).Unix(), factoryCommit)
			audience := req.URL.Query().Get("audience")
			if audience != testWorkerAudience && audience != "claude-federation-test" {
				t.Fatal("unexpected OIDC audience")
			}
			fmt.Fprintf(w, `{"value":"header.%s.%s"}`, base64.RawURLEncoding.EncodeToString([]byte(claims)), audience)
		case "/v1/oauth/token":
			var payload struct {
				Assertion string `json:"assertion"`
			}
			decode(t, readRequest(t, req), &payload)
			if req.Method != http.MethodPost || req.Header.Get("Authorization") != "" ||
				!strings.HasSuffix(payload.Assertion, ".claude-federation-test") {
				t.Fatal("Claude exchange received the wrong credential")
			}
			fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":600}`, testAccessToken)
		default:
			if req.URL.Host != strings.TrimPrefix(testWorkerBase, "https://") ||
				!strings.HasSuffix(req.Header.Get("Authorization"), "."+testWorkerAudience) {
				t.Fatal("worker received the wrong credential or host")
			}
			handle(w, req)
		}
		return w.Result(), nil
	})}
	cfg := claudeauth.Config{
		OIDCURL: testWorkerBase + "/oidc?api-version=2", OIDCRequestToken: testRuntimeToken,
		Audience: "claude-federation-test", ExpectedWorkflowSHA: factoryCommit,
		FederationRuleID: "test-rule", OrganizationID: "test-org", Now: clock.Now,
	}
	auth := claudeauth.NewFederation(testWorkerBase, httpClient, cfg)
	cfg.Audience = testWorkerAudience
	client, err := cfsandbox.New(testWorkerBase, httpClient, cfsandbox.NewOIDCAuthenticator(httpClient, cfg))
	if err != nil {
		t.Fatal(err)
	}
	return runner{worker: client, auth: auth, clock: clock, pollInterval: 10 * time.Second, stdout: io.Discard}
}

func TestWorkerSessionLifecycle(t *testing.T) {
	t.Chdir("../..")
	t.Setenv("FACTORY_COMMIT", factoryCommit)
	cfg, dir, manifest := preparedFiles(t)
	goArchive := manifest.Files[5].Name
	if err := os.Remove(filepath.Join(dir, goArchive)); err != nil {
		t.Fatal(err)
	}
	policy := strings.Replace(read(t, cfg), "roles:\n", `  extra:
    path_rules:
      - host: modules.example.invalid
        path_prefixes: [/test/]
roles:
`, 1)
	write(t, cfg, strings.Replace(policy, "egress: [gomod]", "egress: [gomod, extra]", 1))

	dest := t.TempDir()
	statePath, out := filepath.Join(dest, "state.json"), filepath.Join(dest, "out")
	clock := testClock()
	started := clock.Now()
	finished := started.Add(19 * time.Second)
	const (
		workerVersion = "test-version"
		workerCommit  = "test-deploy-commit"
		patch         = "test patch\n"
		paths         = "first.go\n\nsecond.go\n"
		egress        = "{\"decision\":\"deny\"}\n"
		stderr        = "test stderr\x00\n"
	)
	events := "bad JSON\n" +
		`{"type":"assistant","message":{"content":[{"type":"tool_use","name":"WebFetch"},{"type":"text","name":"WebSearch"}]}}` + "\n" +
		`{"type":"tool_use","name":"WebFetch","padding":"` + strings.Repeat("a", workerEventLineMax) + "\"}\n" +
		`{"type":"assistant","message":{"content":[{"type":"tool_use","name":"WebSearch"},{"type":"tool_use","name":"WebSearch"}]}}`
	var wantRoutes, routes []string
	for _, entry := range manifest.Files {
		if entry.Name != goArchive {
			wantRoutes = append(wantRoutes, "PUT /files/"+entry.Name)
		}
	}
	wantRoutes = append(wantRoutes, "PUT /files/manifest.json", "PUT /token", "POST /start",
		"GET ", "GET /outputs/"+patchName, "GET /outputs/"+pathsName, "GET /outputs/"+probeName,
		"GET /outputs/"+workerEventsName, "GET /outputs/"+workerStderrName, "GET /egress", "DELETE ", "DELETE ")
	var requestDigest string
	r := workerTestRunner(t, clock, func(w http.ResponseWriter, req *http.Request) {
		s, err := readJSON[state](statePath)
		if err != nil || s.Candidate != workerCandidate || !cfsandbox.ValidRunID(s.WorkID) ||
			!strings.HasPrefix(req.URL.Path, "/runs/"+s.WorkID) {
			t.Fatal("worker request preceded durable state or used another run ID")
		}
		suffix := strings.TrimPrefix(req.URL.Path, "/runs/"+s.WorkID)
		routes = append(routes, req.Method+" "+suffix)
		switch {
		case strings.HasPrefix(suffix, "/files/"):
			name := strings.TrimPrefix(suffix, "/files/")
			data := readRequest(t, req)
			if string(data) != read(t, filepath.Join(dir, name)) || req.ContentLength != int64(len(data)) {
				t.Fatal("worker upload did not preserve file bytes")
			}
			fmt.Fprintf(w, `{"name":%q,"bytes":%d,"sha256":"%x"}`, name, len(data), sha256.Sum256(data))
		case suffix == "/token":
			var token struct {
				AccessToken string `json:"access_token"`
				ExpiresIn   int    `json:"expires_in"`
			}
			decode(t, readRequest(t, req), &token)
			if token.AccessToken != testAccessToken || token.ExpiresIn != 600 {
				t.Fatal("worker received incorrect token and expiry")
			}
		case suffix == "/start":
			request := readRequest(t, req)
			requestDigest = fmt.Sprintf("%x", sha256.Sum256(request))
			var got map[string]any
			decode(t, request, &got)
			var want map[string]any
			decode(t, []byte(fmt.Sprintf(`{
 "role":"fixer","model":"claude-opus-5-5","system_prompt":%s,
 "user_message":"Set up with: bash /factory/delivery/setup.sh\nThe task is in: /factory/delivery/task.md\nWhen you are done, run: bash /factory/delivery/finish.sh\nThen reply DONE.",
 "budget_cents":299,"minutes":25,
 "prices":{"input":400,"output":2000,"cache_write_5m":500,"cache_write_1h":800,"cache_read":20},
 "egress":[{"host":"proxy.golang.org"},{"host":"sum.golang.org"},{"host":"modules.example.invalid","path_prefixes":["/test/"]}]
}`, jsonString(t, read(t, "prompts/fixer.md")))), &want)
			if !reflect.DeepEqual(got, want) {
				t.Fatal("worker did not receive the exact start request fields")
			}
			w.WriteHeader(202)
			fmt.Fprintf(w, `{"state":"running","started_at":%q,"worker_version":{"id":%q,"tag":"","timestamp":""},"factory_commit":%q}`,
				started.Format(time.RFC3339), workerVersion, workerCommit)
		case suffix == "" && req.Method == http.MethodGet:
			fmt.Fprintf(w, `{
 "id":%q,"state":"finished","stop_reason":"completed","started_at":%q,"finished_at":%q,
 "usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":3,"cache_creation_5m_input_tokens":2,
 "cache_creation_1h_input_tokens":1,"cost_microcents":1400000,"unmetered_responses":2},
 "egress":{"allowed":6,"denied":21,"llm":1,"dropped":3,"denied_hosts":["denied.example.invalid"]},
 "container":{"running":true,"instance":"standard-3"},"agent_result":{"total_cost_usd":0.01}
}`, s.WorkID, started.Format(time.RFC3339), finished.Format(time.RFC3339))
		case suffix == "/outputs/"+patchName:
			fmt.Fprint(w, patch)
		case suffix == "/outputs/"+pathsName:
			fmt.Fprint(w, paths)
		case suffix == "/outputs/"+probeName:
			w.WriteHeader(404)
			fmt.Fprint(w, `{"error":"not_found"}`)
		case suffix == "/outputs/"+workerEventsName:
			fmt.Fprint(w, events)
		case suffix == "/outputs/"+workerStderrName:
			fmt.Fprint(w, stderr)
		case suffix == "/egress":
			w.Header().Set("x-egress-dropped", "3")
			fmt.Fprint(w, egress)
		case suffix == "" && req.Method == http.MethodDelete:
			if _, err := os.Stat(filepath.Join(out, "record.partial.json")); err != nil {
				t.Fatal("worker run deleted before the partial record was written")
			}
			w.WriteHeader(204)
		default:
			t.Error("unexpected worker request")
			w.WriteHeader(400)
		}
	})
	if err := r.run(t.Context(), []string{"start", "-candidate", workerCandidate, "-policy", cfg, "-files", dir,
		"-state", statePath, "-minutes", "25", "-budget-cents", "299"}); err != nil {
		t.Fatal(err)
	}
	s, err := readJSON[state](statePath)
	if err != nil || s.WorkID != s.SessionID || !s.StartedAt.Equal(started) || s.WorkerVersion != workerVersion ||
		s.WorkerFactoryCommit != workerCommit || s.WorkerTokenPushedAt == nil || s.AgentRequestSHA256 != requestDigest ||
		s.EnvironmentRequestSHA256 != requestDigest || s.FactoryCommit != factoryCommit {
		t.Fatal("start did not persist worker metadata and request digests")
	}
	for _, value := range []string{testAccessToken, testRuntimeToken, testWorkerBase} {
		if strings.Contains(read(t, statePath), value) {
			t.Fatal("state contains a secret or the worker URL")
		}
	}
	if err := r.run(t.Context(), []string{"collect", "-state", statePath, "-out", out}); err != nil {
		t.Fatal(err)
	}
	rec, err := readJSON[record.Record](filepath.Join(out, "record.partial.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Validate(); err != nil {
		t.Fatal(err)
	}
	if rec.Candidate != workerCandidate || rec.StopReason != "completed" ||
		rec.Session != (record.Session{ID: s.WorkID, Status: "finished", ActiveSeconds: 19, DurationSeconds: 19}) ||
		rec.AgentRequestSHA256 != requestDigest || rec.EnvironmentRequestSHA256 != requestDigest ||
		rec.Patch.SHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(patch))) || rec.Patch.Bytes != int64(len(patch)) ||
		!slices.Equal(rec.Patch.Paths, []string{"first.go", "second.go"}) {
		t.Fatalf("unexpected worker record: %+v", rec)
	}
	wantUsage := record.Usage{InputTokens: 10, OutputTokens: 5, CacheReadInputTokens: 3, CacheCreation5mInputTokens: 2,
		CacheCreation1hInputTokens: 1, WebFetchRequests: 1, WebSearchRequests: 2,
		ReportedCost: record.ReportedCost{Amount: "2", Currency: "USD"}}
	if rec.Usage != wantUsage || !rec.Egress.LogAvailable || !slices.Equal(rec.Egress.DeniedDestinations, []string{"denied.example.invalid"}) ||
		rec.Egress.Notes != "allowed=6 denied=21 llm=1 dropped=3 unmetered_responses=2" {
		t.Fatalf("unexpected usage or egress: %+v %+v", rec.Usage, rec.Egress)
	}
	for _, note := range []string{workerVersion, workerCommit, "standard-3", "cost_microcents=1400000", "Agent-reported total_cost_usd=0.01"} {
		if !strings.Contains(rec.Notes, note) {
			t.Errorf("worker record omitted %q", note)
		}
	}
	for name, want := range map[string]string{patchName: patch, pathsName: paths, workerEgressName: egress,
		workerEventsName: events, workerStderrName: stderr} {
		if read(t, filepath.Join(out, name)) != want {
			t.Errorf("worker collection changed bytes of %s", name)
		}
	}
	minimal := state{Candidate: workerCandidate, WorkID: s.WorkID}
	if err := writeJSON(statePath, minimal, delivery.WriteAtomic); err != nil {
		t.Fatal(err)
	}
	r.auth = nil
	if err := r.run(t.Context(), []string{"cleanup", "-state", statePath}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(routes, wantRoutes) {
		t.Fatalf("worker routes = %v, want %v", routes, wantRoutes)
	}
}

func jsonString(t *testing.T, s string) string {
	t.Helper()
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestWorkerStartFailureDeletes(t *testing.T) {
	t.Chdir("../..")
	cfg, dir, _ := preparedFiles(t)
	statePath := filepath.Join(t.TempDir(), "state.json")
	var calls []string
	r := workerTestRunner(t, testClock(), func(w http.ResponseWriter, req *http.Request) {
		s, err := readJSON[state](statePath)
		if err != nil || !strings.HasPrefix(req.URL.Path, "/runs/"+s.WorkID) {
			t.Fatal("worker cleanup needs the saved run ID")
		}
		calls = append(calls, req.Method)
		if req.Method == http.MethodDelete {
			w.WriteHeader(403)
			fmt.Fprint(w, `{"error":"forbidden"}`)
			return
		}
		w.WriteHeader(400)
		fmt.Fprintf(w, `{"error":"length_mismatch","message":%q}`, testWorkerBase+" "+testAccessToken)
	})
	err := r.start(t.Context(), cfg, "fixer", workerCandidate, dir, statePath, 0, 0)
	if err == nil || !strings.Contains(err.Error(), "length_mismatch") || !strings.Contains(err.Error(), "forbidden") ||
		strings.Contains(err.Error(), testWorkerBase) || strings.Contains(err.Error(), testAccessToken) ||
		!slices.Equal(calls, []string{"PUT", "DELETE"}) {
		t.Fatal("worker start failure did not join sanitized upload and cleanup errors")
	}
}

func TestWorkerStartValidation(t *testing.T) {
	t.Chdir("../..")
	cfg, dir, _ := preparedFiles(t)
	statePath := filepath.Join(t.TempDir(), "state.json")
	t.Setenv("FACTORY_WORKER_URL", "")
	t.Setenv("FACTORY_WORKER_AUDIENCE", "")
	r := runner{clock: testClock()}
	start := func() error { return r.start(t.Context(), cfg, "probe", workerCandidate, dir, statePath, 0, 0) }
	if err := start(); err == nil || !strings.Contains(err.Error(), "FACTORY_WORKER_URL") {
		t.Fatal("start did not require the worker URL")
	}
	t.Setenv("FACTORY_WORKER_URL", testWorkerBase)
	if err := start(); err == nil || !strings.Contains(err.Error(), "FACTORY_WORKER_AUDIENCE") {
		t.Fatal("start did not require the worker audience")
	}
	for _, audience := range []string{
		"https://" + "api.anthropic.com",
		"https://" + "anthropic.com/token",
		"https://" + "API.Anthropic.COM.:443/token",
		"//" + "custom.anthropic.com/",
	} {
		t.Setenv("FACTORY_WORKER_AUDIENCE", audience)
		if _, err := r.workerClient(); err == nil || !strings.Contains(err.Error(), "FACTORY_WORKER_AUDIENCE must not use an Anthropic host") {
			t.Fatal("worker client did not reject an Anthropic audience")
		}
	}
	t.Setenv("FACTORY_WORKER_AUDIENCE", testWorkerAudience)
	r = workerTestRunner(t, testClock(), func(w http.ResponseWriter, req *http.Request) {
		t.Fatal("worker request sent without a model price")
	})
	policyData, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	unpriced := strings.Replace(string(policyData), "  claude-haiku-5-5:\n", "  claude-unpriced-model:\n", 1)
	if unpriced == string(policyData) {
		t.Fatal("policy fixture has no Haiku pricing entry to rename")
	}
	cfg = filepath.Join(t.TempDir(), "policy.yaml")
	write(t, cfg, unpriced)
	if err := start(); err == nil || !strings.Contains(err.Error(), "pricing for model") {
		t.Fatal("start did not require policy pricing for the role's model")
	}
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("worker start wrote state before validating configuration")
	}
}

func TestWorkerCleanupFromStateAndEnvironment(t *testing.T) {
	s := state{WorkID: sessionState(time.Time{}).WorkID, Candidate: workerCandidate}
	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := writeJSON(statePath, s, delivery.WriteNew); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FACTORY_WORKER_URL", testWorkerBase)
	t.Setenv("FACTORY_WORKER_AUDIENCE", testWorkerAudience)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", testWorkerBase+"/oidc")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", testRuntimeToken)
	t.Setenv("FACTORY_COMMIT", "")
	var calls []string
	claims := fmt.Sprintf(`{"exp":%d}`, time.Now().Add(5*time.Minute).Unix())
	jwt := "header." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".signature"
	original := http.DefaultClient
	t.Cleanup(func() { http.DefaultClient = original })
	http.DefaultClient = &http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		calls = append(calls, req.Method+" "+req.URL.Path)
		switch req.URL.Path {
		case "/oidc":
			if req.Header.Get("Authorization") != "Bearer "+testRuntimeToken || req.URL.Query().Get("audience") != testWorkerAudience {
				t.Fatal("cleanup used the wrong OIDC credentials or audience")
			}
			fmt.Fprintf(w, `{"value":%q}`, jwt)
		case "/runs/" + s.WorkID:
			if req.Header.Get("Authorization") != "Bearer "+jwt {
				t.Fatal("cleanup did not authenticate to the worker with OIDC")
			}
			w.WriteHeader(204)
		default:
			t.Fatal("cleanup tried an unrelated endpoint")
		}
		return w.Result(), nil
	})}
	r := runner{}
	if err := r.run(t.Context(), []string{"cleanup", "-state", statePath}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(calls, []string{"GET /oidc", "DELETE /runs/" + s.WorkID}) {
		t.Fatalf("cleanup requests = %v", calls)
	}
}

func TestWorkerTokenRefresh(t *testing.T) {
	for _, failAll := range []bool{false, true} {
		t.Run(fmt.Sprint("consecutive failures=", failAll), func(t *testing.T) {
			clock := testClock()
			s := sessionState(clock.Now())
			s.Candidate, s.MinutesLimit = workerCandidate, 30
			s.WorkerTokenPushedAt = new(clock.Now())
			clock.now = clock.Now().Add(workerTokenRefresh - 10*time.Second)
			var pushed []time.Duration
			var stops []string
			r := workerTestRunner(t, clock, func(w http.ResponseWriter, req *http.Request) {
				switch req.URL.Path {
				case "/runs/" + s.WorkID + "/token":
					pushed = append(pushed, clock.Now().Sub(*s.WorkerTokenPushedAt))
					if failAll || len(pushed) == 1 {
						w.WriteHeader(503)
					}
				case "/runs/" + s.WorkID + "/stop":
					var stop map[string]string
					decode(t, readRequest(t, req), &stop)
					stops = append(stops, stop["reason"])
				default:
					status := "running"
					if !failAll && clock.Now().Sub(s.StartedAt) >= workerTokenRefresh+20*time.Second {
						status = "lost"
					}
					fmt.Fprintf(w, `{"id":%q,"state":%q}`, s.WorkID, status)
				}
			})
			status, interruptions, err := r.waitWorker(t.Context(), s)
			wantPushes := []time.Duration{workerTokenRefresh, workerTokenRefresh + 10*time.Second}
			if failAll {
				wantPushes = append(wantPushes, workerTokenRefresh+20*time.Second)
				if err == nil || !strings.Contains(err.Error(), "three consecutive worker token refresh failures") ||
					interruptions.Count != 3 || !slices.Equal(stops, []string{"cancelled"}) {
					t.Fatal("worker was not stopped after three consecutive token refresh failures")
				}
			} else if err != nil || interruptions.Count != 1 || status.State != "lost" || len(stops) != 0 {
				t.Fatal("a recovered token refresh failure should allow polling to continue")
			}
			if !slices.Equal(pushed, wantPushes) {
				t.Errorf("token pushes = %v, want %v", pushed, wantPushes)
			}
		})
	}
}

func TestWorkerDeadlineAndCancellation(t *testing.T) {
	for _, scenario := range []string{"stop and finish", "stop times out", "cancel context"} {
		t.Run(scenario, func(t *testing.T) {
			clock := testClock()
			s := sessionState(clock.Now())
			s.Candidate = workerCandidate
			deadline := s.StartedAt.Add(time.Minute + workerAlarmGrace)
			clock.now = deadline.Add(-time.Second)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var stopTime time.Time
			r := workerTestRunner(t, clock, func(w http.ResponseWriter, req *http.Request) {
				if req.Method == http.MethodPut && req.URL.Path == "/runs/"+s.WorkID+"/token" {
					return
				}
				if req.Method == http.MethodPost {
					if !stopTime.IsZero() || req.URL.Path != "/runs/"+s.WorkID+"/stop" {
						t.Fatal("unexpected worker stop")
					}
					stopTime = clock.Now()
					if string(readRequest(t, req)) != `{"reason":"time_limit"}` {
						t.Fatal("incorrect Worker stop reason")
					}
					return
				}
				if req.Method != http.MethodGet {
					t.Fatal("unexpected request while waiting for worker")
				}
				if scenario == "cancel context" {
					cancel()
				}
				status := "running"
				if scenario == "stop and finish" && !stopTime.IsZero() && clock.Now().After(stopTime) {
					status = "finished"
				}
				fmt.Fprintf(w, `{"id":%q,"state":%q}`, s.WorkID, status)
			})
			status, _, err := r.waitWorker(ctx, s)
			if scenario == "cancel context" {
				if !errors.Is(err, context.Canceled) || !stopTime.IsZero() || len(clock.sleeps) != 0 {
					t.Fatal("wait did not return immediately on cancel")
				}
				return
			}
			if !stopTime.Equal(deadline) {
				t.Fatalf("stop was called at %s, expected %s", stopTime, deadline)
			}
			if scenario == "stop and finish" {
				if err != nil || status.State != "finished" {
					t.Fatalf("worker failed to settle after stop: %v", err)
				}
			} else if err == nil || !clock.Now().Equal(deadline.Add(workerStopGrace)) {
				t.Fatalf("worker did not time out at stop grace: %v", err)
			}
		})
	}
}

func TestWorkerMissingOutputs(t *testing.T) {
	for _, tc := range []struct {
		role, reason string
		required     string
	}{
		{"fixer", "completed", patchName},
		{"fixer", "lost", ""},
		{"fixer", "time_limit", ""},
		{"probe", "completed", probeName},
	} {
		t.Run(tc.role+" "+tc.reason, func(t *testing.T) {
			clock := testClock()
			s := sessionState(clock.Now())
			s.Role, s.Candidate = tc.role, workerCandidate
			out := t.TempDir()
			write(t, filepath.Join(out, patchName), "stale patch")
			write(t, filepath.Join(out, workerStderrName), "stale stderr")
			deleted := false
			r := workerTestRunner(t, clock, func(w http.ResponseWriter, req *http.Request) {
				switch req.URL.Path {
				case "/runs/" + s.WorkID:
					if req.Method == http.MethodDelete {
						deleted = true
						w.WriteHeader(204)
						return
					}
					state := "finished"
					if tc.reason == "lost" {
						state = "lost"
					}
					fmt.Fprintf(w, `{"id":%q,"state":%q,"stop_reason":%q,"started_at":%q,"finished_at":%q}`,
						s.WorkID, state, tc.reason, s.StartedAt.Format(time.RFC3339), clock.Now().Format(time.RFC3339))
				case "/runs/" + s.WorkID + "/egress":
					w.Header().Set("x-egress-dropped", "0")
				case "/runs/" + s.WorkID + "/outputs/" + workerStderrName:
					w.WriteHeader(400)
				default:
					w.WriteHeader(404)
					fmt.Fprint(w, `{"error":"not_found"}`)
				}
			})
			err := r.collect(t.Context(), s, out)
			rec, recordErr := readJSON[record.Record](filepath.Join(out, "record.partial.json"))
			if recordErr != nil || !strings.Contains(rec.Notes, "could not save stderr.log: worker: HTTP 400") {
				t.Fatal("collector did not record the optional log download failure")
			}
			if tc.required != "" {
				if err == nil || !strings.Contains(err.Error(), tc.required+" is required") || deleted {
					t.Fatalf("missing required output = %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if !deleted || rec.Interruptions.Count != 1 || rec.StopReason != tc.reason ||
					!strings.Contains(rec.Notes, "patch.diff was not found") {
					t.Fatal("missing patch or interruption was not recorded")
				}
			}
			for _, name := range []string{patchName, workerStderrName} {
				if _, err := os.Stat(filepath.Join(out, name)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("collector kept a stale %s", name)
				}
			}
		})
	}
}

func TestWorkerCollectWaitsForSettlements(t *testing.T) {
	for _, tc := range []struct {
		name      string
		wait      time.Duration
		polls     int
		remaining int
	}{
		{"settled", 20 * time.Second, 3, 0},
		{"timed out", 60 * time.Second, 6, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := testClock()
			s := sessionState(clock.Now())
			s.Candidate = workerCandidate
			finished := s.StartedAt.Add(time.Minute)
			clock.now = finished
			polls := 0
			r := workerTestRunner(t, clock, func(w http.ResponseWriter, req *http.Request) {
				switch req.URL.Path {
				case "/runs/" + s.WorkID:
					if req.Method == http.MethodDelete {
						w.WriteHeader(204)
						return
					}
					polls++
					inflight := 2
					if polls >= tc.polls {
						inflight = tc.remaining
					}
					fmt.Fprintf(w, `{"id":%q,"state":"finished","stop_reason":"time_limit","started_at":%q,"finished_at":%q,
						"usage":{"inflight":%d,"late_settlements":%d,"cost_microcents":%d,"output_tokens":%d}}`,
						s.WorkID, s.StartedAt.Format(time.RFC3339), finished.Format(time.RFC3339),
						inflight, polls, polls*1_000_000, polls)
				case "/runs/" + s.WorkID + "/egress":
					w.Header().Set("X-Egress-Dropped", "0")
				default:
					w.WriteHeader(404)
				}
			})
			out := t.TempDir()
			if err := r.collect(t.Context(), s, out); err != nil {
				t.Fatal(err)
			}
			rec, err := readJSON[record.Record](filepath.Join(out, "record.partial.json"))
			if err != nil {
				t.Fatal(err)
			}
			if polls != tc.polls || clock.Now().Sub(finished) != tc.wait ||
				rec.Usage.OutputTokens != int64(polls) || rec.Usage.ReportedCost.Amount != fmt.Sprint(polls) ||
				!strings.Contains(rec.Notes, fmt.Sprintf("late_settlements=%d", polls)) {
				t.Fatal("collector did not use the latest status within the settlement wait")
			}
			if tc.remaining == 0 {
				if strings.Contains(rec.Notes, "inflight=") || rec.Interruptions.Count != 1 {
					t.Fatal("collector recorded an interruption for settled requests")
				}
			} else if !strings.Contains(rec.Notes, fmt.Sprintf("inflight=%d", tc.remaining)) ||
				rec.Interruptions.Count != 2 || !slices.Contains(rec.Interruptions.Notes, "Worker usage was still settling after 60 seconds.") {
				t.Fatal("collector did not record the outstanding requests and interruption")
			}
			for _, delay := range clock.sleeps {
				if delay != r.pollInterval {
					t.Fatal("collector changed the polling interval while waiting for settlements")
				}
			}
		})
	}
}

func TestWorkerCollectKeepsTruncatedOutputs(t *testing.T) {
	clock := testClock()
	s := sessionState(clock.Now())
	s.Role, s.Candidate = "probe", workerCandidate
	const event = "{\"type\":\"tool_use\",\"name\":\"WebFetch\"}\n"
	log := event + strings.Repeat("x", workerLogLimit+1-len(event))
	base := "/runs/" + s.WorkID
	r := workerTestRunner(t, clock, func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case base:
			if req.Method == http.MethodDelete {
				w.WriteHeader(204)
				return
			}
			fmt.Fprintf(w, `{"id":%q,"state":"finished","stop_reason":"completed","started_at":%q,"finished_at":%q}`,
				s.WorkID, s.StartedAt.Format(time.RFC3339), clock.Now().Format(time.RFC3339))
		case base + "/egress":
			w.Header().Set("X-Egress-Dropped", "0")
		case base + "/outputs/" + probeName:
			w.Header().Set("X-Factory-Truncated", "1")
			fmt.Fprint(w, "probe prefix")
		case base + "/outputs/" + workerStderrName:
			w.Header().Set("Content-Length", fmt.Sprint(len(log)))
			io.WriteString(w, log)
		case base + "/outputs/" + workerEventsName:
			io.WriteString(w, log)
		default:
			w.WriteHeader(404)
		}
	})
	out := t.TempDir()
	if err := r.collect(t.Context(), s, out); err != nil {
		t.Fatal(err)
	}
	rec, err := readJSON[record.Record](filepath.Join(out, "record.partial.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{probeName, workerEventsName, workerStderrName} {
		if !strings.Contains(rec.Notes, name+" was truncated.") {
			t.Errorf("record omitted the truncation of %s", name)
		}
	}
	for _, name := range []string{workerEventsName, workerStderrName} {
		info, err := os.Stat(filepath.Join(out, name))
		if err != nil || info.Size() != workerLogLimit {
			t.Errorf("collector did not keep %s at the byte limit", name)
		}
	}
	if read(t, filepath.Join(out, probeName)) != "probe prefix" || rec.Usage.WebFetchRequests != 1 {
		t.Fatal("collector did not retain the probe or count complete events in the truncated log")
	}
}
