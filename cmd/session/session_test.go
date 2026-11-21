package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/toshi0607/agent-factory/internal/claude"
	"github.com/toshi0607/agent-factory/internal/claudeauth"
	"github.com/toshi0607/agent-factory/internal/delivery"
	"github.com/toshi0607/agent-factory/poc/record"
)

type fakeClock struct {
	now    time.Time
	sleeps []time.Duration
}

func (f *fakeClock) Now() time.Time { return f.now }
func (f *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.sleeps = append(f.sleeps, d)
	f.now = f.now.Add(d)
	return nil
}

func testClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 11, 19, 7, 16, 49, 0, time.UTC)}
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func clientFor(handler func(*http.Request) (int, string)) *http.Client {
	return &http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
		if req.Body != nil {
			defer req.Body.Close()
		}
		status, body := handler(req)
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
}

func testRunner(handler func(*http.Request) (int, string), clock *fakeClock) runner {
	return runner{
		api:   claude.New("https://api.example.invalid", clientFor(handler), claudeauth.Static{Header: "X-Test-Auth", Value: "fake-placeholder"}),
		clock: clock, pollInterval: 10 * time.Second, stdout: io.Discard,
	}
}

const factoryCommit = "abcdef0123456789abcdef0123456789abcdef01"

func TestAuthCheck(t *testing.T) {
	var requests []string
	client := clientFor(func(req *http.Request) (int, string) {
		requests = append(requests, req.Method+" "+req.URL.Host+req.URL.RequestURI())
		switch req.URL.Path {
		case "/oidc":
			payload := base64.RawURLEncoding.EncodeToString([]byte(`{"job_workflow_sha":"` + factoryCommit + `"}`))
			return 200, fmt.Sprintf(`{"value":%q}`, "fake-header."+payload+".fake-signature")
		case "/v1/oauth/token":
			return 200, `{"access_token":"fake-access-placeholder","token_type":"Bearer","expires_in":30,"scope":"agents:read"}`
		case "/v1/agents":
			if req.Header.Get("Authorization") != "Bearer fake-access-placeholder" {
				t.Fatal("auth-check sent the wrong authorization header")
			}
			return 200, `{"data":[]}`
		default:
			t.Fatalf("unexpected path %s", req.URL.Path)
			return 500, ""
		}
	})
	const base = "https://api.example.invalid"
	auth := claudeauth.NewFederation(base, client, claudeauth.Config{
		OIDCURL: "https://github.example.invalid/oidc", OIDCRequestToken: "fake-oidc-placeholder",
		FederationRuleID: "rule", OrganizationID: "org", ExpectedWorkflowSHA: factoryCommit,
	})
	var stdout bytes.Buffer
	r := runner{api: claude.New(base, client, auth), auth: auth, stdout: &stdout}
	if err := r.run(t.Context(), []string{"auth-check"}); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"GET github.example.invalid/oidc?audience=https%3A%2F%2Fapi.anthropic.com",
		"POST api.example.invalid/v1/oauth/token",
		"GET api.example.invalid/v1/agents?limit=1",
	}
	if !slices.Equal(requests, want) {
		t.Fatalf("auth-check requests = %v, want %v", requests, want)
	}
	if got := stdout.String(); got != "{\"expires_in\":30,\"scope\":\"agents:read\",\"http_status\":200}\n" {
		t.Fatal("auth-check output does not contain the expected metadata")
	}
}

func TestOIDCClaims(t *testing.T) {
	const fakeRequestToken = "fake-request-placeholder"
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{
		"iss":"https://issuer.example.invalid","sub":"repo:owner/repo:ref:refs/heads/main",
		"aud":["custom audience"],"repository":"owner/repo","repository_owner":"owner","repository_visibility":"private",
		"ref":"refs/heads/main","sha":"fake-commit","event_name":"workflow_dispatch","workflow":"P0",
		"workflow_ref":"caller.yml@refs/heads/main","job_workflow_ref":"factory.yml@fake-sha",
		"job_workflow_sha":"fake-factory-sha","runner_environment":"github-hosted",
		"jti":"fake-private-claim","value":"fake-other-claim","exp":123
	}`))
	token := "fake-header." + payload + ".fake-signature"
	client := clientFor(func(req *http.Request) (int, string) {
		if req.Method != "GET" || req.URL.Host != "github.example.invalid" || req.URL.Path != "/oidc" ||
			req.URL.Query().Get("audience") != "custom audience" ||
			req.Header.Get("Authorization") != "Bearer "+fakeRequestToken {
			t.Fatal("unexpected OIDC claims request")
		}
		return 200, fmt.Sprintf(`{"value":%q}`, token)
	})
	auth := claudeauth.NewFederation("https://api.example.invalid", client, claudeauth.Config{
		OIDCURL: "https://github.example.invalid/oidc", OIDCRequestToken: fakeRequestToken, Audience: "custom audience",
	})
	var stdout bytes.Buffer
	r := runner{auth: auth, stdout: &stdout}
	if err := r.run(t.Context(), []string{"oidc-claims"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String(), token) || strings.Contains(stdout.String(), fakeRequestToken) {
		t.Fatal("oidc-claims printed a credential")
	}
	var got, want map[string]any
	decode(t, stdout.Bytes(), &got)
	decode(t, []byte(`{
		"iss":"https://issuer.example.invalid","sub":"repo:owner/repo:ref:refs/heads/main",
		"aud":["custom audience"],"repository":"owner/repo","repository_owner":"owner","repository_visibility":"private",
		"ref":"refs/heads/main","sha":"fake-commit","event_name":"workflow_dispatch","workflow":"P0",
		"workflow_ref":"caller.yml@refs/heads/main","job_workflow_ref":"factory.yml@fake-sha",
		"job_workflow_sha":"fake-factory-sha","runner_environment":"github-hosted"
	}`), &want)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("oidc-claims did not return exactly the allowlisted claims")
	}
}

func TestStart(t *testing.T) {
	t.Setenv("FACTORY_COMMIT", factoryCommit)
	t.Chdir("../..")
	cfg, dir, m := preparedFiles(t)
	for _, tt := range []struct {
		name, failAt string
		role, model  string
		overrides    []string
		cents, mins  int
	}{
		{"policy defaults", "", "fixer", "claude-opus-5-5", nil, 300, 30},
		{"probe with overrides", "", "probe", "claude-haiku-5-5", []string{"-budget-cents", "25", "-minutes", "3"}, 25, 3},
		{"unconfirmed agent tools", "agent", "fixer", "claude-opus-5-5", nil, 300, 30},
		{"upload failure", "upload", "fixer", "claude-opus-5-5", nil, 300, 30},
		{"message failure", "message", "fixer", "claude-opus-5-5", nil, 300, 30},
	} {
		t.Run(tt.name, func(t *testing.T) {
			statePath := filepath.Join(t.TempDir(), "state.json")
			clock := testClock()
			var uploaded, cleanup []string
			var envHash, agentHash, workID string
			r := testRunner(func(req *http.Request) (int, string) {
				switch req.Method + " " + req.URL.RequestURI() {
				case "POST /v1/environments":
					data := readRequest(t, req)
					envHash = fmt.Sprintf("%x", sha256.Sum256(data))
					var body struct {
						Name   string
						Config struct {
							Networking struct {
								AllowedHosts []string `json:"allowed_hosts"`
							}
						}
					}
					decode(t, data, &body)
					workID = body.Name
					s, err := readJSON[state](statePath)
					if err != nil || s.WorkID != workID || s.EnvironmentID != "" {
						t.Fatalf("initial state = %+v, error = %v", s, err)
					}
					if !slices.Equal(body.Config.Networking.AllowedHosts, []string{"proxy.golang.org", "sum.golang.org"}) {
						t.Fatal("wrong allowed hosts")
					}
					return 200, `{"id":"env-1"}`
				case "POST /v1/agents":
					s, err := readJSON[state](statePath)
					if err != nil || s.EnvironmentID != "env-1" {
						t.Fatalf("state before agent creation = %+v, error = %v", s, err)
					}
					data := readRequest(t, req)
					agentHash = fmt.Sprintf("%x", sha256.Sum256(data))
					var body struct{ Name, Model, System string }
					decode(t, data, &body)
					if body.Name != workID || body.Model != tt.model || body.System != read(t, "prompts/"+tt.role+".md") {
						t.Fatal("agent does not match policy")
					}
					if tt.failAt == "agent" {
						return 200, `{"id":"agent-1"}`
					}
					return 200, `{"id":"agent-1","tools":[{"type":"agent_toolset_20260401","default_config":{"enabled":false}}]}`
				case "POST /v1/files":
					s, err := readJSON[state](statePath)
					if err != nil || s.AgentID != "agent-1" || len(s.UploadedFileIDs) != len(uploaded) {
						t.Fatalf("state before upload = %+v, error = %v", s, err)
					}
					p, err := req.MultipartReader()
					if err != nil {
						t.Fatal(err)
					}
					f, err := p.NextPart()
					if err != nil {
						t.Fatal(err)
					}
					defer f.Close()
					name := f.FileName()
					data, err := io.ReadAll(f)
					if err != nil || f.FormName() != "file" || string(data) != read(t, filepath.Join(dir, name)) {
						t.Fatal("upload content or form field mismatch")
					}
					if tt.failAt == "upload" && name == "finish.sh" {
						return 503, "temporarily unavailable"
					}
					uploaded = append(uploaded, name)
					return 200, fmt.Sprintf(`{"id":"file-%d"}`, len(uploaded))
				case "POST /v1/sessions":
					var body struct {
						Agent       string
						Environment string `json:"environment_id"`
						Budget      struct {
							MaxListCost claude.Money `json:"max_list_cost"`
						}
						Resources []claude.Resource
					}
					decode(t, readRequest(t, req), &body)
					if body.Agent != "agent-1" || body.Environment != "env-1" || body.Budget.MaxListCost.Amount != fmt.Sprint(tt.cents) ||
						len(body.Resources) != len(m.Files)+1 {
						t.Fatalf("unexpected session request: %+v", body)
					}
					for i, res := range body.Resources {
						name := delivery.ManifestName
						if i < len(m.Files) {
							name = m.Files[i].Name
						}
						if name != uploaded[i] || res.MountPath != "/workspace/"+name || res.FileID != fmt.Sprintf("file-%d", i+1) {
							t.Fatalf("unexpected resource: %+v", res)
						}
						body.Resources[i].MountPath = "/mnt/session/uploads" + res.MountPath
					}
					slices.Reverse(body.Resources)
					resources, err := json.Marshal(body.Resources)
					if err != nil {
						t.Fatal(err)
					}
					return 200, fmt.Sprintf(`{"id":"session-1","resources":%s}`, resources)
				case "POST /v1/sessions/session-1/events?beta=true":
					s, err := readJSON[state](statePath)
					if err != nil || s.SessionID != "session-1" || len(s.UploadedFileIDs) != len(uploaded) {
						t.Fatalf("state before sending user message = %+v, error = %v", s, err)
					}
					const prefix = "/mnt/session/uploads/workspace/"
					var body struct {
						Events []struct {
							Content []struct{ Text string }
						}
					}
					decode(t, readRequest(t, req), &body)
					want := "Set up with: bash " + prefix + "setup.sh\nThe task is in: " + prefix +
						"task.md\nWhen you are done, run: bash " + prefix + "finish.sh\nThen reply DONE."
					if len(body.Events) != 1 || len(body.Events[0].Content) != 1 || body.Events[0].Content[0].Text != want {
						t.Fatal("user message does not use the real paths")
					}
					if tt.failAt == "message" {
						return 500, "message was rejected"
					}
					return 200, "{}"
				case "GET /v1/sessions/session-1":
					return 200, `{"status":"idle"}`
				default:
					cleanup = append(cleanup, req.Method+" "+req.URL.Path)
					return 200, "{}"
				}
			}, clock)

			args := []string{"start", "-policy", cfg, "-role", tt.role,
				"-candidate", "managed-agents", "-files", dir, "-state", statePath}
			err := r.run(t.Context(), append(args, tt.overrides...))
			if tt.failAt != "" {
				if err == nil {
					t.Fatal("start did not return the API failure")
				}
				if tt.failAt == "agent" && !strings.Contains(err.Error(), "agent response does not confirm that web tools are disabled") {
					t.Fatal(err)
				}
				s, err := readJSON[state](statePath)
				if err != nil || s.EnvironmentID != "env-1" || s.AgentID != "agent-1" {
					t.Fatalf("state after failure = %+v, error = %v", s, err)
				}
				want := []string{"POST /v1/agents/agent-1/archive", "DELETE /v1/environments/env-1"}
				if tt.failAt == "message" {
					if s.SessionID != "session-1" {
						t.Fatalf("state session ID = %q, want session-1", s.SessionID)
					}
					want = append([]string{"DELETE /v1/sessions/session-1"}, want...)
				}
				var wantFiles []string
				for i := range uploaded {
					id := fmt.Sprintf("file-%d", i+1)
					wantFiles = append(wantFiles, id)
					want = append(want, "DELETE /v1/files/"+id)
				}
				if !slices.Equal(s.UploadedFileIDs, wantFiles) {
					t.Fatalf("state file IDs = %v, want %v", s.UploadedFileIDs, wantFiles)
				}
				if (tt.failAt == "agent") != (len(uploaded) == 0) || !slices.Equal(cleanup, want) {
					t.Fatalf("cleanup = %v, want %v", cleanup, want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			s, err := readJSON[state](statePath)
			if err != nil {
				t.Fatal(err)
			}
			if !regexp.MustCompile(`^p0-20261119T071649Z-[0-9a-f]{8}$`).MatchString(s.WorkID) || s.WorkID != workID ||
				s.Candidate != "managed-agents" || s.Task != m.Task || s.BaseCommit != m.BaseCommit || s.FactoryCommit != factoryCommit ||
				s.AgentID != "agent-1" || s.EnvironmentID != "env-1" || s.SessionID != "session-1" ||
				s.BudgetCents != tt.cents || s.MinutesLimit != tt.mins || s.Role != tt.role || s.Model != tt.model ||
				s.EnvironmentRequestSHA256 != envHash || s.AgentRequestSHA256 != agentHash || !s.StartedAt.Equal(clock.Now()) ||
				len(s.UploadedFileIDs) != len(m.Files)+1 || len(cleanup) != 0 {
				t.Fatalf("unexpected state or cleanup: %+v, %v", s, cleanup)
			}
			if strings.Contains(read(t, statePath), "fake-placeholder") {
				t.Fatal("state contains a credential")
			}
		})
	}

	t.Run("existing state", func(t *testing.T) {
		statePath := filepath.Join(t.TempDir(), "state.json")
		const original = "{}\n"
		if err := os.WriteFile(statePath, []byte(original), 0o600); err != nil {
			t.Fatal(err)
		}
		r := testRunner(func(req *http.Request) (int, string) {
			t.Fatal("start called the API with a pre-existing state file")
			return 0, ""
		}, testClock())
		args := []string{"start", "-policy", cfg, "-files", dir, "-state", statePath}
		if err := r.run(t.Context(), args); err == nil || !strings.Contains(err.Error(), "state file already exists") {
			t.Fatalf("start error = %v, want a pre-existing state file error", err)
		}
		if got := read(t, statePath); got != original {
			t.Fatalf("state file = %q, want %q", got, original)
		}
	})
}

func TestStartRejectsNonPositiveOverrides(t *testing.T) {
	for _, flag := range []string{"-budget-cents", "-minutes"} {
		for _, value := range []string{"0", "-1"} {
			args := []string{"start", "-policy", "unused", "-files", "unused", "-state", "unused", flag, value}
			if err := (runner{}).run(t.Context(), args); err == nil || !strings.Contains(err.Error(), flag+" must be positive") {
				t.Errorf("%s %s: expected a validation error, got %v", flag, value, err)
			}
		}
	}
}

func TestStartTimeAndBudgetLimits(t *testing.T) {
	t.Chdir("../..")
	cfg, dir, _ := preparedFiles(t)
	longPolicy := filepath.Join(t.TempDir(), "long-policy.yaml")
	write(t, longPolicy, strings.Replace(read(t, cfg), "minutes: 30", "minutes: 46", 1))
	for _, tt := range []struct {
		name, policy string
		override     []string
		want         string
	}{
		{"policy time exceeds 45", longPolicy, nil, "time limit 46 exceeds the maximum of 45 minutes"},
		{"override time exceeds 45", cfg, []string{"-minutes", "46"}, "time limit 46 exceeds the maximum of 45 minutes"},
		{"override time exceeds policy", cfg, []string{"-minutes", "31"}, "-minutes must be positive and no greater than the role's policy limit of 30"},
		{"override budget exceeds policy", cfg, []string{"-budget-cents", "301"}, "-budget-cents must be positive and no greater than the role's policy limit of 300"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"start", "-policy", tt.policy, "-files", dir, "-state", filepath.Join(t.TempDir(), "state.json")}
			err := (runner{}).run(t.Context(), append(args, tt.override...))
			if err == nil || err.Error() != tt.want {
				t.Fatalf("start = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestCollect(t *testing.T) {
	const done = `{"status":"idle","stats":{"active_seconds":8.5,"duration_seconds":9.1},"usage":{"active_seconds":8.7,"input_tokens":10,"output_tokens":20,"cache_read_input_tokens":30,"cache_creation":{"ephemeral_5m_input_tokens":40,"ephemeral_1h_input_tokens":50},"list_cost":{"amount":"12","currency":"USD"}}}`
	const running = `{"status":"running"}`
	const initialIdle = `{"status":"idle","usage":{"active_seconds":0}}`
	const terminated = `{"status":"terminated"}`
	const events = `{"data":[{"type":"agent.message","content":[{"text":"DONE","type":"text"}]}]}`
	const patch = "test patch\n"
	const paths = "added.go\nedit.go\n"
	const probe = "== done\n"
	for _, tc := range []struct {
		name         string
		sessions     []string
		stopReason   string
		missingPatch bool
		wantSeconds  float64
	}{
		{"completed", []string{initialIdle, running, done, done}, stopCompleted, false, 20},
		{"time limit", []string{running, running, running, done, done}, stopTimeLimit, false, 20},
		{"missing patch", []string{terminated, terminated}, stopCompleted, true, 10},
		{"never started", []string{initialIdle, initialIdle, initialIdle}, stopNeverStarted, false, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := t.TempDir()
			statePath := filepath.Join(t.TempDir(), "state.json")
			clock := testClock()
			s := sessionState(clock.Now())
			switch tc.stopReason {
			case stopTimeLimit:
				s.StartedAt = s.StartedAt.Add(-50 * time.Second)
			case stopNeverStarted:
				s.StartedAt = s.StartedAt.Add(-120 * time.Second)
				s.MinutesLimit = 30
			}
			if err := writeJSON(statePath, s, delivery.WriteNew); err != nil {
				t.Fatal(err)
			}
			if tc.missingPatch {
				write(t, filepath.Join(out, "patch.diff"), "stale patch from old run")
				write(t, filepath.Join(out, "changed-paths.txt"), "stale path from old run")
				write(t, filepath.Join(out, "probe.txt"), "stale probe from old run")
			}
			var gets, interrupts, lists int
			var cleanup []string
			startCollect := clock.Now()
			r := testRunner(func(req *http.Request) (int, string) {
				switch req.Method + " " + req.URL.RequestURI() {
				case "GET /v1/sessions/session-1":
					if gets >= len(tc.sessions) {
						t.Fatal("unexpected session poll")
					}
					status := tc.sessions[gets]
					gets++
					return 200, status
				case "POST /v1/sessions/session-1/events?beta=true":
					interrupts++
					if interrupts != 1 || clock.Now().Sub(startCollect) != 10*time.Second ||
						string(readRequest(t, req)) != `{"events":[{"type":"user.interrupt"}]}` {
						t.Fatal("wrong interruption time or body")
					}
					return 200, "{}"
				case "GET /v1/sessions/session-1/events?beta=true":
					if !tc.missingPatch && (read(t, filepath.Join(out, patchName)) != patch ||
						read(t, filepath.Join(out, pathsName)) != paths || read(t, filepath.Join(out, probeName)) != probe) {
						t.Fatal("listed events before saving outputs")
					}
					return 200, events
				case "GET /v1/files?scope_id=session-1":
					lists++
					if tc.missingPatch {
						return 200, `{"data":[{"id":"scoped-input","filename":"setup.sh","downloadable":false}]}`
					}
					return 200, `{"data":[{"id":"patch","filename":"outputs/patch.diff"},{"id":"paths","filename":"outputs/changed-paths.txt"},{"id":"probe","filename":"outputs/probe.txt"}]}`
				case "GET /v1/files/patch/content":
					return 200, patch
				case "GET /v1/files/paths/content":
					return 200, paths
				case "GET /v1/files/probe/content":
					return 200, probe
				default:
					if _, err := os.Stat(filepath.Join(out, "record.partial.json")); err != nil {
						t.Fatalf("cleanup before record was saved: %v", err)
					}
					cleanup = append(cleanup, req.Method+" "+req.URL.Path)
					return 200, "{}"
				}
			}, clock)
			if err := r.run(t.Context(), []string{"collect", "-state", statePath, "-out", out}); err != nil {
				t.Fatal(err)
			}
			wantCleanup := []string{"DELETE /v1/sessions/session-1", "POST /v1/agents/agent-1/archive",
				"DELETE /v1/environments/env-1", "DELETE /v1/files/upload-1", "DELETE /v1/files/upload-2"}
			if gets != len(tc.sessions) || !slices.Equal(cleanup, wantCleanup) {
				t.Fatalf("session requests = %d of %d, cleanup = %v", gets, len(tc.sessions), cleanup)
			}
			if read(t, filepath.Join(out, "events.json")) != events {
				t.Fatal("events were not saved as raw JSON")
			}
			rec, err := readJSON[record.Record](filepath.Join(out, "record.partial.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := rec.Validate(); err != nil {
				t.Fatal(err)
			}
			if rec.Candidate != s.Candidate || rec.WorkID != s.WorkID || rec.BaseCommit != s.BaseCommit ||
				rec.Model != s.Model || rec.Session.ID != s.SessionID ||
				rec.Role != s.Role || rec.FactoryCommit != s.FactoryCommit || rec.StopReason != tc.stopReason ||
				rec.EnvironmentRequestSHA256 != s.EnvironmentRequestSHA256 || rec.AgentRequestSHA256 != s.AgentRequestSHA256 ||
				rec.BudgetCents != s.BudgetCents || rec.MinutesLimit != s.MinutesLimit || !rec.StartedAt.Equal(s.StartedAt) ||
				!rec.FinishedAt.Equal(clock.Now()) || rec.RunnerSeconds.Collect != tc.wantSeconds ||
				rec.Egress.LogAvailable || !strings.Contains(rec.Egress.Notes, "no network log") {
				t.Fatalf("wrong partial record metadata: %+v", rec)
			}
			if interrupts != rec.Interruptions.Count || (tc.stopReason == stopTimeLimit && (interrupts != 1 || len(rec.Interruptions.Notes) != 1)) ||
				(tc.stopReason != stopTimeLimit && interrupts != 0) {
				t.Fatalf("wrong interruption count or notes: %d, %+v", interrupts, rec.Interruptions)
			}
			if tc.stopReason == stopNeverStarted && !strings.Contains(rec.Notes, "no activity for more than 120 seconds") {
				t.Fatalf("missing startup note: %q", rec.Notes)
			}
			if tc.missingPatch {
				if rec.Patch.SHA256 != "" || rec.Patch.Bytes != 0 || !strings.Contains(rec.Notes, "was not found") || lists != 2 {
					t.Fatalf("missing patch not recorded: %+v, %q", rec.Patch, rec.Notes)
				}
				for _, name := range []string{"patch.diff", "changed-paths.txt", "probe.txt"} {
					if _, err := os.Stat(filepath.Join(out, name)); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("stale output %s: %v", name, err)
					}
				}
				return
			}
			if rec.Patch.SHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(patch))) || rec.Patch.Bytes != int64(len(patch)) ||
				!slices.Equal(rec.Patch.Paths, []string{"added.go", "edit.go"}) ||
				read(t, filepath.Join(out, "patch.diff")) != patch || read(t, filepath.Join(out, "changed-paths.txt")) != paths ||
				read(t, filepath.Join(out, "probe.txt")) != probe {
				t.Fatalf("wrong patch metadata or files: %+v", rec.Patch)
			}
			if tc.sessions[len(tc.sessions)-1] == done {
				wantUsage := record.Usage{
					InputTokens: 10, OutputTokens: 20, CacheReadInputTokens: 30,
					CacheCreation5mInputTokens: 40, CacheCreation1hInputTokens: 50,
					ReportedCost: record.ReportedCost{Amount: "12", Currency: "USD"},
				}
				wantSession := record.Session{ID: s.SessionID, Status: "idle", ActiveSeconds: 8.5, DurationSeconds: 9.1}
				if rec.Usage != wantUsage || rec.Session != wantSession {
					t.Fatalf("wrong usage or session: %+v, %+v", rec.Usage, rec.Session)
				}
			}
		})
	}
}

func TestCleanupContinuesAfterFailure(t *testing.T) {
	for _, fileStatus := range []int{404, 403} {
		t.Run(fmt.Sprint(fileStatus), func(t *testing.T) {
			var calls []string
			r := testRunner(func(req *http.Request) (int, string) {
				target := req.Method + " " + req.URL.RequestURI()
				calls = append(calls, target)
				switch target {
				case "GET /v1/sessions/session-1":
					if len(calls) == 1 {
						return 200, `{"status":"running"}`
					}
					return 200, `{"status":"idle"}`
				case "DELETE /v1/environments/env-1":
					return 405, ""
				case "DELETE /v1/files/upload-1":
					return fileStatus, ""
				default:
					return 200, "{}"
				}
			}, testClock())
			s := sessionState(r.clock.Now())
			path := filepath.Join(t.TempDir(), "state.json")
			if err := writeJSON(path, s, delivery.WriteNew); err != nil {
				t.Fatal(err)
			}
			err := r.run(t.Context(), []string{"cleanup", "-state", path})
			if fileStatus == 403 {
				if err == nil || !strings.Contains(err.Error(), "could not remove file upload-1") {
					t.Fatalf("expected leftover file to be reported, got %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			want := []string{"GET /v1/sessions/session-1", "POST /v1/sessions/session-1/events?beta=true",
				"GET /v1/sessions/session-1", "DELETE /v1/sessions/session-1", "POST /v1/agents/agent-1/archive",
				"DELETE /v1/environments/env-1", "POST /v1/environments/env-1/archive",
				"DELETE /v1/files/upload-1", "DELETE /v1/files/upload-2"}
			if !slices.Equal(calls, want) {
				t.Fatalf("cleanup calls = %v, want %v", calls, want)
			}
		})
	}
}

func TestMerge(t *testing.T) {
	dir := t.TempDir()
	partial, check, out := filepath.Join(dir, "partial.json"), filepath.Join(dir, "check.json"), filepath.Join(dir, "record.json")
	rec := record.Record{
		SchemaVersion: 1, Candidate: "managed-agents", Task: "test", WorkID: "work", BaseCommit: "base",
		Model: "model", StartedAt: testClock().Now(), FinishedAt: testClock().Now().Add(time.Minute),
		RunnerSeconds: record.RunnerSeconds{Collect: 60}, Patch: record.Patch{SHA256: "test-digest"},
	}
	cr := record.CheckResult{Task: "test", PatchSHA256: "test-digest", ApplyOK: true, CheckPassed: false,
		Failures: []record.Failure{{Name: "fixture", Message: "failed"}}}
	if err := writeJSON(partial, rec, delivery.WriteNew); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(check, cr, delivery.WriteNew); err != nil {
		t.Fatal(err)
	}
	if err := (runner{}).run(t.Context(), []string{"merge", "-record", partial, "-check", check,
		"-runner-start", "1.5", "-runner-check", "10", "-out", out}); err != nil {
		t.Fatal(err)
	}
	final, err := readJSON[record.Record](out)
	if err != nil {
		t.Fatal(err)
	}
	rec.Check, rec.RunnerSeconds.Start, rec.RunnerSeconds.Check = cr, 1.5, 10
	if !reflect.DeepEqual(final, rec) {
		t.Fatalf("merged record = %+v, want %+v", final, rec)
	}
	if err := merge(partial, check, "NaN", "0", out); err == nil {
		t.Fatal("merge accepted invalid timing")
	}
	cr.Task = "other"
	if err := writeJSON(check, cr, delivery.WriteAtomic); err != nil {
		t.Fatal(err)
	}
	if err := merge(partial, check, "0", "0", out); err == nil {
		t.Fatal("merge accepted mismatched task")
	}
}

func sessionState(now time.Time) state {
	return state{
		WorkID: "p0-20261119T071649Z-abcdef01", Candidate: "managed-agents", Task: "test",
		BaseCommit: "base", FactoryCommit: factoryCommit, Model: "claude-opus-5-5", Role: "fixer", SessionID: "session-1",
		EnvironmentRequestSHA256: "test-environment-digest", AgentRequestSHA256: "test-agent-digest",
		AgentID: "agent-1", EnvironmentID: "env-1", BudgetCents: 300, MinutesLimit: 1,
		StartedAt: now, UploadedFileIDs: []string{"upload-1", "upload-2"},
	}
}

func preparedFiles(t *testing.T) (string, string, delivery.Manifest) {
	t.Helper()
	dir := t.TempDir()
	const archive = "go1.26.11.linux-amd64.tar.gz"
	m := delivery.Manifest{Task: "test-task", BaseCommit: "test-base"}
	for _, name := range []string{"setup.sh", "finish.sh", "probe.sh", "task.md", "product.tar.gz", archive, "modproxy.tar.gz"} {
		path := filepath.Join(dir, name)
		write(t, path, "placeholder for "+name)
		entry, err := delivery.Inspect(path)
		if err != nil {
			t.Fatal(err)
		}
		m.Files = append(m.Files, entry)
	}
	if err := delivery.WriteNew(filepath.Join(dir, delivery.ManifestName), m.Write); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "test-policy.yaml")
	body := read(t, "policy/google-cloud-emulator.yaml")
	body = strings.Replace(body, "9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec", m.Files[5].SHA256, 1)
	body = strings.Replace(body, "66999944", fmt.Sprint(m.Files[5].Bytes), 1)
	write(t, cfg, body)
	return cfg, dir, m
}

func decode(t *testing.T, data []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
}

func readRequest(t *testing.T, req *http.Request) []byte {
	t.Helper()
	data, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func read(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCollectKeepsResourcesOnFailure(t *testing.T) {
	for _, failure := range []string{"create output directory", "download patch", "read final session", "write record"} {
		t.Run(failure, func(t *testing.T) {
			clock := testClock()
			s := sessionState(clock.Now())
			out := t.TempDir()
			switch failure {
			case "create output directory":
				out = filepath.Join(out, "file")
				write(t, out, "")
			case "write record":
				if err := os.Mkdir(filepath.Join(out, "record.partial.json"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			interrupts, gets := 0, 0
			r := testRunner(func(req *http.Request) (int, string) {
				switch req.Method + " " + req.URL.RequestURI() {
				case "GET /v1/sessions/session-1":
					gets++
					switch {
					case failure == "create output directory" && interrupts == 0:
						return 200, `{"status":"running"}`
					case failure == "read final session" && gets > 1:
						return 403, "final session unavailable"
					default:
						return 200, `{"status":"idle","usage":{"active_seconds":1}}`
					}
				case "POST /v1/sessions/session-1/events?beta=true":
					interrupts++
					if string(readRequest(t, req)) != `{"events":[{"type":"user.interrupt"}]}` {
						t.Fatal("wrong interrupt body")
					}
					if interrupts == 1 {
						return 503, "interrupt unavailable"
					}
					return 200, "{}"
				case "GET /v1/files?scope_id=session-1":
					return 200, `{"data":[{"id":"patch","filename":"patch.diff"},{"id":"paths","filename":"changed-paths.txt"}]}`
				case "GET /v1/files/patch/content":
					if failure == "download patch" {
						return 403, "patch unavailable"
					}
					return 200, "test patch"
				case "GET /v1/files/paths/content":
					return 200, "edit.go\n"
				case "GET /v1/sessions/session-1/events?beta=true":
					return 200, `{"data":[]}`
				default:
					t.Fatalf("unexpected request on failure: %s %s", req.Method, req.URL.Path)
					return 500, ""
				}
			}, clock)
			err := r.collect(t.Context(), s, out)
			if err == nil || !strings.Contains(err.Error(), `resources were kept (session settled)`) ||
				!strings.Contains(err.Error(), `resources were kept; run the "factory-p0-recover" workflow with this run's id to collect again or clean up`) ||
				strings.Contains(err.Error(), out) {
				t.Fatalf("collect = %v", err)
			}
			if failure == "create output directory" {
				if interrupts != 2 || !slices.Equal(clock.sleeps, []time.Duration{2 * time.Second}) {
					t.Fatalf("interrupts = %d, sleeps = %v", interrupts, clock.sleeps)
				}
			} else if interrupts != 0 {
				t.Fatal("interrupted a settled session")
			}
		})
	}
}

func TestCollectDeletesUnsettledSessionAtTimeLimit(t *testing.T) {
	for _, tt := range []struct {
		name            string
		interruptStatus int
		wantInterrupts  []time.Duration
	}{
		{"interrupt keeps failing", 503, []time.Duration{0, 2 * time.Second, 4 * time.Second}},
		{"interrupt grace elapsed", 200, []time.Duration{0}},
		{"session becomes unsettled again", 200, []time.Duration{0, 10 * time.Second}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clock := testClock()
			start := clock.Now()
			s := sessionState(start.Add(-time.Minute))
			var interrupts []time.Duration
			var cleanup []string
			r := testRunner(func(req *http.Request) (int, string) {
				key := req.Method + " " + req.URL.RequestURI()
				switch key {
				case "GET /v1/sessions/session-1":
					if tt.name == "session becomes unsettled again" && len(interrupts) == 1 && clock.Now().Equal(start) {
						return 200, `{"status":"idle"}`
					}
					return 200, `{"status":"running"}`
				case "POST /v1/sessions/session-1/events?beta=true":
					interrupts = append(interrupts, clock.Now().Sub(start))
					return tt.interruptStatus, "{}"
				case "GET /v1/files?scope_id=session-1", "GET /v1/sessions/session-1/events?beta=true":
					return 200, `{"data":[]}`
				default:
					cleanup = append(cleanup, key)
					return 200, "{}"
				}
			}, clock)
			err := r.collect(t.Context(), s, t.TempDir())
			if err == nil || !strings.Contains(err.Error(), "session could not be stopped and was deleted") {
				t.Fatalf("collect = %v", err)
			}
			if !slices.Equal(interrupts, tt.wantInterrupts) || clock.Now().Sub(start) != tt.wantInterrupts[len(tt.wantInterrupts)-1]+interruptGrace {
				t.Fatalf("interrupts = %v, elapsed = %v", interrupts, clock.Now().Sub(start))
			}
			wantCleanup := []string{"DELETE /v1/sessions/session-1", "POST /v1/agents/agent-1/archive",
				"DELETE /v1/environments/env-1", "DELETE /v1/files/upload-1", "DELETE /v1/files/upload-2"}
			if !slices.Equal(cleanup, wantCleanup) {
				t.Fatalf("cleanup calls = %v, want %v", cleanup, wantCleanup)
			}
		})
	}
}

func TestCollectNotesAndWebToolPolicy(t *testing.T) {
	for _, tt := range []struct{ name, wantNote string }{
		{"list events", "could not list session events"},
		{"save events", "could not save session events"},
		{"truncated listings", "file listing was truncated\nevent listing was truncated"},
		{"web tools", "policy violation: the agent used web tools"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			out := t.TempDir()
			if tt.name == "save events" {
				if err := os.Mkdir(filepath.Join(out, "events.json"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			clock := testClock()
			s := sessionState(clock.Now())
			cleaned := 0
			r := testRunner(func(req *http.Request) (int, string) {
				switch req.Method + " " + req.URL.RequestURI() {
				case "GET /v1/sessions/session-1":
					if tt.name == "web tools" {
						return 200, `{"status":"idle","usage":{"active_seconds":1,"server_tool_use":{"web_fetch_requests":2,"web_search_requests":3}}}`
					}
					return 200, `{"status":"idle","usage":{"active_seconds":1}}`
				case "GET /v1/files?scope_id=session-1":
					return 200, fmt.Sprintf(`{"data":[{"id":"patch","filename":"patch.diff"},{"id":"paths","filename":"changed-paths.txt"}],"has_more":%t}`, tt.name == "truncated listings")
				case "GET /v1/files/patch/content":
					return 200, "test patch"
				case "GET /v1/files/paths/content":
					return 200, "edit.go\n"
				case "GET /v1/sessions/session-1/events?beta=true":
					if tt.name == "list events" {
						return 403, "events unavailable"
					}
					return 200, fmt.Sprintf(`{"data":[],"has_more":%t}`, tt.name == "truncated listings")
				default:
					if _, err := os.Stat(filepath.Join(out, "record.partial.json")); err != nil {
						t.Fatalf("cleanup before record was saved: %v", err)
					}
					cleaned++
					return 200, "{}"
				}
			}, clock)
			err := r.collect(t.Context(), s, out)
			if tt.name == "web tools" {
				if err == nil || err.Error() != tt.wantNote {
					t.Fatalf("collect = %v, want %q", err, tt.wantNote)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			rec, err := readJSON[record.Record](filepath.Join(out, "record.partial.json"))
			if err != nil {
				t.Fatal(err)
			}
			if cleaned != 5 || !strings.Contains(rec.Notes, tt.wantNote) || read(t, filepath.Join(out, patchName)) != "test patch" {
				t.Fatalf("cleanup calls = %d, notes = %q", cleaned, rec.Notes)
			}
			if tt.name == "web tools" && (rec.Usage.WebFetchRequests != 2 || rec.Usage.WebSearchRequests != 3 ||
				!strings.Contains(read(t, filepath.Join(out, "events.json")), `"data":[]`)) {
				t.Fatal("web tool case did not save usage and events")
			}
		})
	}
}

func TestOutputFilesSelectsExactNamesAndLatestCandidate(t *testing.T) {
	r := testRunner(func(req *http.Request) (int, string) {
		return 200, `{"data":[
			{"id":"new","filename":"outputs/patch.diff","created_at":"2026-11-20T07:00:00Z"},
			{"id":"old","filename":"old/patch.diff","created_at":"2026-11-19T07:00:00Z"},
			{"id":"decoy","filename":"outputs/not-patch.diff","created_at":"2026-11-21T07:00:00Z"},
			{"id":"dated","filename":"changed-paths.txt","created_at":"2026-11-21T07:00:00Z"},
			{"id":"undated","filename":"tmp/changed-paths.txt","created_at":"invalid"},
			{"id":"last","filename":"outputs/changed-paths.txt","created_at":"2026-11-19T07:00:00Z"},
			{"id":"wrong","filename":"outputs/not-probe.txt"}
		]}`
	}, testClock())
	ids, notes, err := r.outputFiles(t.Context(), "session-1")
	if err != nil || !reflect.DeepEqual(ids, map[string]string{patchName: "new", pathsName: "last"}) ||
		!slices.Equal(notes, []string{"patch.diff had 2 candidates", "changed-paths.txt had 3 candidates"}) {
		t.Fatalf("outputFiles = %v, %v, %v", ids, notes, err)
	}
}
