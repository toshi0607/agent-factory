package claude_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/toshi0607/agent-factory/internal/claude"
	"github.com/toshi0607/agent-factory/internal/claudeauth"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type exchange struct {
	method, target, request, response string
	status                            int
}

func TestManagedAgentsAPI(t *testing.T) {
	ctx := t.Context()
	const envBody = `{"name":"run","config":{"type":"cloud","networking":{"type":"limited","allowed_hosts":["proxy.golang.org","sum.golang.org"]}}}`
	const tools = `[{"type":"agent_toolset_20260401","default_config":{"enabled":false},"configs":[{"name":"bash","enabled":true},{"name":"read","enabled":true},{"name":"write","enabled":true},{"name":"edit","enabled":true},{"name":"glob","enabled":true},{"name":"grep","enabled":true}]}]`
	const agentBody = `{"name":"run","model":"claude-opus-5-5","system":"fix one task","tools":` + tools + `}`
	const events = `{"data":[{"type":"agent.message","content":[{"type":"text","text":"DONE"}]}]}`
	const session = `{"id":"sesn_test","status":"idle","stats":{"active_seconds":50.871,"duration_seconds":54.073018691},"usage":{"active_seconds":51.195,"cache_creation":{"ephemeral_1h_input_tokens":17,"ephemeral_5m_input_tokens":279},"cache_read_input_tokens":12167,"input_tokens":6,"output_tokens":84,"list_cost":{"amount":"25","currency":"USD"}}}`
	steps := []exchange{
		{"POST", "/v1/environments", envBody, `{"id":"env_test","type":"environment"}`, 200},
		{"POST", "/v1/agents", agentBody, `{"id":"agent_test","type":"agent","tools":` + tools + `}`, 200},
		{"POST", "/v1/files", "", `{"id":"file_test","filename":"setup.sh","size_bytes":10,"downloadable":false}`, 200},
		{"POST", "/v1/sessions", `{"agent":"agent_test","environment_id":"env_test","budget":{"type":"limit","max_list_cost":{"amount":"300","currency":"USD"}},"resources":[{"type":"file","file_id":"file_test","mount_path":"/workspace/setup.sh"}]}`,
			`{"id":"sesn_test","status":"idle","resources":[{"type":"file","file_id":"file_test","mount_path":"/mnt/session/uploads/workspace/setup.sh"}]}`, 200},
		{"POST", "/v1/sessions/sesn_test/events?beta=true", `{"events":[{"type":"user.message","content":[{"type":"text","text":"run setup"}]}]}`, `{"data":[]}`, 200},
		{"POST", "/v1/sessions/sesn_test/events?beta=true", `{"events":[{"type":"user.interrupt"}]}`, `{"data":[]}`, 200},
		{"GET", "/v1/sessions/sesn_test", "", session, 200},
		{"GET", "/v1/sessions/sesn_test/events?beta=true", "", events, 200},
		{"GET", "/v1/files?scope_id=sesn_test", "", `{"data":[{"id":"file_output","filename":"outputs/patch.diff","downloadable":true}],"next_page":null,"has_more":false}`, 200},
		{"GET", "/v1/files/file_output/content", "", "patch\n", 200},
		{"DELETE", "/v1/sessions/sesn_test", "", `{"id":"sesn_test","type":"session_deleted"}`, 200},
		{"POST", "/v1/agents/agent_test/archive", "", `{"id":"agent_test","archived_at":"2026-11-15T07:17:58Z"}`, 200},
		{"DELETE", "/v1/environments/env_test", "", `{"error":{"message":"cannot delete"}}`, 405},
		{"POST", "/v1/environments/env_test/archive", "", `{"id":"env_test"}`, 200},
		{"DELETE", "/v1/environments/env_other", "", `{"id":"env_other","type":"environment_deleted"}`, 200},
		{"DELETE", "/v1/files/file_test", "", `{"id":"file_test","type":"file_deleted"}`, 200},
		{"GET", "/v1/agents?limit=1", "", `{"data":[]}`, 200},
	}
	var requests int
	client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		if requests >= len(steps) {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.RequestURI())
		}
		want := steps[requests]
		requests++
		if r.Method != want.method || r.URL.RequestURI() != want.target || r.URL.Host != "api.example.invalid" {
			t.Fatalf("request %d = %s %s, want %s %s", requests, r.Method, r.URL, want.method, want.target)
		}
		if r.Header.Get("anthropic-version") != "2026-10-21" ||
			r.Header.Get("anthropic-beta") != "managed-agents-2026-04-01" ||
			r.Header.Get("X-Test-Auth") != "fake-auth-placeholder" {
			t.Fatal("wrong API headers")
		}
		if _, ok := r.Context().Deadline(); !ok {
			t.Fatal("request has no deadline")
		}
		switch want.target {
		case "/v1/files":
			checkMultipart(t, r)
		default:
			if want.request != "" && r.Header.Get("Content-Type") != "application/json" {
				t.Fatal("missing JSON content type")
			}
			checkJSONBody(t, r, want.request)
		}
		return &http.Response{StatusCode: want.status, Body: io.NopCloser(strings.NewReader(want.response)), Header: make(http.Header)}, nil
	})}
	c := claude.New("https://api.example.invalid", client, claudeauth.Static{Header: "X-Test-Auth", Value: "fake-auth-placeholder"})
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}

	id, digest, err := c.CreateEnvironment(ctx, "run", []string{"proxy.golang.org", "sum.golang.org"})
	must(err)
	if id != "env_test" || digest != fmt.Sprintf("%x", sha256.Sum256([]byte(envBody))) {
		t.Fatalf("environment ID/hash = %s / %s", id, digest)
	}
	id, digest, err = c.CreateAgent(ctx, "run", "claude-opus-5-5", "fix one task")
	must(err)
	if id != "agent_test" || digest != fmt.Sprintf("%x", sha256.Sum256([]byte(agentBody))) {
		t.Fatalf("agent ID/hash = %s / %s", id, digest)
	}
	file, err := c.UploadFile(ctx, "setup.sh", strings.NewReader("script go\n"))
	must(err)
	if file.ID != "file_test" || file.Filename != "setup.sh" {
		t.Fatalf("file = %+v", file)
	}
	created, err := c.CreateSession(ctx, "agent_test", "env_test", 300, []claude.Resource{{Type: "file", FileID: file.ID, MountPath: "/workspace/setup.sh"}})
	must(err)
	if created.ID != "sesn_test" || len(created.Resources) != 1 || created.Resources[0].MountPath != "/mnt/session/uploads/workspace/setup.sh" {
		t.Fatalf("created session = %+v", created)
	}
	must(c.SendUserMessage(ctx, created.ID, "run setup"))
	must(c.Interrupt(ctx, created.ID))
	final, err := c.GetSession(ctx, created.ID)
	must(err)
	if final.Status != "idle" || final.Stats.ActiveSeconds != 50.871 || final.Stats.DurationSeconds != 54.073018691 ||
		final.Usage.ActiveSeconds != 51.195 || final.Usage.InputTokens != 6 || final.Usage.OutputTokens != 84 ||
		final.Usage.CacheReadInputTokens != 12167 || final.Usage.CacheCreation.Ephemeral5mInputTokens != 279 ||
		final.Usage.CacheCreation.Ephemeral1hInputTokens != 17 || final.Usage.ListCost != (claude.Money{Amount: "25", Currency: "USD"}) {
		t.Fatalf("final session = %+v", final)
	}
	raw, moreEvents, err := c.ListEvents(ctx, created.ID)
	must(err)
	if string(raw) != events || moreEvents {
		t.Fatalf("events = %s", raw)
	}
	entries, moreFiles, err := c.ListSessionFiles(ctx, created.ID)
	must(err)
	if moreFiles || len(entries) != 1 || entries[0].Filename != "outputs/patch.diff" {
		t.Fatalf("files = %+v", entries)
	}
	var downloaded bytes.Buffer
	must(c.DownloadFile(ctx, entries[0].ID, &downloaded))
	if downloaded.String() != "patch\n" {
		t.Fatalf("downloaded %q", downloaded.String())
	}
	must(c.DeleteSession(ctx, created.ID))
	must(c.ArchiveAgent(ctx, "agent_test"))
	must(c.DeleteEnvironment(ctx, "env_test"))
	must(c.DeleteEnvironment(ctx, "env_other"))
	must(c.DeleteFile(ctx, file.ID))
	status, err := c.CheckAgents(ctx)
	must(err)
	if status != 200 || requests != len(steps) {
		t.Fatalf("status = %d, requests = %d of %d", status, requests, len(steps))
	}
}

func checkMultipart(t *testing.T, r *http.Request) {
	t.Helper()
	parts, err := r.MultipartReader()
	if err != nil {
		t.Fatal(err)
	}
	part, err := parts.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	defer part.Close()
	data, err := io.ReadAll(part)
	if err != nil {
		t.Fatal(err)
	}
	if part.FileName() != "setup.sh" || part.FormName() != "file" || string(data) != "script go\n" {
		t.Fatalf("multipart file = %q %q %q", part.FileName(), part.FormName(), data)
	}
	if _, err := parts.NextPart(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected exactly one MIME part, got %v", err)
	}
}

func checkJSONBody(t *testing.T, r *http.Request, expected string) {
	t.Helper()
	if r.Body == nil {
		if expected != "" {
			t.Fatalf("missing body, want %s", expected)
		}
		return
	}
	defer r.Body.Close()
	data, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if expected == "" {
		if len(data) != 0 {
			t.Fatalf("unexpected request body %s", data)
		}
		return
	}
	var got, want any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(expected), &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("request body = %s, want %s", data, expected)
	}
}

func TestHTTPError(t *testing.T) {
	const credential = "fake-sensitive-placeholder"
	client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "api.anthropic.com" {
			t.Fatal("default base URL is incorrect")
		}
		text := strings.Repeat("a", 100) + credential + strings.Repeat("b", 2200)
		return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader(text)), Header: make(http.Header)}, nil
	})}
	c := claude.New("", client, claudeauth.Static{Header: "Authorization", Value: "Bearer " + credential})
	status, err := c.CheckAgents(t.Context())
	apiErr, ok := errors.AsType[*claude.HTTPError](err)
	if !ok || status != 403 || apiErr.StatusCode != 403 || len(apiErr.Body) != 2048 ||
		!strings.HasPrefix(apiErr.Body, strings.Repeat("a", 100)+"[redacted]") {
		t.Fatal("expected HTTP 403 with up to 2 KiB of redacted diagnostics")
	}
	if !strings.Contains(err.Error(), "[redacted]") || strings.Contains(err.Error(), credential) || strings.Contains(apiErr.Body, credential) {
		t.Fatal("credential leaked in API error")
	}
}

func TestCreateAgentVerifiesWebToolsDisabled(t *testing.T) {
	for _, tt := range []struct{ name, tools string }{
		{"no toolset", `[]`},
		{"malformed toolset", `[{"type":"agent_toolset_20260401","default_config":{"enabled":"false"}}]`},
		{"no default", `[{"type":"agent_toolset_20260401"}]`},
		{"default enabled", `[{"type":"agent_toolset_20260401","default_config":{"enabled":true}}]`},
		{"fetch enabled", `[{"type":"agent_toolset_20260401","default_config":{"enabled":false},"configs":[{"name":"web_fetch","enabled":true}]}]`},
		{"search enabled", `[{"type":"agent_toolset_20260401","default_config":{"enabled":false},"configs":[{"name":"web_search","enabled":true}]}]`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Transport: transportFunc(func(req *http.Request) (*http.Response, error) {
				defer req.Body.Close()
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"id":"agent_test","tools":` + tt.tools + `}`))}, nil
			})}
			c := claude.New("", client, claudeauth.Static{Header: "X-Test-Auth", Value: "fake-auth-placeholder"})
			id, _, err := c.CreateAgent(t.Context(), "run", "model", "system")
			if id != "agent_test" || err == nil || err.Error() != "agent response does not confirm that web tools are disabled" {
				t.Fatalf("CreateAgent = %q, %v", id, err)
			}
		})
	}
}

func TestHTTPErrorFormatsSafeDiagnostic(t *testing.T) {
	const status = "Managed Agents API: HTTP 403"
	for _, tt := range []struct{ name, body, want string }{
		{"whitespace", "  first\n\tsecond  ", status + ": first second"},
		{"rune limit", strings.Repeat("日", 301), status + ": " + strings.Repeat("日", 300)},
		{"JWT", "JWT eyJ" + strings.Repeat("x", 20), status},
		{"key beyond output limit", strings.Repeat("x", 301) + " sk-ant-fake-key", status},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := &claude.HTTPError{StatusCode: 403, Body: tt.body}
			if err.Error() != tt.want {
				t.Fatal("unexpected API error diagnostic")
			}
		})
	}
}
