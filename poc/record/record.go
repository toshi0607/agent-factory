package record

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

type Record struct {
	SchemaVersion            int           `json:"schema_version"`
	Candidate                string        `json:"candidate"`
	Task                     string        `json:"task"`
	WorkID                   string        `json:"work_id"`
	BaseCommit               string        `json:"base_commit"`
	FactoryCommit            string        `json:"factory_commit"`
	Role                     string        `json:"role"`
	EnvironmentRequestSHA256 string        `json:"environment_request_sha256"`
	AgentRequestSHA256       string        `json:"agent_request_sha256"`
	BudgetCents              int           `json:"budget_cents"`
	MinutesLimit             int           `json:"minutes_limit"`
	StopReason               string        `json:"stop_reason"`
	Model                    string        `json:"model"`
	StartedAt                time.Time     `json:"started_at"`
	FinishedAt               time.Time     `json:"finished_at"`
	Session                  Session       `json:"session"`
	Usage                    Usage         `json:"usage"`
	Sandbox                  *Sandbox      `json:"sandbox,omitempty"`
	RunnerSeconds            RunnerSeconds `json:"runner_seconds"`
	Interruptions            Interruptions `json:"interruptions"`
	Egress                   Egress        `json:"egress"`
	Patch                    Patch         `json:"patch"`
	Check                    CheckResult   `json:"check"`
	Notes                    string        `json:"notes"`
}

type Session struct {
	ID              string  `json:"id"`
	Status          string  `json:"status"`
	ActiveSeconds   float64 `json:"active_seconds"`
	DurationSeconds float64 `json:"duration_seconds"`
}

type Usage struct {
	InputTokens                int64        `json:"input_tokens"`
	OutputTokens               int64        `json:"output_tokens"`
	CacheReadInputTokens       int64        `json:"cache_read_input_tokens"`
	CacheCreation5mInputTokens int64        `json:"cache_creation_5m_input_tokens"`
	CacheCreation1hInputTokens int64        `json:"cache_creation_1h_input_tokens"`
	ReportedCost               ReportedCost `json:"reported_cost"`
	WebFetchRequests           int64        `json:"web_fetch_requests"`
	WebSearchRequests          int64        `json:"web_search_requests"`
}

type ReportedCost struct {
	// Amount is reported by the API in whole US cents.
	Amount   string `json:"amount"`
	Currency string `json:"currency"`
}

type Sandbox struct {
	CPUSeconds       float64 `json:"cpu_seconds"`
	MemoryGiBSeconds float64 `json:"memory_gib_seconds"`
}

type RunnerSeconds struct {
	Start   float64 `json:"start"`
	Collect float64 `json:"collect"`
	Check   float64 `json:"check"`
}

type Interruptions struct {
	Count int      `json:"count"`
	Notes []string `json:"notes"`
}

type Egress struct {
	LogAvailable       bool     `json:"log_available"`
	DeniedDestinations []string `json:"denied_destinations"`
	Notes              string   `json:"notes"`
}

type Patch struct {
	SHA256 string   `json:"sha256"`
	Bytes  int64    `json:"bytes"`
	Paths  []string `json:"paths"`
}

type CheckResult struct {
	Task            string    `json:"task"`
	PatchSHA256     string    `json:"patch_sha256"`
	GenPatchSHA256  string    `json:"gen_patch_sha256,omitempty"`
	JudgedTree      string    `json:"judged_tree,omitempty"`
	PathsOK         bool      `json:"paths_ok"`
	ApplyOK         bool      `json:"apply_ok"`
	GenOK           bool      `json:"gen_ok"`
	GenChangedPaths []string  `json:"gen_changed_paths"`
	BuildOK         bool      `json:"build_ok"`
	CheckPassed     bool      `json:"check_passed"`
	Failures        []Failure `json:"failures"`
	Error           string    `json:"error"`
}

type Failure struct {
	Name    string `json:"name"`
	Message string `json:"message"`
}

var treeID = regexp.MustCompile(`^[0-9a-f]{40}$`)

func (r Record) Validate() error {
	if r.SchemaVersion != 1 {
		return fmt.Errorf("schema_version: expected 1, got %d", r.SchemaVersion)
	}
	switch r.Candidate {
	case "managed-agents", "cloudflare-sandbox":
	default:
		return fmt.Errorf("candidate: expected managed-agents or cloudflare-sandbox, got %q", r.Candidate)
	}
	for _, field := range []struct{ name, value string }{
		{"task", r.Task},
		{"work_id", r.WorkID},
		{"base_commit", r.BaseCommit},
		{"model", r.Model},
	} {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("%s is required", field.name)
		}
	}
	if r.StartedAt.IsZero() {
		return fmt.Errorf("started_at is required")
	}
	if r.FinishedAt.IsZero() {
		return fmt.Errorf("finished_at is required")
	}
	if r.Check.JudgedTree != "" && !treeID.MatchString(r.Check.JudgedTree) {
		return fmt.Errorf("judged_tree must be 40 lowercase hex characters")
	}
	return nil
}
