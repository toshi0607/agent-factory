package record

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func validRecord() Record {
	start := time.Date(2026, time.November, 19, 1, 0, 0, 0, time.UTC)
	return Record{
		SchemaVersion:            1,
		Candidate:                "managed-agents",
		Task:                     "sm-create-get",
		WorkID:                   "work",
		BaseCommit:               "abcdef",
		FactoryCommit:            "factory-commit",
		Role:                     "fixer",
		EnvironmentRequestSHA256: "environment-digest",
		AgentRequestSHA256:       "agent-digest",
		BudgetCents:              300,
		MinutesLimit:             30,
		StopReason:               "completed",
		Model:                    "model",
		StartedAt:                start,
		FinishedAt:               start.Add(time.Minute),
		Session:                  Session{ID: "session", Status: "done", ActiveSeconds: 45, DurationSeconds: 60},
		Usage: Usage{
			InputTokens: 100, OutputTokens: 20, CacheReadInputTokens: 5,
			CacheCreation5mInputTokens: 6, CacheCreation1hInputTokens: 7,
			ReportedCost:     ReportedCost{Amount: "10", Currency: "USD"},
			WebFetchRequests: 2, WebSearchRequests: 3,
		},
		RunnerSeconds: RunnerSeconds{Start: 1, Collect: 2, Check: 3},
		Interruptions: Interruptions{Count: 1, Notes: []string{"retry"}},
		Egress:        Egress{LogAvailable: true, DeniedDestinations: []string{"example.invalid"}, Notes: "denied"},
		Patch:         Patch{SHA256: "hash", Bytes: 123, Paths: []string{"services/secretmanager/create_secret.go"}},
		Check: CheckResult{
			Task: "sm-create-get", PatchSHA256: "hash", PathsOK: true, ApplyOK: true,
			GenOK: true, GenChangedPaths: []string{"docs/coverage/secretmanager.md"},
			BuildOK: true, Failures: []Failure{{Name: "get", Message: "expected OK, got NOT_FOUND"}},
		},
		Notes: "example",
	}
}

func TestRecordJSONRoundTrip(t *testing.T) {
	for _, tt := range []struct {
		candidate string
		sandbox   *Sandbox
	}{
		{"managed-agents", nil},
		{"cloudflare-sandbox", &Sandbox{CPUSeconds: 3, MemoryGiBSeconds: 4}},
	} {
		t.Run(tt.candidate, func(t *testing.T) {
			want := validRecord()
			want.Candidate = tt.candidate
			want.Sandbox = tt.sandbox
			if tt.sandbox != nil {
				want.Check.JudgedTree = strings.Repeat("a", 40)
			}
			data, err := json.Marshal(want)
			if err != nil {
				t.Fatal(err)
			}
			var got Record
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("round trip got %+v, want %+v", got, want)
			}
			if err := got.Validate(); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), `"sandbox":`) != (tt.sandbox != nil) {
				t.Fatalf("unexpected sandbox encoding: %s", data)
			}
			if strings.Contains(string(data), `"judged_tree":`) != (want.Check.JudgedTree != "") {
				t.Fatalf("unexpected judged_tree encoding: %s", data)
			}
			if !strings.Contains(string(data), `"started_at":"2026-11-19T01:00:00Z"`) {
				t.Fatalf("expected RFC 3339 started_at: %s", data)
			}
			if strings.Contains(string(data), `"computed_cost_usd"`) {
				t.Fatal("record encoded a computed cost")
			}
		})
	}
}

func TestRecordValidate(t *testing.T) {
	for _, tt := range []struct {
		name   string
		field  string
		change func(*Record)
	}{
		{"missing schema version", "schema_version", func(r *Record) { r.SchemaVersion = 0 }},
		{"unknown schema version", "schema_version", func(r *Record) { r.SchemaVersion = 2 }},
		{"missing candidate", "candidate", func(r *Record) { r.Candidate = "" }},
		{"unknown candidate", "candidate", func(r *Record) { r.Candidate = "other" }},
		{"missing task", "task", func(r *Record) { r.Task = "" }},
		{"missing work ID", "work_id", func(r *Record) { r.WorkID = "" }},
		{"missing base commit", "base_commit", func(r *Record) { r.BaseCommit = "" }},
		{"missing model", "model", func(r *Record) { r.Model = "" }},
		{"missing start time", "started_at", func(r *Record) { r.StartedAt = time.Time{} }},
		{"missing finish time", "finished_at", func(r *Record) { r.FinishedAt = time.Time{} }},
		{"short judged tree", "judged_tree", func(r *Record) { r.Check.JudgedTree = "abc" }},
		{"uppercase judged tree", "judged_tree", func(r *Record) { r.Check.JudgedTree = strings.Repeat("A", 40) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := validRecord()
			tt.change(&r)
			if err := r.Validate(); err == nil || !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("Validate() = %v, want error for %s", err, tt.field)
			}
		})
	}
}
