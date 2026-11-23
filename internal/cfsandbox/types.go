package cfsandbox

import (
	"time"

	"github.com/toshi0607/agent-factory/internal/policy"
)

type StartRequest struct {
	Role         string            `json:"role"`
	Model        string            `json:"model"`
	SystemPrompt string            `json:"system_prompt"`
	UserMessage  string            `json:"user_message"`
	BudgetCents  int               `json:"budget_cents"`
	Minutes      int               `json:"minutes"`
	Prices       policy.Prices     `json:"prices"`
	Egress       []policy.PathRule `json:"egress"`
}

type Version struct {
	ID string `json:"id"`
}

type StartResponse struct {
	State         string    `json:"state"`
	StartedAt     time.Time `json:"started_at"`
	WorkerVersion Version   `json:"worker_version"`
	FactoryCommit string    `json:"factory_commit"`
	RequestSHA256 string    `json:"-"`
}

type Status struct {
	ID            string    `json:"id"`
	State         string    `json:"state"`
	StopReason    string    `json:"stop_reason"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	WorkerVersion Version   `json:"worker_version"`
	FactoryCommit string    `json:"factory_commit"`
	Usage         Usage     `json:"usage"`
	Egress        Egress    `json:"egress"`
	Container     struct {
		Instance string `json:"instance"`
	} `json:"container"`
	AgentResult *struct {
		TotalCostUSD *float64 `json:"total_cost_usd"`
	} `json:"agent_result"`
}

type Usage struct {
	InputTokens                int64 `json:"input_tokens"`
	OutputTokens               int64 `json:"output_tokens"`
	CacheReadInputTokens       int64 `json:"cache_read_input_tokens"`
	CacheCreation5mInputTokens int64 `json:"cache_creation_5m_input_tokens"`
	CacheCreation1hInputTokens int64 `json:"cache_creation_1h_input_tokens"`
	CostMicrocents             int64 `json:"cost_microcents"`
	UnmeteredResponses         int64 `json:"unmetered_responses"`
}

type Egress struct {
	Allowed     int64    `json:"allowed"`
	Denied      int64    `json:"denied"`
	LLM         int64    `json:"llm"`
	DeniedHosts []string `json:"denied_hosts"`
}
