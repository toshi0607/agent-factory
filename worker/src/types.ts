import type { Ledger } from "./ledger";
import type { Run } from "./run";

export interface OidcEnv {
  OIDC_AUDIENCE: string;
  ALLOWED_REPOSITORY_ID: string;
  ALLOWED_REPOSITORY_OWNER_ID: string;
  ALLOWED_JOB_WORKFLOWS: string;
  ALLOWED_REFS: string;
}

export interface Env extends OidcEnv {
  RUN: DurableObjectNamespace<Run>;
  LEDGER: DurableObjectNamespace<Ledger>;
  INSTANCE_TYPE: string;
  FACTORY_COMMIT: string;
  CF_VERSION_METADATA?: { id: string; tag: string; timestamp: string };
}

export interface Caller {
  repositoryId: string;
  workflowPath: string;
  workflowSha: string;
  run_id: string;
  run_attempt: string;
}

export interface Prices {
  input: number;
  output: number;
  cache_write_5m: number;
  cache_write_1h: number;
  cache_read: number;
}

export interface EgressRule {
  host: string;
  path_prefixes?: string[] | undefined;
}

export interface Rules {
  model: string;
  egress: EgressRule[];
}

export interface PricedRules extends Rules {
  prices: Prices;
}

export interface StartRequest extends PricedRules {
  role: string;
  system_prompt: string;
  user_message: string;
  budget_cents: number;
  minutes: number;
}

export interface TokenInfo {
  present: boolean;
  expires_at: string | null;
}

export interface TokenCounts {
  input_tokens: number;
  output_tokens: number;
  cache_read_input_tokens: number;
  cache_creation_5m_input_tokens: number;
  cache_creation_1h_input_tokens: number;
}

export interface Usage extends TokenCounts {
  requests: number;
  cost_microcents: number;
  unmetered_responses: number;
}

export interface EgressEntry {
  t: string;
  method: string;
  scheme: string;
  host: string;
  path: string;
  query_bytes: number;
  decision: "allow" | "deny" | "llm";
  reason?: string;
  body_reason?: string;
  beta_dropped?: string[];
  status?: number;
  request_bytes?: number;
  response_bytes?: number;
  model?: string;
  usage?: Usage;
}

export interface EgressSummary {
  allowed: number;
  denied: number;
  llm: number;
  dropped: number;
  dropped_deny: number;
  dropped_other: number;
  denied_hosts: string[];
  throttled: number;
}

export interface LedgerStatus {
  token: TokenInfo;
  usage: Usage & {
    inflight: number; late_settlements: number; reserved_microcents: number; oldest_inflight_seconds: number;
  };
  egress: EgressSummary;
  budget_exhausted: boolean;
}

export interface Reservation {
  request_id: string;
  estimate_microcents: number;
}

export type ThrottleReason = "too_many_inflight" | "budget_reserved";

export const THROTTLE_REASONS: readonly string[] = ["too_many_inflight", "budget_reserved"] satisfies ThrottleReason[];

export type Authorization =
  | { ok: true; token: string }
  | { ok: false; reason: "no_token" | "token_expired" | "budget_exhausted" | "run_not_running" | ThrottleReason };

export type State = "created" | "running" | "finished" | "lost" | "destroyed";
export type RequestedStop = "time_limit" | "cancelled";
export type ForcedStop = RequestedStop | "budget_reached";
export type StopReason = ForcedStop | "completed" | "agent_error" | "lost";

export interface AgentResult {
  is_error: boolean;
  subtype: string;
  num_turns: number;
  total_cost_usd: number;
  result_head: string;
}

export type OutputName = "patch.diff" | "changed-paths.txt" | "probe.txt" | "events.jsonl" | "stderr.log";

export function object(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

export function errorResponse(status: number, error: string, message: string): Response {
  return Response.json({ error, message }, { status });
}
