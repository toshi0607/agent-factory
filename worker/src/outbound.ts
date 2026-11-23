import { WorkerEntrypoint } from "cloudflare:workers";
import { duplicateField, filterBeta, validateLlmBody } from "./llm-request";
import { BodyTooLarge, readBytes } from "./streams";
import type { Authorization, EgressEntry, Env, PricedRules, Reservation, Rules } from "./types";
import { costMicrocents, estimatedTokens, meterResponse, type Settlement } from "./usage";

const ANTHROPIC = "api.anthropic.com";
const MESSAGES = "/v1/messages";
const COUNT_TOKENS = "/v1/messages/count_tokens";
const MAX_LLM_BODY = 32 * 1024 * 1024;
const READ_HEADERS = new Set(["accept", "accept-encoding", "user-agent", "range", "if-none-match", "if-modified-since"]);
const LLM_HEADERS = new Set([
  "content-type", "accept", "anthropic-version", "user-agent", "x-app",
  "anthropic-dangerous-direct-browser-access",
]);
const encoder = new TextEncoder();

export interface RequestSummary {
  url: string;
  method: string;
  hasBody: boolean;
  contentLength: string | null;
  transferEncoding: boolean;
}

type Decision<T extends Rules> =
  | { action: "deny"; reason: string }
  | { action: "allow"; url: URL }
  | { action: "llm"; url: URL; meter: boolean; rules: T };
const deny = (reason: string) => ({ action: "deny" as const, reason });

function parseUrl(input: string): URL | undefined {
  try {
    return new URL(input);
  } catch {
    return undefined;
  }
}

function ambiguousPath(rawUrl: string, path: string): boolean {
  const rawPath = /^https:\/\/[^/\\?#]+([^?#]*)/i.exec(rawUrl)?.[1] ?? path;
  return /(?:^|\/)\.{1,2}(?:\/|$)|%(?:2e|2f|5c|25)|\\/i.test(rawPath)
    || /%(?:2e|2f|5c|25)/i.test(path);
}

export function decide<T extends Rules>(request: RequestSummary, rules: T | "inactive" | null): Decision<T> {
  if (rules === "inactive") return deny("run_not_running");
  if (!rules) return deny("run_not_started");
  const url = parseUrl(request.url);
  if (!url) return deny("invalid_url");
  if (url.protocol !== "https:") return deny("plain_http");
  if (url.username || url.password) return deny("userinfo");
  if (url.port) return deny("port_not_allowed");
  const host = url.hostname.toLowerCase();
  if (host.startsWith("[") || /^[0-9.]+$/.test(host)) return deny("ip_literal");

  if (host === ANTHROPIC) {
    if (request.method !== "POST" || (url.pathname !== MESSAGES && url.pathname !== COUNT_TOKENS)
      || (url.search !== "" && url.search !== "?beta=true")) {
      return deny("llm_path");
    }
    return { action: "llm", url, meter: url.pathname === MESSAGES, rules };
  }
  const rule = rules.egress.find(entry => entry.host === host);
  if (host.endsWith(".") || host.endsWith(".anthropic.com") || !rule) return deny("host_not_allowed");
  if (rule.path_prefixes !== undefined && (ambiguousPath(request.url, url.pathname)
    || !rule.path_prefixes.some(prefix => url.pathname.startsWith(prefix)))) {
    return deny("path_not_allowed");
  }
  if (request.method !== "GET" && request.method !== "HEAD") return deny("method_not_allowed");
  if (request.hasBody || request.transferEncoding || (request.contentLength !== null && !/^0+$/.test(request.contentLength))) {
    return deny("body_not_allowed");
  }
  return { action: "allow", url };
}

type Awaitable<T> = T | Promise<T>;
export interface OutboundLedger {
  rules(): Awaitable<PricedRules | "inactive" | null>;
  authorize(reservation?: Reservation): Awaitable<Authorization>;
  record(entry: EgressEntry): Awaitable<number | null>;
  recordFailure(entry: EgressEntry): Awaitable<void>;
  meter(requestId: string, sample: Settlement, entry: EgressEntry, row: number | null): Awaitable<void>;
  flagMeteringFailure(): Awaitable<void>;
}

interface Dependencies {
  ledger: OutboundLedger;
  upstream: typeof fetch;
  now: () => number;
  waitUntil: (promise: Promise<unknown>) => void;
}

function headersFor(request: Request, llm: boolean): Headers {
  const headers = new Headers();
  const allowed = llm ? LLM_HEADERS : READ_HEADERS;
  for (const [name, value] of request.headers) {
    if (allowed.has(name) || (llm && name.startsWith("x-stainless-"))) headers.set(name, value);
  }
  return headers;
}

function logEntry(request: Request, now: number): Omit<EgressEntry, "decision"> {
  const url = parseUrl(request.url);
  return {
    t: new Date(now).toISOString(),
    method: request.method.slice(0, 32),
    scheme: url?.protocol.slice(0, -1) ?? "",
    host: url?.hostname.slice(0, 253) ?? "",
    path: url?.pathname.slice(0, 300) ?? "",
    query_bytes: url?.search ? encoder.encode(url.search.slice(1)).byteLength : 0,
  };
}

async function record(ledger: OutboundLedger, entry: EgressEntry): Promise<number | null> {
  try {
    return await ledger.record(entry);
  } catch {
    console.warn({ event: "egress_record_failed" });
    try {
      await ledger.recordFailure(entry);
    } catch {
      console.warn({ event: "egress_drop_count_failed" });
    }
    return null;
  }
}

async function settle(
  ledger: OutboundLedger, requestId: string, sample: Promise<Settlement>, entry: EgressEntry, row: Promise<number | null>,
): Promise<void> {
  try {
    const result = await sample.catch(() => "failure" as const);
    await ledger.meter(requestId, result, entry, result === "zero" ? null : await row);
  } catch {
    console.error({ event: "metering_write_failed" });
    try {
      await ledger.flagMeteringFailure();
    } catch {
      console.error({ event: "metering_failure_flag_failed" });
    }
  }
}

function reportedLength(headers: Headers): number | undefined {
  const value = headers.get("content-length");
  if (value === null || !/^\d+$/.test(value)) return undefined;
  const number = Number(value);
  return Number.isSafeInteger(number) ? number : undefined;
}

export async function handle(request: Request, { ledger, upstream, now, waitUntil }: Dependencies): Promise<Response> {
  const base = logEntry(request, now());
  function finish(response: Response, details: Pick<EgressEntry, "decision" | "reason"> & Partial<EgressEntry>,
    settlement?: { requestId: string; sample: Promise<Settlement> }): Response {
    const responseBytes = reportedLength(response.headers);
    const entry: EgressEntry = { ...base, ...details, status: response.status };
    if (responseBytes !== undefined) entry.response_bytes = responseBytes;
    const row = record(ledger, entry);
    waitUntil(settlement ? Promise.all([row, settle(ledger, settlement.requestId, settlement.sample, entry, row)]) : row);
    return response;
  }
  function denied(reason: string, details: Partial<EgressEntry> = {}): Response {
    return finish(new Response(`factory: ${reason}\n`, {
      status: 403, headers: { "x-factory-denied": reason },
    }), { ...details, decision: "deny", reason });
  }
  function failed(reason: string, decision: EgressEntry["decision"], details: Partial<EgressEntry> = {}): Response {
    return finish(new Response(`factory: ${reason}\n`, { status: 502 }), { ...details, decision, reason });
  }

  let rules: PricedRules | "inactive" | null;
  try {
    rules = await ledger.rules();
  } catch {
    return failed("ledger_unavailable", "deny");
  }
  const contentLength = request.headers.get("content-length");
  const decision = decide({
    url: request.url, method: request.method, hasBody: request.body !== null, contentLength,
    transferEncoding: request.headers.has("transfer-encoding"),
  }, rules);
  if (decision.action === "deny") return denied(decision.reason);

  if (decision.action === "allow") {
    try {
      const response = await upstream(decision.url.href, {
        method: request.method, headers: headersFor(request, false), redirect: "manual",
      });
      return finish(response, { decision: "allow", request_bytes: 0 });
    } catch {
      return failed("upstream_error", "allow", { request_bytes: 0 });
    }
  }

  const beta = filterBeta(request.headers.get("anthropic-beta"));
  const betaDetails = beta.dropped.length ? { beta_dropped: beta.dropped } : {};
  if (contentLength !== null && /^\d+$/.test(contentLength) && Number(contentLength) > MAX_LLM_BODY) {
    return denied("llm_body_too_large", betaDetails);
  }
  let body: Uint8Array<ArrayBuffer>;
  let parsed: unknown;
  let text: string;
  try {
    body = await readBytes(request.body, MAX_LLM_BODY);
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(body);
    parsed = JSON.parse(text);
  } catch (error) {
    return denied(error instanceof BodyTooLarge ? "llm_body_too_large" : "llm_model", betaDetails);
  }
  const details = { ...betaDetails, request_bytes: body.length };
  const { model, prices } = decision.rules;
  const validation = validateLlmBody(parsed, model);
  if (!validation.ok) {
    return validation.reason === "model" ? denied("llm_model", details)
      : denied("llm_body", { ...details, body_reason: validation.reason });
  }
  const duplicate = duplicateField(text, parsed);
  if (duplicate === "model") return denied("llm_model", details);
  if (duplicate) return denied("llm_body", { ...details, body_reason: duplicate });
  const { maxTokens } = validation;
  const llmDetails = { ...details, model };
  if (decision.meter && maxTokens === undefined) return denied("llm_body", { ...llmDetails, body_reason: "max_tokens" });

  let authorization: Authorization;
  let reservation: Reservation | undefined;
  try {
    if (decision.meter && maxTokens !== undefined) {
      reservation = {
        request_id: crypto.randomUUID(),
        estimate_microcents: costMicrocents(estimatedTokens(body.length, maxTokens), prices),
      };
    }
    authorization = await ledger.authorize(reservation);
  } catch {
    return failed("ledger_unavailable", "deny", llmDetails);
  }
  if (!authorization.ok) {
    const { reason } = authorization;
    const rateLimited = reason === "too_many_inflight" || reason === "budget_reserved";
    const status = rateLimited ? 429 : reason === "no_token" || reason === "token_expired" ? 503 : 403;
    const headers = new Headers({ "x-factory-denied": reason });
    if (rateLimited) headers.set("retry-after", reason === "budget_reserved" ? "2" : "5");
    return finish(Response.json({
      type: "error", error: { type: rateLimited ? "rate_limit_error" : "permission_error", message: `factory: ${reason}` },
    }, { status, headers }), { ...llmDetails, decision: "deny", reason });
  }

  const headers = headersFor(request, true);
  if (beta.forwarded) headers.set("anthropic-beta", beta.forwarded);
  headers.set("authorization", `Bearer ${authorization.token}`);
  const entry = { ...llmDetails, decision: "llm" as const };
  const zero = reservation && { requestId: reservation.request_id, sample: Promise.resolve("zero" as const) };
  let response: Response;
  try {
    response = await upstream(decision.url.href, { method: "POST", headers, body, redirect: "manual" });
  } catch {
    return finish(new Response("factory: upstream_error\n", { status: 502 }), { ...entry, reason: "upstream_error" }, zero);
  }
  if (!reservation || response.status !== 200) return finish(response, entry, zero);
  const [guest, metering] = response.body?.tee() ?? [null, null];
  const sample = meterResponse(metering, response.headers.get("content-type"), body.length, maxTokens);
  return finish(new Response(guest, {
    status: response.status, statusText: response.statusText, headers: response.headers,
  }), entry, { requestId: reservation.request_id, sample });
}

export class Outbound extends WorkerEntrypoint<Env, { runId: string }> {
  protected upstream(_ledger: OutboundLedger): typeof fetch {
    return fetch;
  }

  override fetch(request: Request): Promise<Response> {
    const ledger = this.env.LEDGER.getByName(this.ctx.props.runId);
    return handle(request, {
      ledger, upstream: this.upstream(ledger), now: Date.now, waitUntil: promise => this.ctx.waitUntil(promise),
    });
  }
}
