import "./runtime";
import { describe, expect, it, vi } from "vitest";
import { decide, handle, type OutboundLedger, type RequestSummary } from "../src/outbound";
import type { Authorization, EgressEntry } from "../src/types";
import { startRequest as rules } from "./fixtures";

const storage = "https://storage.googleapis.com";
const prefix = "/proxy-golang-org-prod/";
const proxy = "https://proxy.golang.org";
const messages = "https://api.anthropic.com/v1/messages";

function summary(url: string, overrides: Partial<RequestSummary> = {}): RequestSummary {
  return { url, method: "GET", hasBody: false, contentLength: null, transferEncoding: false, ...overrides };
}

describe("outbound decisions", () => {
  it.each([
    [summary("http://proxy.golang.org/"), "plain_http"],
    [summary("not a URL"), "invalid_url"],
    [summary("https://127.0.0.1/"), "ip_literal"],
    [summary("https://0x7f000001/"), "ip_literal"],
    [summary("https://[::1]/"), "ip_literal"],
    [summary("https://proxy.golang.org:444/"), "port_not_allowed"],
    [summary("https://guest@proxy.golang.org/"), "userinfo"],
    [summary("https://proxy.golang.org./"), "host_not_allowed"],
    [summary("https://proxy.golang.org.example.invalid/"), "host_not_allowed"],
    [summary(storage + prefix + "../x"), "path_not_allowed"],
    [summary(storage + prefix + "%2e%2E/x"), "path_not_allowed"],
    [summary(storage + prefix + "%2e/x"), "path_not_allowed"],
    [summary(storage + prefix + "x%2fabc"), "path_not_allowed"],
    [summary(storage + prefix + "x%252fabc"), "path_not_allowed"],
    [summary(storage + prefix.slice(0, -1)), "path_not_allowed"],
    [summary(storage + prefix.slice(0, -1) + "-other/x"), "path_not_allowed"],
    [summary(storage + "/other/path"), "path_not_allowed"],
    [summary(proxy, { method: "POST" }), "method_not_allowed"],
    [summary(proxy, { hasBody: true }), "body_not_allowed"],
    [summary(proxy, { transferEncoding: true }), "body_not_allowed"],
    [summary(proxy, { contentLength: "1" }), "body_not_allowed"],
    [summary(messages), "llm_path"],
    [summary(messages + "/", { method: "POST" }), "llm_path"],
    [summary(messages + "?beta=false", { method: "POST" }), "llm_path"],
    [summary(messages + "?beta=true&extra=x", { method: "POST" }), "llm_path"],
    [summary(messages + "/stream", { method: "POST" }), "llm_path"],
  ])("denies %j with %s", (request, reason) => {
    expect(decide(request, rules)).toEqual({ action: "deny", reason });
  });

  it.each([
    summary("https://PROXY.GOLANG.ORG:443/"),
    summary(proxy, { method: "HEAD", contentLength: "0" }),
    summary(storage + prefix + "x.zip"),
  ])("allows %j", request => {
    expect(decide(request, rules).action).toBe("allow");
  });

  it("treats a rule without a trailing slash as a literal prefix", () => {
    const customized = { ...rules, egress: [{ host: "storage.googleapis.com", path_prefixes: ["/item"] }] };
    expect(decide(summary(storage + "/items"), customized).action).toBe("allow");
    expect(decide(summary(storage + "/other"), customized).action).toBe("deny");
  });

  it("denies every host before configuration", () => {
    for (const request of [summary(proxy), summary(messages, { method: "POST" })]) {
      expect(decide(request, null)).toEqual({ action: "deny", reason: "run_not_started" });
    }
  });
});

function setup(refusal?: Extract<Authorization, { ok: false }>["reason"]) {
  const token = crypto.randomUUID();
  const entries: EgressEntry[] = [];
  const ledger = {
    rules: vi.fn(() => rules),
    authorize: vi.fn((): Authorization => refusal ? { ok: false, reason: refusal } : { ok: true, token }),
    record: vi.fn((entry: EgressEntry) => entries.push(entry)),
    recordFailure: vi.fn(),
    meter: vi.fn<OutboundLedger["meter"]>(),
    flagMeteringFailure: vi.fn(),
  } satisfies OutboundLedger;
  const upstream = vi.fn<typeof fetch>();
  const pending: Promise<unknown>[] = [];
  const send = (request: Request) => handle(request, {
    ledger, upstream, now: () => 0, waitUntil: promise => { pending.push(promise); },
  });
  return { send, ledger, entries, upstream, token, flushed: () => Promise.all(pending) };
}

function llm(path = messages, body = JSON.stringify({ model: rules.model, max_tokens: 99 }), headers: HeadersInit = {}) {
  return new Request(path, { method: "POST", body, headers });
}

describe("outbound request handling", () => {
  it("returns a deny response and logs a query length without the query or headers", async () => {
    const { send, entries, flushed } = setup();
    const omitted = crypto.randomUUID();
    const response = await send(new Request(`https://example.invalid/files?${omitted}`, { headers: { cookie: omitted } }));
    expect(response.status).toBe(403);
    expect(response.headers.get("x-factory-denied")).toBe("host_not_allowed");
    expect(await response.text()).toBe("factory: host_not_allowed\n");
    await flushed();
    expect(entries).toEqual([{
      t: new Date(0).toISOString(), method: "GET", scheme: "https", host: "example.invalid",
      path: "/files", query_bytes: omitted.length, decision: "deny", reason: "host_not_allowed", status: 403,
    }]);
    expect(JSON.stringify(entries)).not.toContain(omitted);
  });

  it("forwards only permitted read headers and returns redirects to the guest", async () => {
    const { send, upstream, entries, flushed } = setup();
    upstream.mockResolvedValue(new Response("redirect", { status: 302, headers: { location: "https://example.invalid" } }));
    const omitted = crypto.randomUUID();
    const path = "/" + "a".repeat(400);
    const response = await send(new Request(proxy + path, {
      headers: {
        accept: "application/zip", range: "bytes=0-1", "accept-encoding": "gzip", "if-none-match": "etag",
        "if-modified-since": "later", "user-agent": "test", authorization: omitted, cookie: omitted,
        host: "example.invalid", "proxy-authorization": omitted, "x-api-key": omitted,
      },
    }));
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe("https://example.invalid");
    expect(upstream).toHaveBeenCalledOnce();
    const [url, init] = upstream.mock.calls[0] ?? [];
    expect(url).toBe(proxy + path);
    expect(init?.redirect).toBe("manual");
    expect(Object.fromEntries(new Headers(init?.headers))).toEqual({
      accept: "application/zip", range: "bytes=0-1", "accept-encoding": "gzip", "if-none-match": "etag",
      "if-modified-since": "later", "user-agent": "test",
    });
    await flushed();
    expect(entries[0]?.path).toHaveLength(300);
  });

  it("uses a scoped bearer, forwards the body intact and meters bytes on a separate stream", async () => {
    const { send, upstream, ledger, entries, token, flushed } = setup();
    const payload = JSON.stringify({ usage: { input_tokens: 4, output_tokens: 7 }, other: "é" });
    upstream.mockResolvedValue(new Response(payload, { headers: { "content-type": "application/json" } }));
    const body = JSON.stringify({ model: rules.model, max_tokens: 99 });
    const guest = crypto.randomUUID();
    const response = await send(llm(messages + "?beta=true", body, {
      "content-type": "application/json", accept: "application/json", "anthropic-version": "2023-06-01",
      "anthropic-beta": "test", "user-agent": "test", "x-stainless-retry-count": "1", "x-app": "cli",
      "anthropic-dangerous-direct-browser-access": "true", "accept-encoding": "gzip", "x-api-key": guest,
      authorization: `Bearer ${guest}`, cookie: guest, "proxy-authorization": guest, "x-other": guest,
    }));
    expect(await response.text()).toBe(payload);
    expect(upstream).toHaveBeenCalledOnce();
    const [url, init] = upstream.mock.calls[0] ?? [];
    expect(url).toBe(messages + "?beta=true");
    expect(init?.redirect).toBe("manual");
    expect(init?.body).toEqual(new TextEncoder().encode(body));
    expect(Object.fromEntries(new Headers(init?.headers))).toEqual({
      "content-type": "application/json", accept: "application/json", "anthropic-version": "2023-06-01",
      "anthropic-beta": "test", "user-agent": "test", "x-stainless-retry-count": "1", "x-app": "cli",
      "anthropic-dangerous-direct-browser-access": "true", authorization: `Bearer ${token}`,
    });
    await flushed();
    expect(ledger.authorize).toHaveBeenCalledWith(true);
    expect(ledger.meter).toHaveBeenCalledWith(
      { tokens: expect.objectContaining({ input_tokens: 4, output_tokens: 7 }), unmetered: false, responseBytes: Buffer.byteLength(payload) },
      expect.objectContaining({ decision: "llm", status: 200, request_bytes: body.length, model: rules.model }),
      1,
    );
    for (const secret of [guest, token, body, payload]) expect(JSON.stringify(entries)).not.toContain(secret);
  });

  it.each([
    ["no_token", 503], ["token_expired", 503], ["budget_exhausted", 403], ["run_not_running", 403],
  ] as const)("returns the Anthropic error envelope for %s", async (reason, status) => {
    const { send, upstream, flushed, entries } = setup(reason);
    const response = await send(llm());
    expect(response.status).toBe(status);
    expect(await response.json()).toEqual({ type: "error", error: { type: "permission_error", message: `factory: ${reason}` } });
    expect(upstream).not.toHaveBeenCalled();
    await flushed();
    expect(entries[0]).toMatchObject({ decision: "deny", reason, status });
  });

  it.each([
    ["{}", {}, "llm_model"],
    ["not JSON", {}, "llm_model"],
    [JSON.stringify({ model: "claude-other" }), {}, "llm_model"],
    ['{"model":"claude-other","\\u006dodel":"claude-example"}', {}, "llm_model"],
    ['{"model":"claude-example","max_tokens":9999,"max_tokens":99}', {}, "llm_model"],
    [JSON.stringify({ model: rules.model }), { "content-length": String(32 * 1024 * 1024 + 1) }, "llm_body_too_large"],
    [" ".repeat(32 * 1024 * 1024 + 1), {}, "llm_body_too_large"],
  ] as const)("denies an invalid or oversized body (%#)", async (body, headers, reason) => {
    const { send, upstream, ledger } = setup();
    const result = await send(llm(messages, body, headers));
    expect(result.status).toBe(403);
    expect(result.headers.get("x-factory-denied")).toBe(reason);
    expect(upstream).not.toHaveBeenCalled();
    expect(ledger.authorize).not.toHaveBeenCalled();
  });

  it("never meters count_tokens or non-200 Messages responses", async () => {
    const { send, upstream, ledger, flushed } = setup();
    upstream.mockResolvedValueOnce(Response.json({ input_tokens: 5 }));
    upstream.mockResolvedValueOnce(new Response(null, { status: 302, headers: { location: proxy } }));
    expect((await send(llm(messages + "/count_tokens"))).status).toBe(200);
    expect((await send(llm())).status).toBe(302);
    await flushed();
    expect(ledger.authorize.mock.calls).toEqual([[false], [true]]);
    expect(ledger.meter).not.toHaveBeenCalled();
    expect(upstream).toHaveBeenCalledTimes(2);
  });

  it("charges a fallback when a successful response has no usage, even if egress logging fails", async () => {
    const { send, upstream, ledger, flushed } = setup();
    const log = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    try {
      ledger.record.mockImplementation(() => { throw new Error("record failed"); });
      upstream.mockResolvedValue(Response.json({ text: "unchanged" }));
      const body = JSON.stringify({ model: rules.model, max_tokens: 99 });
      const response = await send(llm(messages, body));
      expect(await response.json()).toEqual({ text: "unchanged" });
      await flushed();
      expect(ledger.recordFailure).toHaveBeenCalledOnce();
      expect(ledger.meter).toHaveBeenCalledWith(expect.objectContaining({
        unmetered: true, tokens: expect.objectContaining({ input_tokens: Math.ceil(body.length / 3), output_tokens: 99 }),
      }), expect.any(Object), null);
    } finally {
      log.mockRestore();
    }
  });
});
