import { describe, expect, it, vi } from "vitest";
import { createApp, route, validateStart } from "../src/app";
import { MAX_UPLOAD_BYTES } from "../src/streams";
import type { Caller, Env } from "../src/types";
import { startRequest } from "./fixtures";

const id = "p0-20261123T012345Z-abcdef12";
const base = `/runs/${id}`;

describe("routes and request validation", () => {
  it.each([
    ["", { resource: "run" }],
    ["/start", { resource: "start" }],
    ["/token", { resource: "token" }],
    ["/stop", { resource: "stop" }],
    ["/egress", { resource: "egress" }],
    ["/files/manifest.json", { resource: "files", name: "manifest.json" }],
    ["/outputs/patch.diff", { resource: "outputs", name: "patch.diff" }],
  ])("parses %s", (suffix, target) => {
    expect(route(base + suffix)).toEqual({ id, ...target });
  });

  it.each(["/files/..", "/files/.hidden", "/files/a%2Fb", "/files/a/b", "/files/", "/outputs/private.txt", "/start/", "/"])(
    "rejects invalid route %s", suffix => { expect(route(base + suffix)).toBeUndefined(); },
  );

  it("checks the run ID and filename length", () => {
    expect(route(`/runs/${id.toUpperCase()}`)).toBeUndefined();
    expect(route(`${base}/files/${"a".repeat(100)}`)).toBeDefined();
    expect(route(`${base}/files/${"a".repeat(101)}`)).toBeUndefined();
  });

  it("accepts budget, time, name, and prompt boundaries", () => {
    expect(validateStart({
      ...startRequest, role: "a".repeat(31), model: "claude-" + "a".repeat(60),
      system_prompt: "あ".repeat(21845) + "a", user_message: "é".repeat(8192),
      budget_cents: 1, minutes: 1,
    })).toBeDefined();
    expect(validateStart(startRequest)).toEqual(startRequest);
  });

  it.each([
    { role: "Fixer" }, { role: "x".repeat(32) }, { role: "" }, { model: "opus" },
    { model: "claude-" }, { model: "claude-" + "a".repeat(61) }, { model: "claude-UP" },
    { system_prompt: "é".repeat(32769) }, { system_prompt: null },
    { user_message: "é".repeat(8193) }, { user_message: "\0" }, { user_message: {} },
    { budget_cents: 0 }, { budget_cents: 301 }, { budget_cents: 5.5 }, { budget_cents: "3" },
    { minutes: 0 }, { minutes: 31 }, { minutes: 1.1 },
    { prices: {} }, { prices: { ...startRequest.prices, input: Infinity } },
    { prices: { ...startRequest.prices, output: NaN } },
    { prices: { ...startRequest.prices, cache_write_5m: 0 } },
    { prices: { ...startRequest.prices, cache_write_1h: -1 } },
    { prices: { ...startRequest.prices, cache_read: "1" } },
    { prices: { ...startRequest.prices, other: 1 } },
    { egress: Array.from({ length: 17 }, () => ({ host: "example.invalid" })) },
    { egress: [{ host: "api.anthropic.com" }] }, { egress: [{ host: "other.anthropic.com" }] },
    { egress: [{ host: "EXAMPLE.invalid" }] }, { egress: [{ host: "*.example.invalid" }] },
    { egress: [{ host: "example.invalid:443" }] }, { egress: [{ host: "example.invalid." }] },
    { egress: [{ host: "0x7f000001" }] }, { egress: [{ host: "127.0.0.1" }] },
    { egress: [{ host: "example.invalid", path_prefixes: ["prefix"] }] },
    { egress: [{ host: "example.invalid", path_prefixes: ["/prefix"] }] },
    { egress: [{ host: "example.invalid" }, { host: "example.invalid", path_prefixes: ["/other/"] }] },
    { egress: [{ host: "example.invalid", path_prefixes: ["/prefix?query"] }] },
    { egress: [{ host: "example.invalid", path_prefixes: ["/prefix/%2e/"] }] },
    { egress: [{ host: "example.invalid", path_prefixes: [] }] },
    { egress: [{ host: "example.invalid", secret: "value" }] },
    { other: 1 },
  ])("rejects invalid start fields %j", override => {
    expect(validateStart({ ...startRequest, ...override })).toBeUndefined();
  });
});

describe("Worker HTTP API", () => {
  function client(owned = true, authenticated = true) {
    const caller: Caller = { repositoryId: crypto.randomUUID(), workflowPath: "path", workflowSha: "01".repeat(20), run_id: "1", run_attempt: "1" };
    const claim = vi.fn<import("../src/run").Run["claim"]>(async () => owned ? "claimed" : "forbidden");
    const upload = vi.fn(async () => new Response(null, { status: 204 }));
    const token = vi.fn(async () => Response.json({ expires_at: "later" }));
    const noContent = async () => new Response(null, { status: 204 });
    const getByName = vi.fn(() => ({
      claim, upload, token, status: async () => ({}), destroy: noContent, output: noContent, stop: noContent,
    }));
    const env = { RUN: { getByName }, LEDGER: { getByName: () => ({ egress: noContent }) } } as unknown as Env;
    const app = createApp({
      verify: async () => authenticated ? { ok: true, caller } : { ok: false, error: "invalid_token" },
    });
    const send = async (path: string, init: RequestInit = {}) =>
      app.fetch!(new Request(`https://worker.invalid${path}`, init) as Parameters<NonNullable<typeof app.fetch>>[0],
        env, {} as ExecutionContext);
    return { send, getByName, claim, upload, token };
  }

  it("applies auth before routing and does not contact a Durable Object on 401, 404, or 405", async () => {
    const anonymous = client(true, false);
    expect((await anonymous.send("/missing")).status).toBe(401);
    expect(anonymous.getByName).not.toHaveBeenCalled();
    const authorized = client();
    expect((await authorized.send(base + "/missing")).status).toBe(404);
    const mismatch = await authorized.send(base + "/start");
    expect(mismatch.status).toBe(405);
    expect(mismatch.headers.get("allow")).toBe("POST");
    expect(authorized.getByName).not.toHaveBeenCalled();
  });

  it("rejects a run owned by a different repository", async () => {
    const { send, claim } = client(false);
    expect((await send(base)).status).toBe(403);
    expect(claim).toHaveBeenCalledOnce();
  });

  it("checks workflow-run ownership only on input-mutating routes", async () => {
    const { send, claim, upload, token } = client();
    claim.mockImplementation(async (_id, _caller, changesInputs) => changesInputs ? "wrong_run" : "claimed");
    const file = await send(base + "/files/task.md", { method: "PUT" });
    const start = await send(base + "/start", { method: "POST" });
    expect(file.status).toBe(403);
    expect(start.status).toBe(403);
    expect(await file.json()).toMatchObject({ error: "wrong_run" });
    expect(await start.json()).toMatchObject({ error: "wrong_run" });
    expect(upload).not.toHaveBeenCalled();
    const recovery = await send(base + "/token", {
      method: "PUT", body: JSON.stringify({ access_token: crypto.randomUUID(), expires_in: 30 }),
    });
    expect(recovery.status).toBe(200);
    expect(token).toHaveBeenCalledOnce();
    const cases = [
      [base, "GET"], [base, "DELETE"], [base + "/egress", "GET"],
      [base + "/outputs/patch.diff", "GET"], [base + "/stop", "POST"],
    ] as const;
    for (const [path, method] of cases) {
      const response = await send(path, { method, ...(method === "POST" ? { body: '{"reason":"cancelled"}' } : {}) });
      expect(response.ok).toBe(true);
      expect(claim).toHaveBeenLastCalledWith(id, expect.any(Object), false);
    }
  });

  it("requires Content-Length and enforces the 95 MiB limit before forwarding", async () => {
    const { send, upload } = client();
    const file = `${base}/files/task.md`;
    expect((await send(file, { method: "PUT" })).status).toBe(411);
    expect((await send(file, { method: "PUT", headers: { "content-length": "-12" } })).status).toBe(400);
    expect((await send(file, { method: "PUT", headers: { "content-length": String(MAX_UPLOAD_BYTES + 1) } })).status).toBe(413);
    expect(upload).not.toHaveBeenCalled();
    expect((await send(file, {
      method: "PUT", headers: { "content-length": String(MAX_UPLOAD_BYTES) }, body: "test",
    })).status).toBe(204);
    expect(upload).toHaveBeenCalledWith("task.md", expect.any(ReadableStream), MAX_UPLOAD_BYTES);
  });

  it("validates token expiry, length and characters", async () => {
    const { send, token } = client();
    const path = `${base}/token`;
    const access_token = crypto.randomUUID();
    for (const invalid of [
      { access_token: access_token.slice(0, 19), expires_in: 30 },
      { access_token: access_token.repeat(114), expires_in: 30 },
      { access_token: access_token + " a", expires_in: 30 },
      { access_token: access_token + "\x1f", expires_in: 30 },
      { access_token, expires_in: 29 },
      { access_token, expires_in: 86401 },
      { access_token, expires_in: 100.5 },
      { access_token, expires_in: "30" },
      { access_token, expires_in: 30, extra: true },
    ]) {
      expect((await send(path, { method: "PUT", body: JSON.stringify(invalid) })).status).toBe(400);
    }
    expect(token).not.toHaveBeenCalled();
    for (const expires_in of [30, 86400]) {
      expect((await send(path, { method: "PUT", body: JSON.stringify({ access_token, expires_in }) })).status).toBe(200);
      expect(token).toHaveBeenLastCalledWith(access_token, expires_in);
    }
  });
});
