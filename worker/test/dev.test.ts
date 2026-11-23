import "./runtime";
import { expect, it, vi } from "vitest";
import app, { Outbound } from "../src/dev";
import type { OutboundLedger } from "../src/outbound";
import type { Env, Reservation } from "../src/types";
import { startRequest } from "./fixtures";

vi.mock("@cloudflare/sandbox", () => ({ Files: class {}, SandboxFileError: class {} }));

it.each(["match", "mismatch"] as const)("reports a bearer %s without exposing it", async expected => {
  const token = crypto.randomUUID();
  const ledger = {
    rules: () => startRequest,
    authorize: (reservation?: Reservation) => ({ ok: true, token: reservation || expected === "match" ? token : crypto.randomUUID() } as const),
    record: vi.fn(() => 1), recordFailure: vi.fn(), meter: vi.fn(), flagMeteringFailure: vi.fn(),
  } satisfies OutboundLedger;
  const pending: Promise<unknown>[] = [];
  const ctx = {
    props: { runId: "p0-20261123T012345Z-abcdef12" },
    waitUntil(promise: Promise<unknown>) { pending.push(promise); },
  } as ExecutionContext;
  const env = { LEDGER: { getByName: () => ledger } } as unknown as Env;
  const outbound = new Outbound(ctx, env);
  const response = await outbound.fetch(new Request("https://api.anthropic.com/v1/messages", {
    method: "POST", body: JSON.stringify({ model: startRequest.model, max_tokens: 512 }),
  }));
  expect(response.headers.get("x-dev-saw-bearer")).toBe(expected);
  const events = await response.text();
  expect(events).toContain("event: message_stop");
  expect(events).not.toContain(token);
  expect(JSON.stringify([...response.headers])).not.toContain(token);
  await Promise.all(pending);
  expect(ledger.meter).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({
    tokens: expect.objectContaining({ input_tokens: 1000, output_tokens: 500 }),
  }), expect.any(Object), 1);
});

it.each(["evil.invalid", "localhost.evil.invalid", "127.0.0.1.evil.invalid", "localhost:abc", "localhost:1:2", "localhost:65536",
  "localhost, evil.invalid", "[::1]", ""])("rejects local HTTP Host %j before authenticating", async host => {
  const response = await app.fetch(new Request("http://localhost/runs", { headers: { host } }) as Parameters<typeof app.fetch>[0],
    {} as Env, {} as ExecutionContext);
  expect(response.status).toBe(404);
});

it.each(["localhost", "localhost:8787", "127.0.0.1", "127.0.0.1:8787"])(
  "permits local HTTP Host %s", async host => {
    const response = await app.fetch(new Request("http://localhost/runs", { headers: { host } }) as Parameters<typeof app.fetch>[0],
      {} as Env, {} as ExecutionContext);
    expect(response.status).toBe(500); // The request reached the verifier with no OIDC configuration.
  },
);
