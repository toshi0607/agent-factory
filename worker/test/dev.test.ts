import "./runtime";
import { expect, it, vi } from "vitest";
import { Outbound } from "../src/dev";
import type { OutboundLedger } from "../src/outbound";
import type { Env } from "../src/types";
import { startRequest } from "./fixtures";

vi.mock("@cloudflare/sandbox", () => ({ Files: class {}, SandboxFileError: class {} }));

it.each(["match", "mismatch"] as const)("reports a bearer %s without exposing it", async expected => {
  const token = crypto.randomUUID();
  const ledger = {
    rules: () => startRequest,
    authorize: (budget: boolean) => ({ ok: true, token: budget || expected === "match" ? token : crypto.randomUUID() } as const),
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
  expect(ledger.meter).toHaveBeenCalledWith(expect.objectContaining({
    tokens: expect.objectContaining({ input_tokens: 1000, output_tokens: 500 }),
  }), expect.any(Object), 1);
});
