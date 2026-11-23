import "./runtime";
import { DatabaseSync } from "node:sqlite";
import { describe, expect, it, vi } from "vitest";
import { countEgress, Ledger, LOG_LIMIT, TokenMemory } from "../src/ledger";
import type { EgressEntry, Env } from "../src/types";
import { ZERO_USAGE } from "../src/usage";
import { startRequest } from "./fixtures";

const event: EgressEntry = {
  t: new Date(0).toISOString(), method: "GET", scheme: "https",
  host: "example.invalid", path: "/", query_bytes: 0, decision: "deny",
};

describe("egress log limits", () => {
  it("keeps only the first 5,000 rows and first 50 distinct denied hosts", () => {
    let current = countEgress(undefined, event);
    for (let index = 0; index < 50; index++) {
      current = countEgress(current, { ...event, host: `host-${index}.invalid` });
    }
    current = countEgress(current, event);
    for (let index = current.stored; index < LOG_LIMIT; index++) {
      current = countEgress(current, { ...event, decision: "allow" });
    }
    current = countEgress(current, { ...event, decision: "llm" });
    current = countEgress(current, { ...event, host: "later.invalid" });
    expect(current).toMatchObject({ stored: LOG_LIMIT, allowed: LOG_LIMIT - 52, denied: 53, llm: 1, dropped: 2 });
    expect(current.denied_hosts).toHaveLength(50);
    expect(current.denied_hosts).not.toContain("host-49.invalid");
    expect(current.denied_hosts).not.toContain("later.invalid");
  });

  it("never puts a credential in token status or serialization", () => {
    const memory = new TokenMemory();
    const token = crypto.randomUUID();
    const status = memory.set(token, 30, 0);
    expect(status).toEqual({ present: true, expires_at: new Date(30_000).toISOString() });
    expect(memory.authorize(29_999)).toEqual({ ok: true, token });
    expect(memory.authorize(30_000)).toEqual({ ok: false, reason: "token_expired" });
    expect(memory.status(30_000).present).toBe(false);
    expect(JSON.stringify({ memory, status })).not.toContain(token);
    memory.clear();
    expect(memory.status(0)).toEqual({ present: false, expires_at: null });
  });
});

function setup() {
  const data = new Map<string, unknown>();
  const db = new DatabaseSync(":memory:");
  const kv = { get: data.get.bind(data), put: data.set.bind(data) };
  const sql = {
    exec(query: string, ...bindings: (string | number)[]) {
      const statement = db.prepare(query);
      if (query.startsWith("SELECT")) return { toArray: () => statement.all(...bindings) };
      return statement.run(...bindings);
    },
  };
  const storage = { kv, sql, transactionSync: (transaction: () => unknown) => transaction() };
  const create = () => new Ledger({ storage } as unknown as DurableObjectState, {} as Env);
  return { create, data, close: () => db.close() };
}

describe("Ledger metering and authorization", () => {
  it("persists exact totals, denies a spent budget and clears only the credential", async () => {
    const { create, data, close } = setup();
    try {
      const ledger = create();
      const token = crypto.randomUUID();
      expect(ledger.authorize(true)).toEqual({ ok: false, reason: "run_not_running" });
      const set = ledger.setToken(token, 30);
      expect(set?.present).toBe(true);
      const { model, egress, prices } = startRequest;
      expect(ledger.configure({ model, egress }, { ...prices, output: 0.25 }, 1)).toBe(true);
      expect(ledger.authorize(true)).toEqual({ ok: true, token });

      const llm = { ...event, decision: "llm", reason: "recorded" } as const;
      const row = ledger.record(llm);
      expect(row).toBe(1);
      ledger.meter({ tokens: { ...ZERO_USAGE, output_tokens: 1 }, unmetered: false, responseBytes: 10 }, llm, row);
      const secondRow = ledger.record(llm);
      ledger.meter({ tokens: { ...ZERO_USAGE, output_tokens: 1 }, unmetered: true, responseBytes: 11 }, llm, secondRow);
      expect(ledger.status().usage).toMatchObject({ requests: 2, cost_microcents: 1, unmetered_responses: 1 });
      expect(ledger.budgetExhausted()).toBe(false);
      ledger.meter({ tokens: { ...ZERO_USAGE, output_tokens: 3_999_998 }, unmetered: false, responseBytes: 0 }, llm, null);
      expect(ledger.status().usage.cost_microcents).toBe(1_000_000);
      expect(ledger.authorize(true)).toEqual({ ok: false, reason: "budget_exhausted" });
      expect(ledger.authorize(false)).toEqual({ ok: true, token });

      const restarted = create();
      expect(restarted.status().token.present).toBe(false);
      expect(restarted.budgetExhausted()).toBe(true);
      expect(JSON.stringify({ state: [...data], status: ledger.status() })).not.toContain(token);
      ledger.deactivate(true);
      expect(ledger.setToken(token, 30)).toBeNull();
      expect(ledger.status().token).toEqual({ present: false, expires_at: null });
      const egressLog = ledger.egress();
      expect(egressLog.headers.get("x-egress-dropped")).toBe("0");
      const [first, second] = (await egressLog.text()).trim().split("\n").map(line => JSON.parse(line) as unknown);
      expect(first).toMatchObject({ response_bytes: 10, usage: { output_tokens: 1, unmetered_responses: 0 } });
      expect(second).toMatchObject({ response_bytes: 11, usage: { output_tokens: 1, unmetered_responses: 1 } });
    } finally {
      close();
    }
  });

  it("preserves the expired-token error until the token is refreshed", () => {
    const { create, close } = setup();
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      const ledger = create();
      const { model, egress, prices } = startRequest;
      ledger.configure({ model, egress }, prices, 1);
      const token = crypto.randomUUID();
      const now = Date.now();
      ledger.setToken(token, 30);
      vi.setSystemTime(now + 30_000);
      expect(ledger.authorize(true)).toEqual({ ok: false, reason: "token_expired" });
      const refreshed = crypto.randomUUID();
      ledger.setToken(refreshed, 30);
      expect(ledger.authorize(true)).toEqual({ ok: true, token: refreshed });
    } finally {
      vi.useRealTimers();
      close();
    }
  });
});
