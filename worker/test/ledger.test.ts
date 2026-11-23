import "./runtime";
import { DatabaseSync } from "node:sqlite";
import { describe, expect, it, vi } from "vitest";
import { countEgress, DENY_LOG_LIMIT, Ledger, LOG_LIMIT, TokenMemory } from "../src/ledger";
import { handle } from "../src/outbound";
import type { EgressEntry, Env } from "../src/types";
import { ZERO_USAGE } from "../src/usage";
import { startRequest } from "./fixtures";

const event: EgressEntry = {
  t: new Date(0).toISOString(), method: "GET", scheme: "https",
  host: "example.invalid", path: "/", query_bytes: 0, decision: "deny",
};

describe("egress log limits", () => {
  it("caps deny and allow/llm rows independently and keeps the first 50 distinct denied hosts", () => {
    let current = countEgress(undefined, event);
    for (let index = 0; index < 50; index++) {
      current = countEgress(current, { ...event, host: `host-${index}.invalid` });
    }
    for (let index = current.denied; index < DENY_LOG_LIMIT; index++) {
      current = countEgress(current, event);
    }
    current = countEgress(current, { ...event, host: "later.invalid" });
    for (let index = 0; index < LOG_LIMIT - 1; index++) {
      current = countEgress(current, { ...event, decision: "allow" });
    }
    current = countEgress(current, { ...event, decision: "llm" });
    current = countEgress(current, { ...event, decision: "allow" });
    current = countEgress(current, { ...event, decision: "llm" });
    expect(current).toMatchObject({
      stored: DENY_LOG_LIMIT + LOG_LIMIT, allowed: LOG_LIMIT, denied: DENY_LOG_LIMIT + 1,
      llm: 2, dropped: 3, dropped_deny: 1, dropped_other: 2,
    });
    expect(current.denied_hosts).toHaveLength(50);
    expect(current.denied_hosts).not.toContain("host-49.invalid");
    expect(current.denied_hosts).not.toContain("later.invalid");
  });

  it("reports stored rows and total drops after a deny flood", async () => {
    const { create, close } = setup();
    try {
      const ledger = create();
      for (let index = 0; index <= DENY_LOG_LIMIT; index++) ledger.record(event);
      for (let index = 0; index <= LOG_LIMIT; index++) ledger.record({ ...event, decision: "llm" });
      const response = ledger.egress();
      expect(response.headers.get("x-egress-dropped")).toBe("2");
      expect((await response.text()).trim().split("\n")).toHaveLength(DENY_LOG_LIMIT + LOG_LIMIT);
      expect(ledger.status().egress).toMatchObject({ dropped: 2, dropped_deny: 1, dropped_other: 1 });
    } finally {
      close();
    }
  });

  it("applies the split caps to persisted logs from the previous schema", async () => {
    const { create, data, storage, close } = setup();
    try {
      create();
      const oldDenied = DENY_LOG_LIMIT + 2;
      for (let index = 0; index < oldDenied; index++) {
        storage.sql.exec("INSERT INTO egress (entry) VALUES (?)", JSON.stringify(event));
      }
      storage.sql.exec("INSERT INTO egress (entry) VALUES (?)", JSON.stringify(llm));
      data.set("egress", { stored: oldDenied + 1, denied: oldDenied, llm: 1, allowed: 1, dropped: 1, denied_hosts: [] });
      const ledger = create();
      expect(ledger.status().egress).toMatchObject({ dropped: 3, dropped_deny: 2, dropped_other: 1 });
      expect(ledger.record(event)).toBeNull();
      expect(ledger.record(llm)).not.toBeNull();
      expect((await ledger.egress().text()).trim().split("\n")).toHaveLength(DENY_LOG_LIMIT + 2);
    } finally {
      close();
    }
  });

  it("counts back-pressure refusals as throttled without logging a deny or a denied host", async () => {
    const { create, close } = setup();
    try {
      // #given
      const ledger = create();
      const refusal = { ...event, host: "api.anthropic.com", status: 429 };
      // #when
      for (const reason of ["too_many_inflight", "budget_reserved"]) {
        expect(ledger.record({ ...refusal, reason })).toBeNull();
      }
      // #then
      expect(ledger.status().egress).toMatchObject({ throttled: 2, denied: 0, dropped: 0, denied_hosts: [] });
      expect(await ledger.egress().text()).toBe("");
    } finally {
      close();
    }
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
      if (query.startsWith("SELECT") || query.includes(" RETURNING ")) return { toArray: () => statement.all(...bindings) };
      return statement.run(...bindings);
    },
  };
  const storage = {
    kv, sql, setAlarm: vi.fn(async (_at: number) => {}),
    transactionSync<T>(transaction: () => T): T {
      const snapshot = new Map(data);
      db.exec("BEGIN");
      try {
        const result = transaction();
        db.exec("COMMIT");
        return result;
      } catch (error) {
        db.exec("ROLLBACK");
        data.clear();
        for (const [key, value] of snapshot) data.set(key, value);
        throw error;
      }
    },
  };
  const create = () => new Ledger({ storage } as unknown as DurableObjectState, {} as Env);
  return { create, data, storage, close: () => db.close() };
}

const reservation = (request_id: string, estimate_microcents = 1) => ({ request_id, estimate_microcents });
const llm = { ...event, decision: "llm", reason: "recorded" } as const;

describe("Ledger metering and authorization", () => {
  it("serializes requests near the budget and admits a lone request above the remaining budget", async () => {
    const { create, close } = setup();
    try {
      const ledger = create();
      const { model, egress, prices } = startRequest;
      ledger.configure({ model, egress }, prices, 1);
      ledger.setToken(crypto.randomUUID(), 30);
      expect((await ledger.authorize(reservation("settled", 200_000))).ok).toBe(true);
      ledger.meter("settled", "failure", llm, null);

      const next = reservation("next", 400_000);
      const [first, blocked] = await Promise.all([ledger.authorize(reservation("first", 500_000)), ledger.authorize(next)]);
      expect(first.ok).toBe(true);
      expect(blocked).toEqual({ ok: false, reason: "budget_reserved" });
      ledger.meter("first", "zero", llm, null);
      expect((await ledger.authorize(next)).ok).toBe(true);
      expect((await ledger.authorize(reservation("equal", 400_000))).ok).toBe(true);
      expect(await ledger.authorize(reservation("over"))).toEqual({ ok: false, reason: "budget_reserved" });
      ledger.meter("next", "zero", llm, null);
      ledger.meter("equal", "zero", llm, null);

      expect((await ledger.authorize(reservation("lone", 900_000))).ok).toBe(true);
      ledger.meter("lone", "failure", llm, null);
      expect(await ledger.authorize(reservation("spent"))).toEqual({ ok: false, reason: "budget_exhausted" });
    } finally {
      close();
    }
  });

  it("persists exact totals, denies a spent budget and clears only the credential", async () => {
    const { create, data, close } = setup();
    try {
      const ledger = create();
      const token = crypto.randomUUID();
      expect(await ledger.authorize(reservation("first"))).toEqual({ ok: false, reason: "run_not_running" });
      const set = ledger.setToken(token, 30);
      expect(set?.present).toBe(true);
      const { model, egress, prices } = startRequest;
      expect(ledger.configure({ model, egress }, { ...prices, output: 0.25 }, 1)).toBe(true);
      expect(await ledger.authorize(reservation("first"))).toEqual({ ok: true, token });

      const row = ledger.record(llm);
      expect(row).toBe(1);
      ledger.meter("first", { tokens: { ...ZERO_USAGE, output_tokens: 1 }, unmetered: false, responseBytes: 10 }, llm, row);
      await ledger.authorize(reservation("second", 2));
      const secondRow = ledger.record(llm);
      ledger.meter("second", { tokens: { ...ZERO_USAGE, output_tokens: 1 }, unmetered: true, responseBytes: 11 }, llm, secondRow);
      expect(ledger.status().usage).toMatchObject({ requests: 2, cost_microcents: 3, unmetered_responses: 1 });
      expect(ledger.budgetExhausted()).toBe(false);
      await ledger.authorize(reservation("third"));
      ledger.meter("third", { tokens: { ...ZERO_USAGE, output_tokens: 3_999_991 }, unmetered: false, responseBytes: 0 }, llm, null);
      expect(ledger.status().usage.cost_microcents).toBe(1_000_000);
      expect(await ledger.authorize(reservation("denied"))).toEqual({ ok: false, reason: "budget_exhausted" });
      expect(await ledger.authorize()).toEqual({ ok: true, token });

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

  it("reports the reserved estimate and the age of the oldest reservation", async () => {
    const { create, close } = setup();
    vi.useFakeTimers({ toFake: ["Date"] });
    try {
      // #given
      const ledger = create();
      const { model, egress, prices } = startRequest;
      ledger.configure({ model, egress }, prices, 1);
      ledger.setToken(crypto.randomUUID(), 300);
      expect(ledger.status().usage).toMatchObject({ reserved_microcents: 0, oldest_inflight_seconds: 0 });
      const now = Date.now();
      // #when
      await ledger.authorize(reservation("old", 300));
      vi.setSystemTime(now + 4_000);
      await ledger.authorize(reservation("new", 200));
      vi.setSystemTime(now + 7_500);
      // #then
      expect(ledger.status().usage).toMatchObject({ inflight: 2, reserved_microcents: 500, oldest_inflight_seconds: 7 });
    } finally {
      vi.useRealTimers();
      close();
    }
  });

  it("preserves the expired-token error until the token is refreshed", async () => {
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
      expect(await ledger.authorize(reservation("request"))).toEqual({ ok: false, reason: "token_expired" });
      const refreshed = crypto.randomUUID();
      ledger.setToken(refreshed, 30);
      expect(await ledger.authorize(reservation("request"))).toEqual({ ok: true, token: refreshed });
    } finally {
      vi.useRealTimers();
      close();
    }
  });
});

it("admits four of six concurrent reservations and frees a slot exactly once", async () => {
  const { create, close } = setup();
  try {
    const ledger = create();
    const { model, egress, prices } = startRequest;
    ledger.configure({ model, egress }, prices, 1);
    ledger.setToken(crypto.randomUUID(), 30);
    const batch = await Promise.all(Array.from({ length: 6 }, (_, id) => ledger.authorize(reservation(String(id)))));
    expect(batch.filter(result => result.ok)).toHaveLength(4);
    expect(batch.filter(result => !result.ok)).toEqual([
      { ok: false, reason: "too_many_inflight" }, { ok: false, reason: "too_many_inflight" },
    ]);
    expect(ledger.status().usage).toMatchObject({ inflight: 4, late_settlements: 0 });
    ledger.meter("0", "failure", llm, null);
    expect((await ledger.authorize(reservation("new"))).ok).toBe(true);
    ledger.meter("0", "failure", llm, null);
    ledger.meter("unknown", "failure", llm, null);
    expect(ledger.status().usage).toMatchObject({
      inflight: 4, late_settlements: 2, cost_microcents: 1, unmetered_responses: 1,
    });
  } finally {
    close();
  }
});

it("sweeps persisted reservations after 20 minutes and refuses an exhausted budget", async () => {
  const { create, storage, close } = setup();
  vi.useFakeTimers({ toFake: ["Date"] });
  try {
    const ledger = create();
    const { model, egress, prices } = startRequest;
    ledger.configure({ model, egress }, prices, 1);
    ledger.setToken(crypto.randomUUID(), 3600);
    const start = Date.now();
    const expiry = start + 20 * 60_000;
    await ledger.authorize(reservation("first", 999_991));
    vi.setSystemTime(start + 10_000);
    await ledger.authorize(reservation("second", 9));
    expect(storage.setAlarm).toHaveBeenLastCalledWith(expiry);
    const restarted = create();
    vi.setSystemTime(expiry - 1);
    expect(restarted.status().usage).toMatchObject({ inflight: 2, cost_microcents: 0 });
    vi.setSystemTime(expiry);
    await restarted.alarm();
    expect(storage.setAlarm).toHaveBeenLastCalledWith(expiry + 10_000);
    expect(restarted.status().usage).toMatchObject({ inflight: 1, cost_microcents: 999_991, unmetered_responses: 1 });
    vi.setSystemTime(expiry + 10_000);
    await restarted.alarm();
    expect(restarted.status().usage).toMatchObject({ inflight: 0, cost_microcents: 1_000_000, unmetered_responses: 2 });
    expect(await restarted.authorize(reservation("denied"))).toEqual({ ok: false, reason: "budget_exhausted" });
  } finally {
    vi.useRealTimers();
    close();
  }
});

it.each([false, true])("handles a guest abort when the upstream stalls = %s", async stalls => {
  const { create, close } = setup();
  vi.useFakeTimers({ toFake: ["Date"] });
  try {
    const ledger = create();
    const { model, egress, prices } = startRequest;
    ledger.configure({ model, egress }, prices, 300);
    ledger.setToken(crypto.randomUUID(), 3600);
    const pending: Promise<unknown>[] = [];
    let source!: ReadableStreamDefaultController<Uint8Array>;
    const upstreamBody = new ReadableStream<Uint8Array>({ start(controller) { source = controller; } });
    const body = JSON.stringify({ model, max_tokens: 100 });
    const response = await handle(new Request("https://api.anthropic.com/v1/messages", { method: "POST", body }), {
      ledger, upstream: async () => new Response(upstreamBody, { headers: { "content-type": "application/json" } }),
      now: Date.now, waitUntil: promise => { pending.push(promise); },
    });
    expect(response.status).toBe(200);
    expect(ledger.status().usage.inflight).toBe(1);
    const cancelled = response.body!.cancel();
    if (stalls) {
      vi.setSystemTime(Date.now() + 20 * 60_000);
      await ledger.alarm();
      expect(ledger.status().usage).toMatchObject({
        inflight: 0, cost_microcents: Math.ceil(Math.ceil(body.length / 3) * prices.input + 100 * prices.output),
        unmetered_responses: 1, late_settlements: 0,
      });
    }
    source.enqueue(new TextEncoder().encode('{"usage":{"input_tokens":4,"output_tokens":3}}'));
    source.close();
    await Promise.all([...pending, cancelled]);
    expect(ledger.status().usage).toMatchObject({
      inflight: 0, late_settlements: Number(stalls), unmetered_responses: Number(stalls), requests: 1,
    });
    if (!stalls) expect(ledger.status().usage).toMatchObject({ input_tokens: 4, output_tokens: 3 });
  } finally {
    vi.useRealTimers();
    close();
  }
});
