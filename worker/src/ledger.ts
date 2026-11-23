import { DurableObject } from "cloudflare:workers";
import type {
  Authorization, EgressEntry, EgressSummary, Env, LedgerStatus, PricedRules, Prices, Reservation, Rules, TokenInfo, Usage,
} from "./types";
import { exactCost, jsonInteger, microcents, type Settlement, ZERO_USAGE } from "./usage";

export const LOG_LIMIT = 5_000;
export const DENY_LOG_LIMIT = 2_000;
const DENIED_HOST_LIMIT = 50;
const INFLIGHT_LIMIT = 4;
const RESERVATION_MS = 20 * 60_000;
const SUMMARY_KEY = "egress";
const USAGE_KEY = "usage";
const RULES_KEY = "rules";
const LATE_KEY = "late_settlements";
const EMPTY_EGRESS: EgressSummary = {
  allowed: 0, denied: 0, llm: 0, dropped: 0, dropped_deny: 0, dropped_other: 0, denied_hosts: [],
};

interface EgressCounters extends EgressSummary {
  stored: number;
  stored_deny: number;
}

export function countEgress(
  current: EgressCounters | undefined, entry: EgressEntry, canStore = true,
): EgressCounters {
  const next = { ...(current ?? { ...EMPTY_EGRESS, stored: 0, stored_deny: 0 }) };
  if (entry.decision === "deny") {
    next.denied += 1;
    if (entry.host && next.denied_hosts.length < DENIED_HOST_LIMIT && !next.denied_hosts.includes(entry.host)) {
      next.denied_hosts = [...next.denied_hosts, entry.host];
    }
    if (canStore && next.stored_deny < DENY_LOG_LIMIT) {
      next.stored_deny += 1;
      next.stored += 1;
    } else {
      next.dropped_deny += 1;
    }
  } else {
    if (entry.decision === "llm") next.llm += 1;
    else next.allowed += 1;
    if (canStore && next.stored - next.stored_deny < LOG_LIMIT) next.stored += 1;
    else next.dropped_other += 1;
  }
  next.dropped = next.dropped_deny + next.dropped_other;
  return next;
}

export class TokenMemory {
  #value: { token: string; expiresAt: number } | undefined;

  set(token: string, seconds: number, now: number): TokenInfo {
    this.#value = { token, expiresAt: now + seconds * 1000 };
    return this.status(now);
  }

  status(now: number): TokenInfo {
    const expiresAt = this.#value?.expiresAt;
    return { present: expiresAt !== undefined && expiresAt > now, expires_at: expiresAt === undefined
      ? null : new Date(expiresAt).toISOString() };
  }

  authorize(now: number): Authorization {
    if (!this.#value) return { ok: false, reason: "no_token" };
    if (this.#value.expiresAt <= now) return { ok: false, reason: "token_expired" };
    return { ok: true, token: this.#value.token };
  }

  clear(): void {
    this.#value = undefined;
  }
}

interface Config {
  rules: Rules;
  prices: Prices;
  budgetCents: number;
}

interface MeterTotals {
  usage: Usage;
  units: string;
  exhausted: boolean;
}

export class Ledger extends DurableObject<Env> {
  readonly #token = new TokenMemory();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec("CREATE TABLE IF NOT EXISTS egress (id INTEGER PRIMARY KEY, entry TEXT NOT NULL)");
    ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS inflight (
      request_id TEXT PRIMARY KEY, estimate_microcents INTEGER NOT NULL, started_at INTEGER NOT NULL
    )`);
    this.#migrateEgress();
  }

  setToken(token: string, seconds: number): TokenInfo | null {
    if (this.ctx.storage.kv.get("closed")) return null;
    return this.#token.set(token, seconds, Date.now());
  }

  tokenStatus(): TokenInfo {
    return this.#token.status(Date.now());
  }

  configure(rules: Rules, prices: Prices, budgetCents: number): boolean {
    const kv = this.ctx.storage.kv;
    if (kv.get("closed") || kv.get(RULES_KEY)) return false;
    kv.put(RULES_KEY, { rules, prices, budgetCents } satisfies Config);
    return true;
  }

  deactivate(destroy: boolean): void {
    if (destroy) {
      this.#token.clear();
      this.ctx.storage.kv.put("closed", true);
    }
    this.ctx.storage.kv.put("inactive", true);
  }

  rules(): PricedRules | "inactive" | null {
    const kv = this.ctx.storage.kv;
    if (kv.get("inactive")) return "inactive";
    const config = kv.get<Config>(RULES_KEY);
    return config ? { ...config.rules, prices: config.prices } : null;
  }

  async authorize(reservation?: Reservation): Promise<Authorization> {
    const { kv, sql } = this.ctx.storage;
    const now = Date.now();
    const authorization = this.ctx.storage.transactionSync((): Authorization => {
      this.#sweep(now);
      const config = kv.get<Config>(RULES_KEY);
      if (kv.get("inactive") || !config) return { ok: false, reason: "run_not_running" };
      if (reservation) {
        const { count, reserved } = this.#inflight();
        if (count >= INFLIGHT_LIMIT) return { ok: false, reason: "too_many_inflight" };
        if (this.#exhausted()) return { ok: false, reason: "budget_exhausted" };
        const settled = kv.get<MeterTotals>(USAGE_KEY)?.usage.cost_microcents ?? 0;
        if (count > 0 && settled + reserved + reservation.estimate_microcents > config.budgetCents * 1_000_000) {
          return { ok: false, reason: "too_many_inflight" };
        }
      }
      const token = this.#token.authorize(now);
      if (reservation && token.ok) {
        sql.exec("INSERT INTO inflight VALUES (?, ?, ?)", reservation.request_id, reservation.estimate_microcents, now);
      }
      return token;
    });
    if (reservation && authorization.ok) await this.#scheduleSweep();
    return authorization;
  }

  #inflight(): { count: number; reserved: number } {
    return this.ctx.storage.sql.exec<{ count: number; reserved: number }>(
      "SELECT COUNT(*) AS count, COALESCE(SUM(estimate_microcents), 0) AS reserved FROM inflight",
    ).toArray()[0]!;
  }

  #sweep(now: number): void {
    const sql = this.ctx.storage.sql;
    const expired = sql.exec<{ request_id: string; estimate_microcents: number }>(
      "SELECT request_id, estimate_microcents FROM inflight WHERE started_at <= ?", now - RESERVATION_MS,
    ).toArray();
    for (const { request_id, estimate_microcents } of expired) {
      this.#addUsage("failure", estimate_microcents);
      sql.exec("DELETE FROM inflight WHERE request_id = ?", request_id);
    }
  }

  async #scheduleSweep(): Promise<void> {
    const oldest = this.ctx.storage.sql.exec<{ started_at: number }>(
      "SELECT started_at FROM inflight ORDER BY started_at LIMIT 1",
    ).toArray()[0];
    if (oldest) await this.ctx.storage.setAlarm(oldest.started_at + RESERVATION_MS);
  }

  override async alarm(): Promise<void> {
    this.ctx.storage.transactionSync(() => this.#sweep(Date.now()));
    await this.#scheduleSweep();
  }

  #exhausted(): boolean {
    return this.ctx.storage.kv.get<MeterTotals>(USAGE_KEY)?.exhausted === true
      || this.ctx.storage.kv.get("metering_failed") === true;
  }

  budgetExhausted(): boolean {
    return this.ctx.storage.transactionSync(() => {
      this.#sweep(Date.now());
      return this.#exhausted();
    });
  }

  #migrateEgress(): void {
    const { kv, sql } = this.ctx.storage;
    const previous = kv.get<EgressCounters>(SUMMARY_KEY);
    if (!previous || previous.stored_deny !== undefined) return;
    this.ctx.storage.transactionSync(() => {
      const deny = "json_extract(entry, '$.decision') = 'deny'";
      sql.exec(`DELETE FROM egress WHERE id IN (SELECT id FROM egress WHERE ${deny} ORDER BY id LIMIT -1 OFFSET ?)`,
        DENY_LOG_LIMIT);
      const { stored, stored_deny } = sql.exec<{ stored: number; stored_deny: number }>(
        `SELECT COUNT(*) AS stored, COUNT(CASE WHEN ${deny} THEN 1 END) AS stored_deny FROM egress`,
      ).toArray()[0]!;
      const dropped = Math.max(previous.dropped + previous.stored - stored,
        previous.denied + previous.allowed + previous.llm - stored);
      const dropped_deny = Math.max(0, previous.denied - stored_deny);
      kv.put(SUMMARY_KEY, { ...previous, stored, stored_deny, dropped, dropped_deny, dropped_other: dropped - dropped_deny });
    });
  }

  record(entry: EgressEntry): number | null {
    return this.ctx.storage.transactionSync(() => {
      const { kv, sql } = this.ctx.storage;
      const previous = kv.get<EgressCounters>(SUMMARY_KEY);
      const next = countEgress(previous, entry);
      kv.put(SUMMARY_KEY, next);
      if (next.stored === (previous?.stored ?? 0)) return null;
      return sql.exec<{ id: number }>("INSERT INTO egress (entry) VALUES (?) RETURNING id", JSON.stringify(entry))
        .toArray()[0]!.id;
    });
  }

  recordFailure(entry: EgressEntry): void {
    const kv = this.ctx.storage.kv;
    kv.put(SUMMARY_KEY, countEgress(kv.get<EgressCounters>(SUMMARY_KEY), entry, false));
  }

  flagMeteringFailure(): void {
    this.ctx.storage.kv.put("metering_failed", true);
  }

  #addUsage(sample: Exclude<Settlement, "zero">, estimate: number): Usage {
    const kv = this.ctx.storage.kv;
    const config = kv.get<Config>(RULES_KEY);
    if (!config) throw new Error("Missing metering configuration");
    const { prices, budgetCents } = config;
    const previous = kv.get<MeterTotals>(USAGE_KEY);
    const tokens = sample === "failure" ? ZERO_USAGE : sample.tokens;
    const unmetered = sample === "failure" || sample.unmetered;
    const { units, denominator } = exactCost(tokens, prices);
    const charge = unmetered ? BigInt(estimate) * denominator : units;
    const total = BigInt(previous?.units ?? "0") + charge;
    const cost = microcents(total, denominator);
    const usage = { ...(previous?.usage ?? ZERO_USAGE) };
    for (const field of ["input_tokens", "output_tokens", "cache_read_input_tokens",
      "cache_creation_5m_input_tokens", "cache_creation_1h_input_tokens"] as const) {
      usage[field] = jsonInteger(BigInt(usage[field]) + BigInt(tokens[field]));
    }
    usage.requests += 1;
    usage.unmetered_responses += Number(unmetered);
    usage.cost_microcents = jsonInteger(cost);
    kv.put(USAGE_KEY, {
      usage, units: total.toString(), exhausted: cost >= BigInt(budgetCents) * 1_000_000n,
    } satisfies MeterTotals);
    return { ...tokens, requests: 1, cost_microcents: jsonInteger(microcents(charge, denominator)),
      unmetered_responses: Number(unmetered) };
  }

  meter(requestId: string, sample: Settlement, entry: EgressEntry, row: number | null): void {
    this.ctx.storage.transactionSync(() => {
      const { kv, sql } = this.ctx.storage;
      this.#sweep(Date.now());
      const reservation = sql.exec<{ estimate_microcents: number }>(
        "SELECT estimate_microcents FROM inflight WHERE request_id = ?", requestId,
      ).toArray()[0];
      if (!reservation) {
        kv.put(LATE_KEY, (kv.get<number>(LATE_KEY) ?? 0) + 1);
        return;
      }
      sql.exec("DELETE FROM inflight WHERE request_id = ?", requestId);
      if (sample === "zero") return;
      const usage = this.#addUsage(sample, reservation.estimate_microcents);
      if (row !== null) {
        const updated = { ...entry, response_bytes: sample === "failure" ? undefined : sample.responseBytes, usage };
        sql.exec("UPDATE egress SET entry = ? WHERE id = ?", JSON.stringify(updated), row);
      }
    });
  }

  status(): LedgerStatus {
    return this.ctx.storage.transactionSync(() => {
      this.#sweep(Date.now());
      const kv = this.ctx.storage.kv;
      const { allowed, denied, llm, dropped, dropped_deny, dropped_other, denied_hosts } =
        kv.get<EgressCounters>(SUMMARY_KEY) ?? EMPTY_EGRESS;
      return {
        token: this.tokenStatus(),
        usage: {
          ...(kv.get<MeterTotals>(USAGE_KEY)?.usage ?? ZERO_USAGE),
          inflight: this.#inflight().count, late_settlements: kv.get<number>(LATE_KEY) ?? 0,
        },
        budget_exhausted: this.#exhausted(),
        egress: { allowed, denied, llm, dropped, dropped_deny, dropped_other, denied_hosts },
      };
    });
  }

  egress(): Response {
    const dropped = this.ctx.storage.kv.get<EgressCounters>(SUMMARY_KEY)?.dropped ?? 0;
    const rows = this.ctx.storage.sql.exec<{ entry: string }>("SELECT entry FROM egress ORDER BY id").toArray();
    const encoder = new TextEncoder();
    const iter = rows.values();
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        const row = iter.next();
        if (row.done) controller.close();
        else controller.enqueue(encoder.encode(row.value.entry + "\n"));
      },
    });
    return new Response(body, { headers: {
      "content-type": "application/x-ndjson", "x-egress-dropped": String(dropped),
    } });
  }
}
