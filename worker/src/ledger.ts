import { DurableObject } from "cloudflare:workers";
import type {
  Authorization, EgressEntry, EgressSummary, Env, LedgerStatus, Prices, Rules, TokenInfo, Usage,
} from "./types";
import { costMicrocents, exactCost, jsonInteger, microcents, type Metering, ZERO_USAGE } from "./usage";

export const LOG_LIMIT = 5_000;
const DENIED_HOST_LIMIT = 50;
const SUMMARY_KEY = "egress";
const USAGE_KEY = "usage";
const RULES_KEY = "rules";
const EMPTY_EGRESS: EgressSummary = { allowed: 0, denied: 0, llm: 0, dropped: 0, denied_hosts: [] };

interface EgressCounters extends EgressSummary {
  stored: number;
}

export function countEgress(current: EgressCounters | undefined, entry: EgressEntry): EgressCounters {
  const next = { ...(current ?? { ...EMPTY_EGRESS, stored: 0 }) };
  if (entry.decision === "deny") {
    next.denied += 1;
    if (entry.host && next.denied_hosts.length < DENIED_HOST_LIMIT && !next.denied_hosts.includes(entry.host)) {
      next.denied_hosts = [...next.denied_hosts, entry.host];
    }
  } else if (entry.decision === "llm") {
    next.llm += 1;
  } else {
    next.allowed += 1;
  }
  if (next.stored < LOG_LIMIT) next.stored += 1;
  else next.dropped += 1;
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

  rules(): Rules | null {
    return this.ctx.storage.kv.get<Config>(RULES_KEY)?.rules ?? null;
  }

  authorize(checkBudget: boolean): Authorization {
    const kv = this.ctx.storage.kv;
    if (kv.get("inactive") || !kv.get(RULES_KEY)) return { ok: false, reason: "run_not_running" };
    if (checkBudget && this.budgetExhausted()) return { ok: false, reason: "budget_exhausted" };
    return this.#token.authorize(Date.now());
  }

  budgetExhausted(): boolean {
    return this.ctx.storage.kv.get<MeterTotals>(USAGE_KEY)?.exhausted === true
      || this.ctx.storage.kv.get("metering_failed") === true;
  }

  record(entry: EgressEntry): number | null {
    return this.ctx.storage.transactionSync(() => {
      const previous = this.ctx.storage.kv.get<EgressCounters>(SUMMARY_KEY);
      const next = countEgress(previous, entry);
      this.ctx.storage.kv.put(SUMMARY_KEY, next);
      if (next.stored === previous?.stored) return null;
      this.ctx.storage.sql.exec("INSERT INTO egress (id, entry) VALUES (?, ?)", next.stored, JSON.stringify(entry));
      return next.stored;
    });
  }

  recordFailure(): void {
    const summary = this.ctx.storage.kv.get<EgressCounters>(SUMMARY_KEY) ?? { ...EMPTY_EGRESS, stored: 0 };
    this.ctx.storage.kv.put(SUMMARY_KEY, { ...summary, dropped: summary.dropped + 1 });
  }

  flagMeteringFailure(): void {
    this.ctx.storage.kv.put("metering_failed", true);
  }

  meter(sample: Metering, entry: EgressEntry, row: number | null): void {
    this.ctx.storage.transactionSync(() => {
      const kv = this.ctx.storage.kv;
      const config = kv.get<Config>(RULES_KEY);
      if (!config) throw new Error("Missing metering configuration");
      const { prices, budgetCents } = config;
      const previous = kv.get<MeterTotals>(USAGE_KEY);
      const { tokens, unmetered, responseBytes } = sample;
      const { units, denominator } = exactCost(tokens, prices);
      const total = BigInt(previous?.units ?? "0") + units;
      const cost = microcents(total, denominator);
      const usage = { ...(previous?.usage ?? ZERO_USAGE) };
      for (const field of Object.keys(tokens) as (keyof typeof tokens)[]) {
        usage[field] = jsonInteger(BigInt(usage[field]) + BigInt(tokens[field]));
      }
      usage.requests += 1;
      usage.unmetered_responses += Number(unmetered);
      usage.cost_microcents = jsonInteger(cost);
      kv.put(USAGE_KEY, {
        usage, units: total.toString(), exhausted: cost >= BigInt(budgetCents) * 1_000_000n,
      } satisfies MeterTotals);
      if (row !== null) {
        const detail: Usage = {
          ...tokens, requests: 1, cost_microcents: costMicrocents(tokens, prices),
          unmetered_responses: Number(unmetered),
        };
        const updated = { ...entry, response_bytes: responseBytes, usage: detail };
        this.ctx.storage.sql.exec("UPDATE egress SET entry = ? WHERE id = ?", JSON.stringify(updated), row);
      }
    });
  }

  status(): LedgerStatus {
    const { allowed, denied, llm, dropped, denied_hosts } =
      this.ctx.storage.kv.get<EgressCounters>(SUMMARY_KEY) ?? EMPTY_EGRESS;
    return {
      token: this.tokenStatus(),
      usage: this.ctx.storage.kv.get<MeterTotals>(USAGE_KEY)?.usage ?? ZERO_USAGE,
      budget_exhausted: this.budgetExhausted(),
      egress: { allowed, denied, llm, dropped, denied_hosts },
    };
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
