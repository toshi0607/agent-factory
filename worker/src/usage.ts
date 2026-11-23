import { readBytes, readLines } from "./streams";
import { object, type Prices, type TokenCounts, type Usage } from "./types";

const MAX_JSON_BYTES = 4 * 1024 * 1024;
const MAX_EVENT_CHARS = 1024 * 1024;
const ZERO_TOKENS: TokenCounts = {
  input_tokens: 0,
  output_tokens: 0,
  cache_read_input_tokens: 0,
  cache_creation_5m_input_tokens: 0,
  cache_creation_1h_input_tokens: 0,
};
export const ZERO_USAGE: Usage = { ...ZERO_TOKENS, requests: 0, cost_microcents: 0, unmetered_responses: 0 };

export interface Metering {
  tokens: TokenCounts;
  unmetered: boolean;
  responseBytes: number;
}

function tokenCount(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

function checkServerTools(source: Record<string, unknown> | undefined): void {
  if (!source || !("server_tool_use" in source)) return;
  const serverTools = object(source.server_tool_use);
  if (!serverTools || Object.values(serverTools).some(count => count !== 0)) throw new Error("unexpected server tool usage");
}

function tokenFields(source: Record<string, unknown> | undefined): Partial<TokenCounts> {
  if (!source) return {};
  const counts: Partial<TokenCounts> = {};
  for (const field of ["input_tokens", "output_tokens", "cache_read_input_tokens"] as const) {
    if (field in source) {
      const count = tokenCount(source[field]);
      if (count === undefined) throw new Error("invalid usage");
      counts[field] = count;
    }
  }
  if ("cache_creation_input_tokens" in source || "cache_creation" in source) {
    const total = tokenCount(source.cache_creation_input_tokens);
    if ("cache_creation_input_tokens" in source && total === undefined) throw new Error("invalid cache usage");
    const cache = object(source.cache_creation);
    if (source.cache_creation != null && !cache) throw new Error("invalid cache breakdown");
    const short = tokenCount(cache?.ephemeral_5m_input_tokens);
    const long = tokenCount(cache?.ephemeral_1h_input_tokens);
    if ((cache && "ephemeral_5m_input_tokens" in cache && short === undefined)
      || (cache && "ephemeral_1h_input_tokens" in cache && long === undefined)) {
      throw new Error("invalid cache breakdown");
    }
    const known = (short ?? 0) + (long ?? 0);
    if (!Number.isSafeInteger(known) || (total !== undefined && known > total)) {
      throw new Error("invalid cache totals");
    }
    if (total !== undefined) {
      counts.cache_creation_5m_input_tokens = short ?? 0;
      counts.cache_creation_1h_input_tokens = (long ?? 0) + total - known;
    } else {
      if (short !== undefined) counts.cache_creation_5m_input_tokens = short;
      if (long !== undefined) counts.cache_creation_1h_input_tokens = long;
    }
  }
  return counts;
}

async function streamUsage(body: ReadableStream<Uint8Array>): Promise<Partial<TokenCounts>> {
  let data: string[] = [];
  let size = 0;
  let start: Partial<TokenCounts> | undefined;
  let delta: Partial<TokenCounts> | undefined;

  function event(): void {
    if (!data.length) return;
    const parsed = object(JSON.parse(data.join("\n")));
    data = [];
    size = 0;
    const messageUsage = object(object(parsed?.message)?.usage);
    const usage = object(parsed?.usage);
    checkServerTools(messageUsage);
    checkServerTools(usage);
    if (parsed?.type === "message_start") {
      if (start || delta) throw new Error("repeated message start");
      start = tokenFields(messageUsage);
    } else if (parsed?.type === "message_delta" && start) {
      const current = tokenFields(usage);
      delta = { ...delta, ...current, output_tokens: current.output_tokens ?? -1 };
    }
  }

  for await (const line of readLines(body, MAX_EVENT_CHARS, true)) {
    if (line === null) throw new Error("oversized SSE line");
    if (line === "") {
      event();
    } else if (line === "data" || line.startsWith("data:")) {
      const value = line.slice(5).replace(/^ /, "");
      size += value.length + 1;
      if (size > MAX_EVENT_CHARS) throw new Error("oversized SSE event");
      data.push(value);
    }
  }
  event();
  const output = delta?.output_tokens;
  if (output === undefined || output < 0) return {};
  return { ...start, ...delta };
}

export function estimatedTokens(requestBytes: number, maxTokens: number): TokenCounts {
  return { ...ZERO_TOKENS, input_tokens: Math.ceil(requestBytes / 3), output_tokens: maxTokens };
}

export type Settlement = Metering | "failure" | "zero";

export async function meterResponse(
  body: ReadableStream<Uint8Array> | null, contentType: string | null, requestBytes: number, maxTokens: unknown,
): Promise<Metering> {
  let responseBytes = 0;
  try {
    if (!body) throw new Error("missing response body");
    const counted = body.pipeThrough(new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        responseBytes += chunk.byteLength;
        controller.enqueue(chunk);
      },
    }));
    let counts: Partial<TokenCounts>;
    if (contentType?.split(";")[0]?.trim().toLowerCase() === "text/event-stream") {
      counts = await streamUsage(counted);
    } else {
      const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false })
        .decode(await readBytes(counted, MAX_JSON_BYTES));
      const usage = object(object(JSON.parse(text))?.usage);
      checkServerTools(usage);
      counts = tokenFields(usage);
    }
    if (counts.input_tokens === undefined || counts.output_tokens === undefined) throw new Error("missing usage");
    return { tokens: { ...ZERO_TOKENS, ...counts }, unmetered: false, responseBytes };
  } catch {
    return {
      tokens: estimatedTokens(requestBytes, tokenCount(maxTokens) ?? Number.MAX_SAFE_INTEGER),
      unmetered: true,
      responseBytes,
    };
  }
}

const PRICE_FIELDS = [
  ["input_tokens", "input"], ["output_tokens", "output"], ["cache_read_input_tokens", "cache_read"],
  ["cache_creation_5m_input_tokens", "cache_write_5m"], ["cache_creation_1h_input_tokens", "cache_write_1h"],
] as const;

function decimal(value: number): { digits: bigint; scale: number } {
  const [mantissa = "", power = "0"] = value.toString().split("e");
  const [integer = "", fraction = ""] = mantissa.split(".");
  return { digits: BigInt(integer + fraction), scale: fraction.length - Number(power) };
}

// The run's prices fix the denominator. Persist units so sub-microcent amounts survive between requests.
export function exactCost(tokens: TokenCounts, prices: Prices): { units: bigint; denominator: bigint } {
  const terms = PRICE_FIELDS.map(([count, rate]) => ({ count: BigInt(tokens[count]), ...decimal(prices[rate]) }));
  const scale = Math.max(0, ...terms.map(term => term.scale));
  const units = terms.reduce((sum, { count, digits, scale: places }) =>
    sum + count * digits * 10n ** BigInt(scale - places), 0n);
  return { units, denominator: 10n ** BigInt(scale) };
}

export function microcents(units: bigint, denominator: bigint): bigint {
  return (units + denominator - 1n) / denominator;
}

export function jsonInteger(value: bigint): number {
  return value > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(value);
}

export function costMicrocents(tokens: TokenCounts, prices: Prices): number {
  const { units, denominator } = exactCost(tokens, prices);
  return jsonInteger(microcents(units, denominator));
}
