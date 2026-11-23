import { describe, expect, it } from "vitest";
import { costMicrocents, exactCost, meterResponse, microcents, ZERO_USAGE } from "../src/usage";
import { startRequest } from "./fixtures";

const expected = {
  input_tokens: 10, output_tokens: 20, cache_read_input_tokens: 30,
  cache_creation_5m_input_tokens: 40, cache_creation_1h_input_tokens: 50,
};

function stream(chunks: Uint8Array[]): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk);
      controller.close();
    },
  });
}
const encoder = new TextEncoder();
const json = (usage: unknown) => meterResponse(stream([encoder.encode(JSON.stringify({ usage }))]), "application/json", 10, 99);

describe("usage extraction", () => {
  it("extracts JSON usage and the cache breakdown", async () => {
    const sample = await json({
      input_tokens: 10, output_tokens: 20, cache_read_input_tokens: 30, cache_creation_input_tokens: 90,
      cache_creation: { ephemeral_5m_input_tokens: 40, ephemeral_1h_input_tokens: 50 },
    });
    expect(sample.tokens).toEqual(expected);
    expect(sample.unmetered).toBe(false);
  });

  it("prices aggregate cache creation and unclassified cache tokens at the 1h rate", async () => {
    const counts = { input_tokens: 10, output_tokens: 20, cache_creation_input_tokens: 90 };
    expect((await json(counts)).tokens).toMatchObject({ cache_creation_1h_input_tokens: 90, cache_creation_5m_input_tokens: 0 });
    expect((await json({ ...counts, cache_creation: { ephemeral_5m_input_tokens: 40 } })).tokens)
      .toMatchObject({ cache_creation_1h_input_tokens: 50, cache_creation_5m_input_tokens: 40 });
  });

  it("handles every byte split, including CRLF, multi-line data and multibyte text", async () => {
    const text = [
      ": café",
      "event: message_start",
      'data: {"type":"message_start","message":{"usage":{"input_tokens":1,"output_tokens":2,',
      'data: "cache_read_input_tokens":3,"cache_creation_input_tokens":95}}}', "",
      'data: {"type":"message_delta","usage":{"output_tokens":19,"input_tokens":10}}', "",
      'data: {"type":"message_delta","usage":{"output_tokens":20,"cache_read_input_tokens":30,',
      'data: "cache_creation":{"ephemeral_5m_input_tokens":40,"ephemeral_1h_input_tokens":50}}}', "",
      'data: {"type":"message_stop"}', "", "",
    ].join("\r\n");
    const bytes = encoder.encode(text);
    const check = async (chunks: Uint8Array[]) => {
      expect(await meterResponse(stream(chunks), "text/event-stream; charset=utf-8", 10, 99)).toEqual({
        tokens: expected, unmetered: false, responseBytes: bytes.length,
      });
    };
    for (let split = 0; split <= bytes.length; split++) {
      await check([bytes.subarray(0, split), bytes.subarray(split)]);
    }
    await check(Array.from(bytes, byte => Uint8Array.of(byte)));
  });

  it.each([
    {}, { input_tokens: 1 }, { input_tokens: -1, output_tokens: 2 },
    { input_tokens: "1", output_tokens: 2 },
    { input_tokens: 1, output_tokens: 2, cache_creation_input_tokens: 1, cache_creation: { ephemeral_5m_input_tokens: 5 } },
  ])("uses the conservative fallback for missing or invalid usage %j", async usage => {
    const result = await json(usage);
    expect(result.unmetered).toBe(true);
    expect(result.tokens).toEqual({
      input_tokens: 4, output_tokens: 99, cache_read_input_tokens: 0,
      cache_creation_5m_input_tokens: 0, cache_creation_1h_input_tokens: 0,
    });
  });

  it("uses the fallback when a stream ends before the final delta or with an error", async () => {
    const onlyStart = encoder.encode('data: {"type":"message_start","message":{"usage":{"input_tokens":2}}}\n\n');
    const broken = new ReadableStream<Uint8Array>({ pull(controller) { controller.error(new Error("disconnected")); } });
    for (const body of [stream([onlyStart]), broken]) {
      expect(await meterResponse(body, "text/event-stream", 100, 32)).toMatchObject({
        unmetered: true, tokens: { input_tokens: 34, output_tokens: 32 },
      });
    }
  });

  it("retains the cache dimensions that a later SSE delta omits", async () => {
    const bytes = encoder.encode([
      'data: {"type":"message_start","message":{"usage":{"input_tokens":10,"cache_creation":{"ephemeral_1h_input_tokens":50}}}}',
      'data: {"type":"message_delta","usage":{"output_tokens":19,"cache_creation":{"ephemeral_5m_input_tokens":40}}}',
      'data: {"type":"message_delta","usage":{"output_tokens":20,"cache_creation":null}}',
      "",
    ].join("\n\n"));
    expect(await meterResponse(stream([bytes]), "text/event-stream", 10, 99)).toMatchObject({
      unmetered: false, tokens: {
        input_tokens: 10, output_tokens: 20,
        cache_creation_5m_input_tokens: 40, cache_creation_1h_input_tokens: 50,
      },
    });
  });
});

describe("integer microcent arithmetic", () => {
  it("uses the correct price for each usage field", () => {
    expect(costMicrocents(expected, startRequest.prices)).toBe(105_200);
  });

  it("keeps fractional microcents exact across requests and supports decimal exponents", () => {
    const prices = { ...startRequest.prices, input: 0.1, output: 0.2, cache_read: 1e-7 };
    const { units, denominator } = exactCost({ ...ZERO_USAGE, input_tokens: 1, output_tokens: 1, cache_read_input_tokens: 1 }, prices);
    expect(units).toBe(3_000_001n);
    expect(denominator).toBe(10_000_000n);
    expect(microcents(units * 10n, denominator)).toBe(4n);
    expect(microcents(3_000_000n * 10n, denominator)).toBe(3n);
  });

  it("keeps the internal charge exact even beyond safe JSON numbers", () => {
    const tokens = { ...ZERO_USAGE, output_tokens: Number.MAX_SAFE_INTEGER };
    expect(exactCost(tokens, startRequest.prices).units).toBe(18_014_398_509_481_982_000n);
    expect(costMicrocents(tokens, startRequest.prices)).toBe(Number.MAX_SAFE_INTEGER);
  });
});
