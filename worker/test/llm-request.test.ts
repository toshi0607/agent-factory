import { expect, it } from "vitest";
import { BETA_NAMES, duplicateField, filterBeta, validateLlmBody } from "../src/llm-request";

const model = "claude-example";
const validate = (fields: object) => validateLlmBody({ model, ...fields }, model);
const message = (content: unknown) => ({ messages: [{ role: "user", content }] });

it("accepts the Claude Code fields and client tool results, leaving tool input and cache metadata opaque", () => {
  const text = { type: "text", text: "prompt", cache_control: { type: "ephemeral", ttl: "1h" } };
  const image = { type: "image", source: { type: "base64", media_type: "image/png", data: "ZGF0YQ==" } };
  const document = { type: "document", source: { type: "text", media_type: "text/plain", data: "document" } };
  const result = { type: "tool_result", tool_use_id: "local", content: [text, image, document] };
  let input: unknown = { type: "custom_payload", file_id: "application-specific" };
  for (let depth = 0; depth < 65; depth++) input = { child: input };
  expect(validate({
    system: [text], max_tokens: 128_000, stream: true, temperature: 1, top_p: 1, top_k: 1,
    stop_sequences: ["stop"], metadata: { user_id: "user" },
    context_management: { edits: [] }, output_config: { effort: "medium" }, thinking: { type: "adaptive" },
    tools: [
      { name: "Read", description: "Read a file", input_schema: { type: "object" } },
      { name: "Bash", type: "custom", cache_control: { type: "ephemeral" }, defer_loading: true,
        strict: true, eager_input_streaming: true },
    ],
    tool_choice: { type: "tool", name: "Read", disable_parallel_tool_use: true },
    messages: [
      { role: "user", content: "string" },
      { role: "assistant", content: [
        { type: "thinking", thinking: "thought" }, { type: "redacted_thinking", data: "data" },
        { type: "tool_use", id: "local", name: "Read", input },
      ] },
      { role: "user", content: [result] },
    ],
  })).toEqual({ ok: true, maxTokens: 128_000 });
});

it.each(["mcp_servers", "container", "service_tier", "speed", "inference_geo"])("rejects %s", key => {
  expect(validate({ [key]: "private" })).toEqual({ ok: false, reason: `key:${key}` });
});

it.each([
  "web_search_example", "web_fetch_example", "code_execution_example",
  "mcp_toolset", "bash_example", "text_editor_example", "computer_example", "memory_example", null,
])("rejects non-custom tool type %s", type => {
  expect(validate({ tools: [{ type }] })).toEqual({ ok: false, reason: "tool_type" });
});

it.each(["server_tool_use", "web_search_tool_result", "mcp_tool_use", "container_upload", "search_result"])(
  "rejects unsupported type %s inside a tool result", type => {
    expect(validate(message([{ type: "tool_result", content: [{ type }] }]))).toEqual({
      ok: false, reason: `block_type:${type}`,
    });
  },
);

it.each(["url", "file", "content", "other", null])("rejects unsupported media source %s", type => {
  for (const media of ["image", "document"]) {
    expect(validate({ system: [{ type: media, source: { type } }] })).toEqual({ ok: false, reason: "source_type" });
  }
});

it.each([
  [{ metadata: [] }, "metadata"],
  [{ metadata: { user_id: 1 } }, "metadata"],
  [{ metadata: { other: true } }, "key:other"],
  [{ tools: {} }, "tools"],
  [{ tools: [{ other: true }] }, "key:other"],
  [{ tool_choice: { type: "other" } }, "tool_choice"],
  [{ tool_choice: { type: "auto", other: true } }, "key:other"],
  [{ system: {} }, "content"],
  [{ messages: {} }, "messages"],
  [{ messages: [{ role: "developer", content: "text" }] }, "message"],
  [{ messages: [{ role: "user", content: null }] }, "content"],
  [message([{}]), "block_type"],
  [message([{ type: "tool_result", content: [{}] }]), "block_type"],
  [{ system: [{ type: "text", cache_control: { other: [{ file_id: "private" }] } }] }, "file_id"],
  [message([{ type: "image", source: { type: "base64", file_id: "private" } }]), "file_id"],
  [message([{ type: "tool_result", file_id: "private", content: "text" }]), "file_id"],
  [{ thinking: 1 }, "thinking"],
  [{ output_config: [] }, "output_config"],
  [{ context_management: null }, "context_management"],
] as const)("rejects invalid structured fields (%#)", (body, reason) => {
  expect(validate(body)).toEqual({ ok: false, reason });
});

it.each([0, -1, 128_001, 1.1, Infinity, "99", null])("rejects max_tokens %s", max_tokens => {
  expect(validate({ max_tokens })).toEqual({ ok: false, reason: "max_tokens" });
});

it("limits walked nesting to 64 container levels and bounds reason names", () => {
  let extra: object = {};
  for (let depth = 0; depth < 60; depth++) extra = { extra };
  expect(validate({ system: [{ type: "text", extra }] }).ok).toBe(true);
  expect(validate({ system: [{ type: "text", extra: { extra } }] })).toEqual({ ok: false, reason: "depth" });
  expect(validate({ ["a".repeat(80)]: "a value" })).toEqual({ ok: false, reason: "key:" + "a".repeat(36) });
  expect(validate({ ["bad\nname"]: "a value" })).toEqual({ ok: false, reason: "key" });
});

it("preserves opaque input and detects duplicate keys with escaped spellings in walked content", () => {
  const opaque = '{"system":[{"type":"tool_use","input":{"x":1,"x":2}}]}';
  const walked = String.raw`{"system":[{"type":"tool_result","content":[{"type":"text","\u0074ype":"text"}]}]}`;
  expect(duplicateField(opaque, JSON.parse(opaque))).toBeUndefined();
  expect(duplicateField(walked, JSON.parse(walked))).toBe("duplicate_key");
});

it("contains exactly the eight captured beta names", () => {
  const names = [
    "claude-code-20250219", "interleaved-thinking-2025-05-14", "context-management-2025-06-27",
    "per-turn-control-2026-07-01", "mid-conversation-tool-changes-2026-07-01", "thinking-token-count-2026-05-13",
    "effort-2025-11-24", "thinking-display-updates-2026-08-18",
  ];
  expect([...BETA_NAMES]).toEqual(names);
  expect(filterBeta(names.join(", ") + ", EFFORT-2025-11-24")).toEqual({
    forwarded: names.join(","), dropped: ["EFFORT-2025-11-24"],
  });
});

it("accepts the per-turn system message Claude Code appends and rejects other shapes of it", () => {
  const turns = [{ role: "user", content: [{ type: "text", text: "hello" }] }];
  expect(validate({ messages: [...turns, { role: "system", content: [], output_config: { effort: "medium" } }] }))
    .toEqual({ ok: true, maxTokens: undefined });
  expect(validate({ messages: [...turns, { role: "system", content: [], output_config: "medium" }] }))
    .toEqual({ ok: false, reason: "message" });
  expect(validate({ messages: [...turns, { role: "system", content: [], container: {} }] }))
    .toEqual({ ok: false, reason: "key:container" });
  expect(validate({ messages: [...turns, { role: "developer", content: [] }] }))
    .toEqual({ ok: false, reason: "message" });
});
