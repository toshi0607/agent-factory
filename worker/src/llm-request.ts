import { object } from "./types";

export const BODY_KEYS = new Set([
  "model", "messages", "system", "max_tokens", "stream", "temperature", "top_p", "top_k",
  "stop_sequences", "metadata", "tools", "tool_choice", "thinking", "output_config", "context_management",
]);
export const METADATA_KEYS = new Set(["user_id"]);
export const TOOL_KEYS = new Set([
  "name", "description", "input_schema", "type", "cache_control", "defer_loading", "strict", "eager_input_streaming",
]);
export const TOOL_TYPES = new Set(["custom"]);
export const TOOL_CHOICE_KEYS = new Set(["type", "name", "disable_parallel_tool_use"]);
export const TOOL_CHOICE_TYPES = new Set(["auto", "any", "tool", "none"]);
// Claude Code sends per-turn settings as a system-role message with an output_config object.
export const MESSAGE_KEYS = new Set(["role", "content", "output_config"]);
export const MESSAGE_ROLES = new Set(["user", "assistant", "system"]);
export const BLOCK_TYPES = new Set(["text", "tool_use", "tool_result", "thinking", "redacted_thinking", "image", "document"]);
export const SOURCE_TYPES = new Set(["base64", "text"]);
export const OPAQUE_OBJECT_KEYS = ["context_management", "thinking", "output_config"] as const;
export const BETA_NAMES = new Set([
  "claude-code-20250219",
  "interleaved-thinking-2025-05-14",
  "context-management-2025-06-27",
  "per-turn-control-2026-07-01",
  "mid-conversation-tool-changes-2026-07-01",
  "thinking-token-count-2026-05-13",
  "effort-2025-11-24",
  "thinking-display-updates-2026-08-18",
]);
export const MAX_TOKENS = 128_000;
const MAX_DEPTH = 64;
const MAX_REASON = 40;

function namedReason(reason: string, name: unknown): string {
  return typeof name === "string" && /^[a-z0-9_.-]+$/i.test(name.slice(0, MAX_REASON))
    ? `${reason}:${name}`.slice(0, MAX_REASON) : reason;
}

function keys(value: Record<string, unknown>, allowed: ReadonlySet<string>): string | undefined {
  const unexpected = Object.keys(value).find(key => !allowed.has(key));
  return unexpected === undefined ? undefined : namedReason("key", unexpected);
}

function has(allowed: ReadonlySet<string>, value: unknown): value is string {
  return typeof value === "string" && allowed.has(value);
}

type Content = "value" | "content" | "block" | "messages" | "message";

function walk(value: unknown, kind: Content, depth: number): string | undefined {
  if (depth > MAX_DEPTH && typeof value === "object" && value !== null) return "depth";
  if (kind === "content" && typeof value === "string") return;
  if (Array.isArray(value)) {
    if (kind === "message" || kind === "block") return kind;
    const itemKind = kind === "messages" ? "message" : kind === "content" ? "block" : "value";
    for (const item of value) {
      const reason = walk(item, itemKind, depth + 1);
      if (reason) return reason;
    }
    return;
  }

  const fields = object(value);
  if (fields && Object.hasOwn(fields, "file_id")) return "file_id";
  if (kind === "content" || kind === "messages") return kind;
  if (kind === "message") {
    if (!fields || !has(MESSAGE_ROLES, fields.role)) return "message";
    if ("output_config" in fields && !object(fields.output_config)) return "message";
    return keys(fields, MESSAGE_KEYS) ?? walk(fields.content, "content", depth + 1);
  }
  if (kind === "block") {
    if (!fields || !has(BLOCK_TYPES, fields.type)) return namedReason("block_type", fields?.type);
    if ((fields.type === "image" || fields.type === "document") && !has(SOURCE_TYPES, object(fields.source)?.type)) {
      return "source_type";
    }
  }
  if (!fields) return;

  for (const [key, child] of Object.entries(fields)) {
    if (kind === "block" && fields.type === "tool_use" && key === "input") continue;
    const childKind = kind === "block" && fields.type === "tool_result" && key === "content" ? "content" : "value";
    const reason = walk(child, childKind, depth + 1);
    if (reason) return reason;
  }
}

type Validation = { ok: true; maxTokens: number | undefined } | { ok: false; reason: string };

export function validateLlmBody(parsed: unknown, model: string): Validation {
  const bad = (reason: string): Validation => ({ ok: false, reason });
  const body = object(parsed);
  if (!body || body.model !== model) return bad("model");
  const unexpected = keys(body, BODY_KEYS);
  if (unexpected) return bad(unexpected);

  if ("metadata" in body) {
    const metadata = object(body.metadata);
    if (!metadata) return bad("metadata");
    const reason = keys(metadata, METADATA_KEYS);
    if (reason) return bad(reason);
    if ("user_id" in metadata && typeof metadata.user_id !== "string") return bad("metadata");
  }
  if ("tools" in body) {
    if (!Array.isArray(body.tools)) return bad("tools");
    for (const value of body.tools) {
      const tool = object(value);
      if (!tool || ("type" in tool && !has(TOOL_TYPES, tool.type))) return bad("tool_type");
      const reason = keys(tool, TOOL_KEYS);
      if (reason) return bad(reason);
    }
  }
  if ("tool_choice" in body) {
    const choice = object(body.tool_choice);
    if (!choice || !has(TOOL_CHOICE_TYPES, choice.type)) return bad("tool_choice");
    const reason = keys(choice, TOOL_CHOICE_KEYS);
    if (reason) return bad(reason);
  }
  for (const key of OPAQUE_OBJECT_KEYS) {
    if (key in body && !object(body[key])) return bad(key);
  }
  if ("system" in body) {
    const reason = walk(body.system, "content", 2);
    if (reason) return bad(reason);
  }
  if ("messages" in body) {
    const reason = walk(body.messages, "messages", 2);
    if (reason) return bad(reason);
  }
  const maxTokens = body.max_tokens;
  if (typeof maxTokens === "number" && Number.isInteger(maxTokens) && maxTokens > 0 && maxTokens <= MAX_TOKENS) {
    return { ok: true, maxTokens };
  }
  return "max_tokens" in body ? bad("max_tokens") : { ok: true, maxTokens: undefined };
}

// JSON.parse retains only the last occurrence of a key. Check the original text
// before forwarding it to a parser that may interpret duplicate keys differently.
export function duplicateField(text: string, parsed: unknown): "model" | "duplicate_key" | undefined {
  type Frame = {
    value: unknown;
    kind: Content | "root";
    seen: Set<string>;
    key?: string;
    item: number;
    expectingKey: boolean;
  };
  const frames: Frame[] = [];
  const structural = /["\\{}\[\],]/g;
  let depth = 0;
  let quoted = false;
  let keyStart = -1;
  for (let match = structural.exec(text); match; match = structural.exec(text)) {
    const character = match[0];
    const parent = frames[depth - 1];
    if (quoted) {
      if (character === "\\") {
        structural.lastIndex += 1;
      } else if (character === '"') {
        quoted = false;
        if (keyStart >= 0 && parent) {
          const key = JSON.parse(text.slice(keyStart, structural.lastIndex)) as string;
          if (parent.seen.has(key)) {
            return depth === 1 && (key === "model" || key === "max_tokens") ? "model" : "duplicate_key";
          }
          parent.seen.add(key);
          parent.key = key;
          parent.expectingKey = false;
          keyStart = -1;
        }
      }
    } else if (character === '"') {
      quoted = true;
      if (parent?.expectingKey) keyStart = match.index;
    } else if (character === "{" || character === "[") {
      if (depth < MAX_DEPTH && (depth === 0 || parent)) {
        const fields = object(parent?.value);
        const opaque = parent?.kind === "block" && fields?.type === "tool_use" && parent.key === "input";
        if (!opaque) {
          const value = !parent ? parsed : Array.isArray(parent.value)
            ? parent.value[parent.item] : fields?.[parent.key ?? ""];
          let kind: Frame["kind"] = "value";
          if (!parent) kind = "root";
          else if (parent.kind === "root" && parent.key === "messages") kind = "messages";
          else if (parent.kind === "messages") kind = "message";
          else if (parent.kind === "content") kind = "block";
          else if ((parent.kind === "root" && parent.key === "system")
            || (parent.kind === "message" && parent.key === "content")
            || (parent.kind === "block" && fields?.type === "tool_result" && parent.key === "content")) kind = "content";
          frames.push({ value, kind, seen: new Set(), item: 0, expectingKey: character === "{" });
        }
      }
      depth += 1;
    } else if (character === "}" || character === "]") {
      if (frames.length === depth) frames.pop();
      depth -= 1;
    } else if (parent) {
      parent.item += 1;
      parent.expectingKey = object(parent.value) !== undefined;
    }
  }
}

export function filterBeta(header: string | null): { forwarded: string; dropped: string[] } {
  const allowed: string[] = [];
  const dropped: string[] = [];
  for (const value of header?.split(",") ?? []) {
    const name = value.trim();
    if (BETA_NAMES.has(name)) allowed.push(name);
    else if (name && dropped.length < 8) dropped.push(name.slice(0, 60));
  }
  return { forwarded: allowed.join(","), dropped };
}
