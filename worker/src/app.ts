import { z } from "zod";
import type { Verify } from "./oidc";
import { BodyTooLarge, MAX_UPLOAD_BYTES, readBytes } from "./streams";
import { errorResponse, type Env, type OutputName, type StartRequest } from "./types";

const RUN_ID = /^p0-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$/;
const FILENAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
const HOSTNAME = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const OUTPUTS: ReadonlySet<string> = new Set<OutputName>([
  "patch.diff", "changed-paths.txt", "probe.txt", "events.jsonl", "stderr.log",
]);
const encoder = new TextEncoder();
const boundedString = (bytes: number) => z.string().refine(text => encoder.encode(text).length <= bytes);
const price = z.number().positive().finite();
const host = z.string().max(253).regex(HOSTNAME).refine(value => {
  if (value.endsWith(".anthropic.com")) return false;
  try {
    const parsed = new URL(`https://${value}/`);
    return parsed.hostname === value && !/^[0-9.]+$/.test(value);
  } catch {
    return false;
  }
});
const prefix = z.string().startsWith("/").refine(value => {
  if (/[?#\\\s\u0000-\u001f\u007f]|%2[eEfF]/.test(value)) return false;
  return !value.split("/").some(segment => segment === "." || segment === "..");
});
const startSchema = z.strictObject({
  role: z.string().regex(/^[a-z][a-z0-9-]{0,30}$/),
  model: z.string().regex(/^claude-[a-z0-9-]{1,60}$/),
  system_prompt: boundedString(64 * 1024),
  user_message: boundedString(16 * 1024).refine(text => !text.includes("\0")),
  budget_cents: z.int().min(1).max(300),
  minutes: z.int().min(1).max(30),
  prices: z.strictObject({
    input: price, output: price, cache_write_5m: price, cache_write_1h: price, cache_read: price,
  }),
  egress: z.array(z.strictObject({ host, path_prefixes: z.array(prefix).min(1).optional() })).max(16),
});
const tokenSchema = z.strictObject({
  access_token: z.string().min(20).max(4096).regex(/^[\x21-\x7e]+$/),
  expires_in: z.int().min(30).max(86400),
});
const stopSchema = z.strictObject({ reason: z.enum(["time_limit", "cancelled"]) });

export function validateStart(value: unknown): StartRequest | undefined {
  const result = startSchema.safeParse(value);
  return result.success ? result.data : undefined;
}

type Route = { id: string } & (
  | { resource: "run" | "start" | "token" | "egress" | "stop" }
  | { resource: "files"; name: string }
  | { resource: "outputs"; name: OutputName }
);

export function route(path: string): Route | undefined {
  const [root, runs, id, resource, name, ...rest] = path.split("/");
  if (root !== "" || runs !== "runs" || !id || !RUN_ID.test(id) || rest.length) return undefined;
  if (resource === undefined) return { id, resource: "run" };
  if (name === undefined) {
    if (resource === "start" || resource === "token" || resource === "egress" || resource === "stop") {
      return { id, resource };
    }
    return undefined;
  }
  if (resource === "files" && FILENAME.test(name)) return { id, resource, name };
  if (resource === "outputs" && OUTPUTS.has(name)) return { id, resource, name: name as OutputName };
  return undefined;
}

const methods: Record<Route["resource"], readonly string[]> = {
  run: ["GET", "DELETE"], files: ["PUT"], start: ["POST"], token: ["PUT"],
  outputs: ["GET"], egress: ["GET"], stop: ["POST"],
};
const messages = {
  misconfigured: "Authentication is not configured",
  invalid_token: "Invalid token",
  wrong_audience: "Invalid audience",
  wrong_repository: "Repository is not allowed",
  wrong_workflow: "Workflow is not allowed",
  expired: "Token expired",
};

async function json(request: Request, limit: number): Promise<unknown> {
  try {
    const bytes = await readBytes(request.body, limit);
    return JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes));
  } catch (error) {
    if (error instanceof BodyTooLarge) throw error;
    return undefined;
  }
}

export function createApp({ verify }: { verify: Verify }): ExportedHandler<Env> {
  return {
    async fetch(request, env) {
      try {
        const auth = await verify(request.headers.get("authorization"), env);
        if (!auth.ok) {
          return errorResponse(auth.error === "misconfigured" ? 500 : 401, auth.error, messages[auth.error]);
        }
        const target = route(new URL(request.url).pathname);
        if (!target) return errorResponse(404, "not_found", "Route not found");
        const allowed = methods[target.resource];
        if (!allowed.includes(request.method)) {
          const response = errorResponse(405, "method_not_allowed", "Method not allowed");
          response.headers.set("allow", allowed.join(", "));
          return response;
        }

        const run = env.RUN.getByName(target.id);
        if (!await run.claim(target.id, auth.caller)) {
          return errorResponse(403, "forbidden", "Run belongs to a different repository");
        }
        switch (target.resource) {
          case "run": return request.method === "DELETE" ? await run.destroy() : Response.json(await run.status());
          case "egress": return await env.LEDGER.getByName(target.id).egress();
          case "outputs": return await run.output(target.name);
          case "files": {
            const length = request.headers.get("content-length");
            if (length === null) return errorResponse(411, "length_required", "Content-Length required");
            if (!/^\d+$/.test(length)) return errorResponse(400, "invalid_length", "Invalid Content-Length");
            const size = Number(length);
            if (size > MAX_UPLOAD_BYTES) return errorResponse(413, "body_too_large", "Upload exceeds 95 MiB");
            return await run.upload(target.name, request.body, size);
          }
          case "start": {
            const start = validateStart(await json(request, 768 * 1024));
            if (!start) return errorResponse(400, "invalid_start", "Invalid start request");
            return await run.start(start);
          }
          case "token": {
            const token = tokenSchema.safeParse(await json(request, 32 * 1024));
            if (!token.success) return errorResponse(400, "invalid_token_request", "Invalid token request");
            return await run.token(token.data.access_token, token.data.expires_in);
          }
          case "stop": {
            const stop = stopSchema.safeParse(await json(request, 1024));
            if (!stop.success) return errorResponse(400, "invalid_stop", "Invalid stop request");
            return await run.stop(stop.data.reason);
          }
        }
      } catch (error) {
        if (error instanceof BodyTooLarge) return errorResponse(413, "body_too_large", "Request body too large");
        console.error({ event: "run_request_failed" });
        return errorResponse(500, "internal_error", "Run request failed");
      }
    },
  };
}
