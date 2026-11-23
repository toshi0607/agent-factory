import { Files, SandboxFileError } from "@cloudflare/sandbox";
import { DurableObject } from "cloudflare:workers";
import { createHash } from "node:crypto";
import { agentCommand, type AgentCommand, type AgentInput } from "./agent";
import type { Outbound } from "./outbound";
import { BodyTooLarge, MAX_UPLOAD_BYTES, readBytes, readLines } from "./streams";
import {
  errorResponse, object, type AgentResult, type Caller, type Env, type ForcedStop, type OutputName,
  type RequestedStop, type StartRequest, type State, type StopReason,
} from "./types";

const ROOT = "/factory";
const DELIVERY = `${ROOT}/delivery`;
const TASK = `${ROOT}/task`;
const OUT = `${ROOT}/out`;
const CTL = `${ROOT}/ctl`;
const PID = `${CTL}/pid`;
const EXIT_CODE = `${CTL}/exit-code`;
const CREATED_MS = 15 * 60_000;
const MAX_OUTPUT_BYTES = 64 * 1024 * 1024;
const MAX_RESULT_BYTES = 256 * 1024;
const TICK_MS = 30_000;
const RETENTION_MS = 10 * 60_000;
const INACTIVITY_MS = 15 * 60_000;
const AGENT = "1000:1000";
const CA = "/etc/cloudflare/certs/cloudflare-containers-ca.crt";
const TRUST = {
  NODE_EXTRA_CA_CERTS: CA, SSL_CERT_FILE: CA, CURL_CA_BUNDLE: CA, GIT_SSL_CAINFO: CA,
};
const RUN_KEY = "run";
const INSTANCES = ["lite", "basic", "standard-1", "standard-2", "standard-3", "standard-4"] as const;

const LAUNCH = `umask 022
printf '%s\\n' "$$" > ${PID} || exit 125
printf '%s\\n' "$$"
IFS= read -r start && [ "$start" = go ] || exit 125
/usr/bin/setpriv --reuid=agent --regid=agent --init-groups --no-new-privs /bin/bash -c \\
  'exec "$@" </dev/null >${OUT}/events.jsonl 2>${OUT}/stderr.log' factory-command "$@"
code=$?
printf '%s\\n' "$code" >${EXIT_CODE}.tmp && mv -fT -- ${EXIT_CODE}.tmp ${EXIT_CODE}`;

interface RunData {
  id: string;
  repositoryId: string;
  workflowPath: string;
  workflowSha?: string;
  run_id?: string;
  run_attempt?: string;
  created_at?: number;
  controlFilesProtected?: boolean;
  state: State;
  stop_reason: StopReason | null;
  started_at: string | null;
  finished_at: string | null;
  deadline_at: string | null;
  exit_code: number | null;
  agent_result: AgentResult | null;
  budget_cents: number | null;
  minutes: number | null;
  finish_ok: boolean | null;
  group?: number;
  destroyRequested?: boolean;
}

type RunContext = DurableObjectState & {
  exports: Cloudflare.Exports & { Outbound: LoopbackForExport<typeof Outbound> };
};
type Instance = (typeof INSTANCES)[number];

function isInstance(value: string): value is Instance {
  return INSTANCES.some(instance => instance === value);
}
function missing(error: unknown): boolean {
  return SandboxFileError.is(error) && (error.code === "ENOENT" || error.code === "ENOTDIR");
}
function isForced(reason: StopReason | null): reason is ForcedStop {
  return reason === "time_limit" || reason === "cancelled" || reason === "budget_reached";
}
function now(): string {
  return new Date().toISOString();
}

function resultEvent(event: Record<string, unknown>): AgentResult | null {
  const { is_error, subtype, num_turns, total_cost_usd, result } = event;
  if (typeof is_error !== "boolean") return null;
  return {
    is_error,
    subtype: typeof subtype === "string" ? subtype.slice(0, 100) : "",
    num_turns: typeof num_turns === "number" && Number.isSafeInteger(num_turns) && num_turns >= 0 ? num_turns : 0,
    total_cost_usd: typeof total_cost_usd === "number" && Number.isFinite(total_cost_usd) && total_cost_usd >= 0
      ? total_cost_usd : 0,
    result_head: typeof result === "string" ? [...result.slice(0, 400)].slice(0, 200).join("") : "",
  };
}

export async function readResult(body: ReadableStream<Uint8Array> | null): Promise<AgentResult | null> {
  if (!body) return null;
  let result: AgentResult | null = null;
  for await (const line of readLines(body, 1024 * 1024)) {
    if (!line) continue;
    try {
      const event = object(JSON.parse(line));
      if (event?.type === "result") result = resultEvent(event);
    } catch {
      continue;
    }
  }
  return result;
}

async function processGroup(stream: ReadableStream<Uint8Array> | null): Promise<number> {
  if (!stream) throw new Error("Missing process group handshake");
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let text = "";
  try {
    while (text.length < 32 && !text.includes("\n")) {
      const part = await reader.read();
      if (part.done) break;
      if (part.value.byteLength > 32) break;
      text += decoder.decode(part.value);
    }
  } finally {
    reader.releaseLock();
  }
  if (!/^[1-9]\d{0,9}\n$/.test(text) || Number(text) <= 1) throw new Error("Invalid process group handshake");
  return Number(text);
}

export class Run extends DurableObject<Env> {
  readonly #container: Container;
  readonly #files: Files;
  readonly #outbound: RunContext["exports"]["Outbound"];
  #pending: Promise<void> = Promise.resolve();

  constructor(ctx: RunContext, env: Env) {
    super(ctx, env);
    if (!ctx.container) throw new Error("Missing Container attachment");
    this.#container = ctx.container;
    this.#outbound = ctx.exports.Outbound;
    this.#files = new Files({ exec: (argv, options) => this.#exec(argv, options) });
    if (this.#ready()) {
      void ctx.blockConcurrencyWhile(async () => { await this.#container.setInactivityTimeout(INACTIVITY_MS); });
    }
  }

  protected command(input: AgentInput): AgentCommand {
    return agentCommand(input);
  }

  async claim(id: string, caller: Caller, changesInputs: boolean): Promise<"claimed" | "forbidden" | "wrong_run"> {
    function check(existing: RunData): "claimed" | "forbidden" | "wrong_run" {
      if (existing.repositoryId !== caller.repositoryId) return "forbidden";
      if (changesInputs && (existing.run_id !== caller.run_id || existing.run_attempt !== caller.run_attempt)) {
        return "wrong_run";
      }
      return "claimed";
    }
    const kv = this.ctx.storage.kv;
    const existing = kv.get<RunData>(RUN_KEY);
    if (existing) return check(existing);
    return this.ctx.blockConcurrencyWhile(async () => {
      const claimed = kv.get<RunData>(RUN_KEY);
      if (claimed) return check(claimed);
      const created_at = Date.now();
      this.#save({
        id, repositoryId: caller.repositoryId, workflowPath: caller.workflowPath, workflowSha: caller.workflowSha,
        run_id: caller.run_id, run_attempt: caller.run_attempt, state: "created", created_at,
        stop_reason: null, started_at: null, finished_at: null, deadline_at: null, exit_code: null,
        agent_result: null, budget_cents: null, minutes: null, finish_ok: null,
      });
      await this.ctx.storage.setAlarm(created_at + CREATED_MS);
      return "claimed";
    });
  }

  async token(token: string, seconds: number): Promise<Response> {
    const result = await this.#ledger().setToken(token, seconds);
    if (!result) return errorResponse(409, "destroyed", "Run was destroyed");
    return Response.json({ expires_at: result.expires_at });
  }

  async status() {
    const ledger = await this.#ledger().status();
    const data = this.#data();
    const { id, state, stop_reason, started_at, finished_at, deadline_at, exit_code, agent_result,
      budget_cents, minutes, finish_ok } = data;
    return {
      id, state, stop_reason, started_at, finished_at, deadline_at, exit_code, agent_result,
      usage: ledger.usage, budget_cents, minutes, egress: ledger.egress, token: ledger.token,
      container: { running: this.#container.running, instance: this.env.INSTANCE_TYPE },
      ...this.#version(), finish_ok, caller_workflow_sha: data.workflowSha ?? null,
    };
  }

  upload(name: string, body: ReadableStream<Uint8Array> | null, length: number): Promise<Response> {
    return this.#serialize(async () => {
      const data = this.#data();
      if (data.state !== "created" || data.destroyRequested) return this.#alreadyStarted();
      await this.#ensureContainer(data.id);
      const tmp = `${DELIVERY}/.upload-${crypto.randomUUID()}`;
      const hash = createHash("sha256");
      let bytes = 0;
      let wrongLength = false;
      const stream = (body ?? new ReadableStream<Uint8Array>({ start: controller => controller.close() }))
        .pipeThrough(new TransformStream<Uint8Array, Uint8Array>({
          transform(chunk, controller) {
            bytes += chunk.byteLength;
            if (bytes > MAX_UPLOAD_BYTES) throw new BodyTooLarge();
            if (bytes > length) {
              wrongLength = true;
              throw new Error("Content-Length mismatch");
            }
            hash.update(chunk);
            controller.enqueue(chunk);
          },
        }));
      try {
        await this.#files.writeFile(tmp, stream);
        if (bytes !== length) {
          wrongLength = true;
          throw new Error("Content-Length mismatch");
        }
        await this.#files.rename(tmp, `${DELIVERY}/${name}`);
        return Response.json({ name, bytes, sha256: hash.digest("hex") });
      } catch (error) {
        try {
          await this.#files.remove(tmp, { force: true, signal: AbortSignal.timeout(5_000) });
        } catch {
          console.warn({ event: "upload_cleanup_failed" });
        }
        if (error instanceof BodyTooLarge) return errorResponse(413, "body_too_large", "Upload exceeds 95 MiB");
        if (wrongLength) return errorResponse(400, "length_mismatch", "Upload size differs from Content-Length");
        throw error;
      }
    });
  }

  start(request: StartRequest): Promise<Response> {
    return this.#serialize(async () => {
      const data = this.#data();
      if (data.state !== "created" || data.destroyRequested) return this.#alreadyStarted();
      const ledger = this.#ledger();
      if (!(await ledger.tokenStatus()).present) return errorResponse(409, "no_token", "An active token is required");
      const signal = AbortSignal.timeout(10_000);
      if (!this.#ready() || !await this.#isFile(`${DELIVERY}/manifest.json`, signal)
        || !await this.#isFile(`${DELIVERY}/task.md`, signal)) {
        return errorResponse(409, "missing_files", "Upload manifest.json and task.md first");
      }
      const systemPromptPath = `${TASK}/system-prompt.txt`;
      await this.#files.writeFile(systemPromptPath, request.system_prompt, { signal });
      if (!(await ledger.tokenStatus()).present) return errorResponse(409, "no_token", "An active token is required");

      const started = Date.now();
      const active: RunData = {
        ...data, state: "running", started_at: new Date(started).toISOString(), controlFilesProtected: true,
        deadline_at: new Date(started + request.minutes * 60_000).toISOString(),
        budget_cents: request.budget_cents, minutes: request.minutes,
      };
      await this.ctx.blockConcurrencyWhile(async () => {
        await this.#scheduleCheck(active);
        this.#save(active);
      });
      try {
        if (!await ledger.configure({ model: request.model, egress: request.egress }, request.prices, request.budget_cents)) {
          throw new Error("Ledger configuration refused");
        }
        const command = this.command({ model: request.model, systemPromptPath, userMessage: request.user_message });
        await this.#launch(active, command);
      } catch {
        console.error({ event: "agent_launch_failed" });
        await this.#quiesce();
        try {
          if (this.#container.running) await this.#container.destroy();
        } catch {
          console.warn({ event: "launch_cleanup_failed" });
        }
        await this.#finalize(active, "lost", "lost", null, null, null);
        return errorResponse(502, "launch_failed", "Agent launch failed");
      }
      return Response.json({ state: "running", started_at: active.started_at, ...this.#version() }, { status: 202 });
    });
  }

  async output(name: OutputName): Promise<Response> {
    if (this.#ready() && !this.#data().destroyRequested) {
      const path = `${OUT}/${name}`;
      try {
        const stat = await this.#files.lstat(path, { signal: AbortSignal.timeout(5_000) });
        if (stat.type === "file") {
          const signal = AbortSignal.timeout(10 * 60_000);
          const file = await this.#files.readFile(path, { signal });
          const headers = new Headers(file.headers);
          const truncated = stat.size > BigInt(MAX_OUTPUT_BYTES);
          if (truncated) headers.set("x-factory-truncated", "1");
          headers.delete("content-length");
          // Fix the output length when selecting headers, even if the file grows.
          let remaining = truncated ? MAX_OUTPUT_BYTES : Number(stat.size);
          const body = file.body?.pipeThrough(new TransformStream<Uint8Array, Uint8Array>({
            transform(chunk, controller) {
              const size = Math.min(chunk.byteLength, remaining);
              if (size > 0) controller.enqueue(chunk.subarray(0, size));
              remaining -= size;
              if (size < chunk.byteLength || (truncated && remaining === 0)) controller.terminate();
            },
          }), { signal });
          return new Response(body, { status: file.status, statusText: file.statusText, headers });
        }
      } catch (error) {
        if (!missing(error)) throw error;
      }
    }
    return errorResponse(404, "not_found", "Output not found");
  }

  stop(reason: RequestedStop): Promise<Response> {
    return this.#serialize(async () => {
      const data = this.#data();
      const stopped = !data.destroyRequested && (data.state === "running" || data.state === "created")
        ? await this.#forceStop(data, reason)
        : data;
      return Response.json({ state: stopped.state, stop_reason: stopped.stop_reason });
    });
  }

  destroy(): Promise<Response> {
    return this.#serialize(async () => {
      await this.#destroy(this.#data());
      return new Response(null, { status: 204 });
    });
  }

  override alarm(): Promise<void> {
    return this.#serialize(async () => {
      const data = this.ctx.storage.kv.get<RunData>(RUN_KEY);
      if (!data || data.state === "destroyed") return;
      if (data.destroyRequested || data.state === "finished" || data.state === "lost") {
        await this.#destroy(data);
        return;
      }
      if (isForced(data.stop_reason)) {
        await this.#forceStop(data, data.stop_reason);
        return;
      }
      if (data.state === "created") {
        const expiry = (data.created_at ?? Date.now() - CREATED_MS) + CREATED_MS;
        if (Date.now() >= expiry) await this.#destroy({ ...data, stop_reason: "cancelled", finished_at: now() });
        else await this.ctx.storage.setAlarm(expiry);
        return;
      }
      if (data.state !== "running") return;
      if (data.deadline_at !== null && Date.now() >= Date.parse(data.deadline_at)) {
        await this.#forceStop(data, "time_limit");
        return;
      }
      await this.#scheduleCheck(data);
      if (await this.#ledger().budgetExhausted()) {
        await this.#forceStop(data, "budget_reached");
      } else if (!this.#ready() || data.group === undefined) {
        await this.#quiesce();
        await this.#finalize(data, "lost", "lost", null, null, null);
      } else {
        const code = await this.#exitCode(data);
        if (code !== null && (data.controlFilesProtected || !await this.#groupAlive(data.group))) {
          await this.#quiesce();
          const result = await this.#result();
          const reason = code === 0 && result?.is_error === false ? "completed" : "agent_error";
          await this.#finalize(data, "finished", reason, code, result, null);
        }
      }
    });
  }

  #data(): RunData {
    const data = this.ctx.storage.kv.get<RunData>(RUN_KEY);
    if (!data) throw new Error("Run has no owner");
    return data;
  }

  #save(data: RunData): void {
    this.ctx.storage.kv.put(RUN_KEY, data);
  }

  #ledger() {
    return this.env.LEDGER.getByName(this.#data().id);
  }

  #version() {
    return {
      worker_version: this.env.CF_VERSION_METADATA ?? null,
      factory_commit: this.env.FACTORY_COMMIT,
    };
  }

  #alreadyStarted(): Response {
    return errorResponse(409, "already_started", "Run is no longer accepting this operation");
  }

  #serialize<T>(operation: () => Promise<T>): Promise<T> {
    // Uploads and finish.sh can take longer than the Durable Object concurrency gate.
    const result = this.#pending.then(operation);
    this.#pending = result.then(() => undefined, () => undefined);
    return result;
  }

  #ready(): boolean {
    return this.#container.running && this.ctx.storage.kv.get("prepared") === true;
  }

  #exec(argv: string[], options: ContainerExecOptions = {}): Promise<ExecProcess> {
    return this.#container.exec(argv, { cwd: ROOT, user: AGENT, ...options, env: { ...options.env, ...TRUST } });
  }

  async #ensureContainer(id: string): Promise<void> {
    if (this.#ready()) return;
    const instance = this.env.INSTANCE_TYPE;
    const image = this.#container.images.sandbox;
    if (!image || !isInstance(instance)) throw new Error("Invalid container configuration");
    if (this.#container.running) await this.#container.destroy();
    this.ctx.storage.kv.delete("prepared");
    this.#container.start({ image, instance, enableInternet: false, labels: { run: id } });
    try {
      const outbound = this.#outbound({ props: { runId: id } });
      await this.#container.interceptAllOutboundHttp(outbound);
      await this.#container.interceptOutboundHttps("*", outbound);
      await this.#container.setInactivityTimeout(INACTIVITY_MS);
      const setup = await this.#exec(["install", "-d", "-o", "agent", "-g", "agent", DELIVERY, TASK, OUT, `${ROOT}/work`], {
        user: "0:0", signal: AbortSignal.timeout(10_000), stdout: "ignore", stderr: "ignore",
      });
      if (await setup.exitCode !== 0) throw new Error("Directory setup failed");
      this.ctx.storage.kv.put("prepared", true);
    } catch (error) {
      if (this.#container.running) await this.#container.destroy();
      throw error;
    }
  }

  async #launch(data: RunData, { argv, env }: AgentCommand): Promise<void> {
    const abort = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => {
        abort.abort();
        reject(new Error("Process handshake timed out"));
      }, 10_000);
    });
    const launch = async () => {
      const process = await this.#exec(["setsid", "--fork", "--wait", "bash", "-c", LAUNCH, "factory-agent", ...argv], {
        user: "0:0", env, stdin: "pipe", stdout: "pipe", stderr: "ignore", signal: abort.signal,
      });
      void process.exitCode.catch(() => console.warn({ event: "agent_process_disconnected" }));
      const group = await processGroup(process.stdout);
      if (!process.stdin) throw new Error("Missing process control pipe");
      const stdin = process.stdin.getWriter();
      try {
        abort.signal.throwIfAborted();
        this.#save({ ...data, group });
        await this.ctx.storage.sync();
        abort.signal.throwIfAborted();
        await stdin.write(new TextEncoder().encode("go\n"));
        await stdin.close();
      } finally {
        stdin.releaseLock();
      }
    };
    try {
      await Promise.race([launch(), timeout]);
    } finally {
      clearTimeout(timer);
    }
  }

  async #isFile(path: string, signal: AbortSignal): Promise<boolean> {
    try {
      return (await this.#files.lstat(path, { signal })).type === "file";
    } catch (error) {
      if (missing(error)) return false;
      throw error;
    }
  }

  async #optionalFile(path: string, signal: AbortSignal): Promise<Response | null> {
    if (!await this.#isFile(path, signal)) return null;
    try {
      return await this.#files.readFile(path, { signal });
    } catch (error) {
      if (missing(error)) return null;
      throw error;
    }
  }

  async #exitCode(data: RunData): Promise<number | null> {
    try {
      const path = data.controlFilesProtected ? EXIT_CODE : `${TASK}/exit-code`;
      const file = await this.#optionalFile(path, AbortSignal.timeout(5_000));
      if (!file) return null;
      const text = new TextDecoder().decode(await readBytes(file.body, 16)).trim();
      const code = Number(text);
      return /^\d{1,3}$/.test(text) && code <= 255 ? code : 125;
    } catch {
      console.warn({ event: "exit_code_read_failed" });
      return this.#ready() ? 125 : null;
    }
  }

  async #groupAlive(group: number): Promise<boolean> {
    const process = await this.#exec(["bash", "-c", 'kill -0 -- "-$1" 2>/dev/null', "factory-liveness", String(group)], {
      user: "0:0", signal: AbortSignal.timeout(5_000), stdout: "ignore", stderr: "ignore",
    });
    const code = await process.exitCode;
    if (code !== 0 && code !== 1) throw new Error("Process group check failed");
    return code === 0;
  }

  async #killAgentProcesses(): Promise<void> {
    if (!this.#container.running) return;
    try {
      const process = await this.#exec(["bash", "-c", "kill -KILL -1"], {
        signal: AbortSignal.timeout(10_000), stdout: "ignore", stderr: "ignore",
      });
      await process.exitCode;
    } catch {
      console.warn({ event: "agent_kill_failed" });
    }
  }

  async #quiesce(destroy = false): Promise<void> {
    try {
      await this.#ledger().deactivate(destroy);
    } finally {
      await this.#killAgentProcesses();
    }
  }

  async #result(): Promise<AgentResult | null> {
    try {
      const path = `${OUT}/events.jsonl`;
      const signal = AbortSignal.timeout(30_000);
      if (!await this.#isFile(path, signal)) return null;
      const process = await this.#exec(["tail", "-c", String(MAX_RESULT_BYTES), "--", path], {
        signal, stdout: "pipe", stderr: "ignore",
      });
      const stream = process.stdout?.pipeThrough(new TransformStream<Uint8Array, Uint8Array>(), { signal });
      const [result, code] = await Promise.all([readResult(stream ?? null), process.exitCode]);
      return code === 0 ? result : null;
    } catch {
      console.warn({ event: "agent_result_read_failed" });
      return null;
    }
  }

  async #forceStop(data: RunData, requested: ForcedStop): Promise<RunData> {
    const reason = isForced(data.stop_reason) ? data.stop_reason : requested;
    const stopping = { ...data, stop_reason: reason };
    await this.ctx.blockConcurrencyWhile(async () => {
      await this.ctx.storage.setAlarm(Date.now() + TICK_MS);
      this.#save(stopping);
    });
    await this.#quiesce();

    let finishOk: boolean | null = null;
    let code: number | null = null;
    let result: AgentResult | null = null;
    if (this.#ready()) {
      finishOk = await this.#finish();
      if (finishOk !== null) await this.#killAgentProcesses();
      code = await this.#exitCode(data);
      result = await this.#result();
    }
    return this.#finalize(stopping, "finished", reason, code, result, finishOk);
  }

  async #finish(): Promise<boolean | null> {
    try {
      const script = `${DELIVERY}/finish.sh`;
      if (!await this.#isFile(script, AbortSignal.timeout(5_000))) return null;
      const abort = new AbortController();
      const timer = setTimeout(() => abort.abort(), 120_000);
      try {
        const process = await this.#exec(["bash", script], {
          env: { FACTORY_WORK_DIR: `${ROOT}/work`, FACTORY_OUT_DIR: OUT, HOME: "/home/agent" },
          signal: abort.signal, stdout: "ignore", stderr: "ignore",
        });
        return await process.exitCode === 0;
      } finally {
        clearTimeout(timer);
      }
    } catch {
      console.warn({ event: "finish_failed" });
      return false;
    }
  }

  async #finalize(
    data: RunData, state: "finished" | "lost", reason: StopReason,
    code: number | null, result: AgentResult | null, finishOk: boolean | null,
  ): Promise<RunData> {
    const finished: RunData = {
      ...data, state, stop_reason: reason, exit_code: code, agent_result: result, finished_at: now(), finish_ok: finishOk,
    };
    await this.ctx.storage.setAlarm(Date.now() + RETENTION_MS);
    this.#save(finished);
    return finished;
  }

  async #destroy(data: RunData): Promise<void> {
    if (data.state === "destroyed") {
      await this.ctx.storage.deleteAlarm();
      return;
    }
    this.#save({ ...data, destroyRequested: true });
    await this.ctx.storage.setAlarm(Date.now() + TICK_MS);
    await this.#quiesce(true);
    if (this.#container.running) await this.#container.destroy();
    this.ctx.storage.kv.delete("prepared");
    this.#save({ ...data, state: "destroyed" });
    await this.ctx.storage.deleteAlarm();
  }

  #scheduleCheck(data: RunData): Promise<void> {
    const deadline = data.deadline_at === null ? Infinity : Date.parse(data.deadline_at);
    return this.ctx.storage.setAlarm(Math.min(Date.now() + TICK_MS, deadline));
  }
}
