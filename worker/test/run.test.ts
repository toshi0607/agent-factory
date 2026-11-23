import "./runtime";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { readResult, Run } from "../src/run";
import type { Caller, Env, StartRequest } from "../src/types";
import { startRequest } from "./fixtures";

const disk = vi.hoisted(() => new Map<string, Uint8Array>());
vi.mock("@cloudflare/sandbox", () => {
  class SandboxFileError extends Error {
    readonly code = "ENOENT";
    static is(error: unknown) { return error instanceof SandboxFileError; }
  }
  class Files {
    async lstat(path: string) {
      if (!disk.has(path)) throw new SandboxFileError();
      return { type: "file" };
    }
    async readFile(path: string) {
      const contents = disk.get(path);
      if (!contents) throw new SandboxFileError();
      return new Response(contents.slice());
    }
    async writeFile(path: string, source: string | ReadableStream<Uint8Array>) {
      disk.set(path, new Uint8Array(await new Response(source).arrayBuffer()));
    }
    async rename(source: string, destination: string) {
      const file = disk.get(source);
      if (!file) throw new SandboxFileError();
      disk.set(destination, file);
      disk.delete(source);
    }
    async remove(path: string) { disk.delete(path); }
  }
  return { Files, SandboxFileError };
});

const id = "p0-20261123T012345Z-abcdef12";
const token = { present: true, expires_at: "later" };
const caller: Caller = {
  repositoryId: crypto.randomUUID(), workflowPath: "path", workflowSha: "ab".repeat(20),
};

function fixture() {
  let running = false;
  const history: string[] = [];
  const kv = new Map<string, unknown>();
  const toBytes = (text: string) => new TextEncoder().encode(text);
  const inputs: string[] = [];
  const container = {
    get running() { return running; },
    images: { sandbox: "image" },
    start: vi.fn(() => { running = true; history.push("start"); }),
    interceptAllOutboundHttp: vi.fn(async () => { history.push("http"); }),
    interceptOutboundHttps: vi.fn(async () => { history.push("https"); }),
    setInactivityTimeout: vi.fn(async () => { history.push("timeout"); }),
    exec: vi.fn(async (argv: string[], _options: ContainerExecOptions) => {
      history.push("exec");
      if (argv[0] !== "setsid") return { exitCode: Promise.resolve(0) };
      return {
        stdout: new Response("123\n").body,
        stdin: new WritableStream<Uint8Array>({ write(chunk) { inputs.push(new TextDecoder().decode(chunk)); } }),
        exitCode: Promise.resolve(0),
      };
    }),
    destroy: vi.fn(async () => { running = false; disk.clear(); }),
  };
  const ledger = {
    tokenStatus: vi.fn(async () => token), setToken: vi.fn(async () => token),
    configure: vi.fn(async () => true),
    deactivate: vi.fn(async (_destroy: boolean) => undefined),
    status: vi.fn(async () => ({ token })),
    budgetExhausted: vi.fn(async () => false),
  };
  const storage = {
    kv: { get: kv.get.bind(kv), put: kv.set.bind(kv), delete: kv.delete.bind(kv) },
    setAlarm: vi.fn(async (_at: number) => undefined), deleteAlarm: vi.fn(async () => undefined),
    sync: vi.fn(async () => undefined),
  };
  const outbound = vi.fn(() => ({}));
  const ctx = { container, storage, exports: { Outbound: outbound }, blockConcurrencyWhile: (fn: () => Promise<unknown>) => fn() };
  const create = () => new Run(ctx as unknown as ConstructorParameters<typeof Run>[0], {
    LEDGER: { getByName: () => ledger }, INSTANCE_TYPE: "standard-3", FACTORY_COMMIT: "",
  } as unknown as Env);
  const run = create();
  run.claim(id, caller);
  const upload = (name: string, contents = "abc", size = contents.length) => run.upload(name, new Response(contents).body, size);
  const start = async (overrides: Partial<StartRequest> = {}) => {
    for (const file of ["manifest.json", "task.md"]) await upload(file);
    return run.start({ ...startRequest, ...overrides });
  };
  return { run, create, container, ledger, history, storage, outbound, inputs, upload, start, toBytes, lose: () => { running = false; } };
}

beforeEach(() => {
  disk.clear();
  vi.useFakeTimers({ toFake: ["Date"] });
});
afterEach(() => vi.useRealTimers());

describe("Run lifecycle", () => {
  it("claims a run once and hashes each upload with both intercepts active", async () => {
    const { run, create, container, upload, outbound, history } = fixture();
    expect(run.claim(id, { ...caller, workflowPath: "different" })).toBe(true);
    expect(create().claim(id, { ...caller, repositoryId: crypto.randomUUID() })).toBe(false);
    expect(await (await upload("task.md")).json()).toEqual({
      name: "task.md", bytes: 3, sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    });
    expect(history).toEqual(["start", "http", "https", "timeout", "exec"]);
    expect(container.start).toHaveBeenCalledWith(expect.objectContaining({ enableInternet: false, instance: "standard-3" }));
    expect(outbound).toHaveBeenCalledWith({ props: { runId: id } });
    expect((await upload("task.md", "new text", 12)).status).toBe(400);
    expect((await upload("task.md", "new text", 2)).status).toBe(400);
    expect(new TextDecoder().decode(disk.get("/factory/delivery/task.md"))).toBe("abc");
    expect([...disk.keys()]).toEqual(["/factory/delivery/task.md"]);
  });

  it("requires a token and both uploads and starts only once under concurrency", async () => {
    const { run, container, ledger, inputs, storage, upload } = fixture();
    ledger.tokenStatus.mockResolvedValueOnce({ ...token, present: false });
    expect(await (await run.start(startRequest)).json()).toMatchObject({ error: "no_token" });
    expect(await (await run.start(startRequest)).json()).toMatchObject({ error: "missing_files" });
    await upload("manifest.json");
    await upload("task.md");
    const [launched, duplicate] = await Promise.all([run.start(startRequest), run.start(startRequest)]);
    expect(launched.status).toBe(202);
    expect(await launched.json()).toMatchObject({ state: "running", started_at: new Date().toISOString() });
    expect(duplicate.status).toBe(409);
    expect((await upload("task.md")).status).toBe(409);
    expect(inputs).toEqual(["go\n"]);
    expect(storage.sync).toHaveBeenCalledOnce();
    expect(storage.setAlarm).toHaveBeenCalledWith(Date.now() + 30_000);
    expect(ledger.configure).toHaveBeenCalledWith(
      { model: startRequest.model, egress: startRequest.egress }, startRequest.prices, startRequest.budget_cents,
    );
    expect(container.exec).toHaveBeenLastCalledWith(expect.arrayContaining(["setsid", "claude"]), expect.objectContaining({
      cwd: "/factory", user: "1000:1000",
      env: expect.objectContaining({
        NODE_EXTRA_CA_CERTS: "/etc/cloudflare/certs/cloudflare-containers-ca.crt",
        SSL_CERT_FILE: "/etc/cloudflare/certs/cloudflare-containers-ca.crt",
        CURL_CA_BUNDLE: "/etc/cloudflare/certs/cloudflare-containers-ca.crt",
        GIT_SSL_CAINFO: "/etc/cloudflare/certs/cloudflare-containers-ca.crt",
      }),
    }));
  });

  it("leaves the container unprepared and executes nothing when interception fails", async () => {
    const { container, upload, history } = fixture();
    container.interceptOutboundHttps.mockRejectedValueOnce(new Error("intercept failed"));
    await expect(upload("task.md")).rejects.toThrow("intercept failed");
    expect(container.exec).not.toHaveBeenCalled();
    expect(container.destroy).toHaveBeenCalledOnce();
    expect((await upload("task.md")).status).toBe(200);
    expect(history).toEqual(["start", "http", "start", "http", "https", "timeout", "exec"]);
  });

  it("resumes after eviction, observes the exit code and retains outputs for ten minutes", async () => {
    const { create, ledger, start, toBytes, storage, container } = fixture();
    await start();
    disk.set("/factory/task/exit-code", toBytes("0\n"));
    disk.set("/factory/out/events.jsonl", toBytes('{"type":"result","is_error":false}\n'));
    disk.set("/factory/out/patch.diff", toBytes("patch content"));
    const resumed = create();
    await resumed.alarm();
    expect(await resumed.status()).toMatchObject({ state: "finished", stop_reason: "completed", exit_code: 0 });
    expect(await (await resumed.output("patch.diff")).text()).toBe("patch content");
    expect((await resumed.output("probe.txt")).status).toBe(404);
    expect(storage.setAlarm).toHaveBeenLastCalledWith(Date.now() + 600_000);
    vi.setSystemTime(Date.now() + 600_000);
    await resumed.alarm();
    expect(await resumed.status()).toMatchObject({ state: "destroyed", stop_reason: "completed" });
    expect(ledger.deactivate).toHaveBeenLastCalledWith(true);
    expect(container.destroy).toHaveBeenCalledOnce();
    expect((await resumed.destroy()).status).toBe(204);
    expect(container.destroy).toHaveBeenCalledOnce();
    expect(storage.deleteAlarm).toHaveBeenCalled();
  });

  it.each(["time_limit", "budget_reached", "cancelled"] as const)("preserves %s and collects partial outputs", async reason => {
    const { run, start, container, ledger, upload, toBytes } = fixture();
    await upload("finish.sh");
    await start({ minutes: 1 });
    disk.set("/factory/task/exit-code", toBytes("0\n"));
    disk.set("/factory/out/events.jsonl", toBytes('{"type":"result","is_error":false}\n'));
    if (reason === "time_limit") {
      vi.setSystemTime(Date.now() + 60_000);
      ledger.budgetExhausted.mockResolvedValue(true);
      await run.alarm();
    } else if (reason === "budget_reached") {
      ledger.budgetExhausted.mockResolvedValue(true);
      await run.alarm();
    } else {
      expect((await run.stop("cancelled")).status).toBe(200);
    }
    expect((await run.stop("cancelled")).status).toBe(200);
    expect(await run.status()).toMatchObject({ state: "finished", stop_reason: reason, finish_ok: true, exit_code: 0 });
    expect(container.exec.mock.calls.map(([argv]) => argv[0])).toEqual(["install", "setsid", "bash", "bash"]);
    expect(container.exec.mock.calls[2]?.[0].at(-1)).toBe("123");
    expect(container.exec).toHaveBeenLastCalledWith(["bash", "/factory/delivery/finish.sh"], expect.objectContaining({
      user: "1000:1000", signal: expect.any(AbortSignal),
      env: expect.objectContaining({ FACTORY_WORK_DIR: "/factory/work", FACTORY_OUT_DIR: "/factory/out" }),
    }));
  });

  it("marks a missing container as lost and never executes in it again", async () => {
    const { run, start, lose, container } = fixture();
    await start();
    lose();
    await run.alarm();
    expect(await run.status()).toMatchObject({ state: "lost", stop_reason: "lost" });
    expect(container.exec).toHaveBeenCalledTimes(2);
  });
});

describe("result events", () => {
  it("skips malformed and oversized lines, selects the last result and caps Unicode text", async () => {
    const last = { type: "result", is_error: false, subtype: "success", num_turns: 12, total_cost_usd: 0.19, result: "🧪".repeat(201) };
    const body = new Response([
      '{"type":"result","is_error":true}', "ignored".repeat(200_000),
      JSON.stringify(last), "not JSON", '{"type":"system","ignored":true}',
    ].join("\n")).body;
    expect(await readResult(body)).toEqual({
      is_error: false, subtype: "success", num_turns: 12, total_cost_usd: 0.19, result_head: "🧪".repeat(200),
    });
  });
});
