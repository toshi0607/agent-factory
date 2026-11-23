import "./runtime";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { readResult, Run } from "../src/run";
import type { Caller, Env, StartRequest } from "../src/types";
import { startRequest } from "./fixtures";

const { disk, oversized } = vi.hoisted(() => ({
  disk: new Map<string, Uint8Array>(),
  oversized: new Map<string, { size: bigint; body: ReadableStream<Uint8Array>; signal?: AbortSignal }>(),
}));
vi.mock("@cloudflare/sandbox", () => {
  class SandboxFileError extends Error {
    readonly code = "ENOENT";
    static is(error: unknown) { return error instanceof SandboxFileError; }
  }
  class Files {
    async lstat(path: string) {
      const size = oversized.get(path)?.size ?? disk.get(path)?.byteLength;
      if (size === undefined) throw new SandboxFileError();
      return { type: "file", size: BigInt(size) };
    }
    async readFile(path: string, { signal }: { signal?: AbortSignal } = {}) {
      const output = oversized.get(path);
      if (output) {
        if (signal) output.signal = signal;
        return new Response(output.body);
      }
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
  repositoryId: crypto.randomUUID(), workflowPath: "path", workflowSha: "ab".repeat(20), run_id: "123", run_attempt: "1",
};

function fixture() {
  let running = false;
  let groupAlive = false;
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
      if (argv[3] === "factory-liveness") return { exitCode: Promise.resolve(groupAlive ? 0 : 1) };
      if (argv[0] === "tail") {
        return { stdout: new Response(disk.get(argv[4]!)?.slice(-Number(argv[2]))).body, exitCode: Promise.resolve(0) };
      }
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
  void run.claim(id, caller, false);
  const upload = (name: string, contents = "abc", size = contents.length) => run.upload(name, new Response(contents).body, size);
  const start = async (overrides: Partial<StartRequest> = {}) => {
    for (const file of ["manifest.json", "task.md"]) await upload(file);
    return run.start({ ...startRequest, ...overrides });
  };
  return {
    run, create, container, ledger, history, storage, outbound, inputs, upload, start, toBytes,
    lose: () => { running = false; }, setGroupAlive: (alive: boolean) => { groupAlive = alive; },
  };
}

beforeEach(() => {
  disk.clear();
  oversized.clear();
  vi.useFakeTimers({ toFake: ["Date"] });
});
afterEach(() => vi.useRealTimers());

describe("Run lifecycle", () => {
  it("claims a run once and hashes each upload with both intercepts active", async () => {
    const { run, create, container, upload, outbound, history } = fixture();
    expect(await run.claim(id, { ...caller, workflowPath: "different" }, false)).toBe("claimed");
    expect(await create().claim(id, { ...caller, repositoryId: crypto.randomUUID() }, false)).toBe("forbidden");
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
      cwd: "/factory", user: "0:0",
      env: expect.objectContaining({
        NODE_EXTRA_CA_CERTS: "/etc/cloudflare/certs/cloudflare-containers-ca.crt",
        SSL_CERT_FILE: "/etc/cloudflare/certs/cloudflare-containers-ca.crt",
        CURL_CA_BUNDLE: "/etc/cloudflare/certs/cloudflare-containers-ca.crt",
        GIT_SSL_CAINFO: "/etc/cloudflare/certs/cloudflare-containers-ca.crt",
      }),
    }));
    const launch = container.exec.mock.lastCall?.[0][5];
    expect(launch).toContain("/factory/ctl/pid");
    expect(launch).toContain("/factory/ctl/exit-code");
    expect(launch).toMatch(/setpriv --reuid=agent --regid=agent --init-groups --no-new-privs/);
    expect(launch).toContain(`'exec "$@" </dev/null >/factory/out/events.jsonl`);
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
    disk.set("/factory/ctl/exit-code", toBytes("0\n"));
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
    disk.set("/factory/ctl/exit-code", toBytes("0\n"));
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
    const kill = ["bash", "-c", "kill -KILL -1"];
    expect(container.exec.mock.calls.slice(2).map(([argv]) => argv)).toEqual([
      kill, ["bash", "/factory/delivery/finish.sh"], kill,
      ["tail", "-c", "262144", "--", "/factory/out/events.jsonl"],
    ]);
    expect(container.exec).toHaveBeenNthCalledWith(3, kill, expect.objectContaining({ user: "1000:1000" }));
    expect(container.exec).toHaveBeenNthCalledWith(4, ["bash", "/factory/delivery/finish.sh"], expect.objectContaining({
      user: "1000:1000", signal: expect.any(AbortSignal),
      env: expect.objectContaining({ FACTORY_WORK_DIR: "/factory/work", FACTORY_OUT_DIR: "/factory/out" }),
    }));
  });

  it("records the first workflow SHA and grants recovery without granting input changes", async () => {
    const { run, create } = fixture();
    for (const other of [{ run_id: "999" }, { run_attempt: "2" }]) {
      const recovery = { ...caller, ...other, workflowSha: "cd".repeat(20) };
      expect(await create().claim(id, recovery, false)).toBe("claimed");
      expect(await create().claim(id, recovery, true)).toBe("wrong_run");
    }
    expect(await run.claim(id, caller, true)).toBe("claimed");
    expect(await run.status()).toMatchObject({ caller_workflow_sha: caller.workflowSha });
  });

  it.each([false, true])("destroys an unstarted run after 15 minutes with uploaded files = %s", async uploaded => {
    const { run, create, storage, upload, container, ledger } = fixture();
    const expiry = Date.now() + 15 * 60_000;
    expect(storage.setAlarm).toHaveBeenCalledWith(expiry);
    if (uploaded) await upload("task.md");
    vi.setSystemTime(expiry - 1);
    const resumed = create();
    await resumed.alarm();
    expect((await run.status()).state).toBe("created");
    vi.setSystemTime(expiry);
    await resumed.alarm();
    expect(await run.status()).toMatchObject({ state: "destroyed", stop_reason: "cancelled" });
    expect(ledger.deactivate).toHaveBeenCalledWith(true);
    expect(container.destroy).toHaveBeenCalledTimes(Number(uploaded));
    expect(storage.deleteAlarm).toHaveBeenCalled();
  });

  it("ignores a legacy exit-code and trusts the protected exit-code with a live process group", async () => {
    const { run, start, toBytes, setGroupAlive, container, ledger } = fixture();
    await start();
    disk.set("/factory/task/exit-code", toBytes("0\n"));
    await run.alarm();
    expect((await run.status()).state).toBe("running");
    disk.set("/factory/ctl/exit-code", toBytes("0\n"));
    disk.set("/factory/out/events.jsonl", toBytes('{"type":"result","is_error":false}\n'));
    setGroupAlive(true);
    await run.alarm();
    expect(await run.status()).toMatchObject({ state: "finished", stop_reason: "completed" });
    expect(container.exec.mock.calls.some(([argv]) => argv[3] === "factory-liveness")).toBe(false);
    expect(ledger.deactivate).toHaveBeenCalledWith(false);
    expect(container.exec.mock.calls.slice(-2).map(([argv]) => argv)).toEqual([
      ["bash", "-c", "kill -KILL -1"], ["tail", "-c", "262144", "--", "/factory/out/events.jsonl"],
    ]);
  });

  it("waits for the recorded process group to exit before trusting a legacy exit-code", async () => {
    const { run, start, toBytes, setGroupAlive, container, ledger, storage } = fixture();
    await start();
    storage.kv.put("run", { ...storage.kv.get("run") as object, controlFilesProtected: undefined });
    disk.set("/factory/task/exit-code", toBytes("0\n"));
    disk.set("/factory/out/events.jsonl", toBytes('{"type":"result","is_error":false}\n'));
    setGroupAlive(true);
    await run.alarm();
    expect((await run.status()).state).toBe("running");
    expect(container.exec).toHaveBeenLastCalledWith(
      ["bash", "-c", expect.stringContaining("kill -0"), "factory-liveness", "123"],
      expect.objectContaining({ user: "0:0" }),
    );
    expect(ledger.deactivate).not.toHaveBeenCalled();
    setGroupAlive(false);
    await run.alarm();
    expect(await run.status()).toMatchObject({ state: "finished", stop_reason: "completed" });
    expect(container.exec.mock.calls.slice(-2).map(([argv]) => argv)).toEqual([
      ["bash", "-c", "kill -KILL -1"], ["tail", "-c", "262144", "--", "/factory/out/events.jsonl"],
    ]);
  });

  it("still kills the agent and runs finish at the deadline with a live process group", async () => {
    const { run, start, upload, setGroupAlive, toBytes, container } = fixture();
    await upload("finish.sh");
    await start({ minutes: 1 });
    setGroupAlive(true);
    await run.alarm();
    expect((await run.status()).state).toBe("running");
    disk.set("/factory/ctl/exit-code", toBytes("0\n"));
    container.exec.mockResolvedValueOnce({ exitCode: Promise.resolve(1) });
    vi.setSystemTime(Date.now() + 60_000);
    await run.alarm();
    expect(await run.status()).toMatchObject({ stop_reason: "time_limit", finish_ok: true });
  });

  it("reads results only from the last 256 KiB", async () => {
    const { run, start, toBytes, container } = fixture();
    await start();
    disk.set("/factory/ctl/exit-code", toBytes("0\n"));
    disk.set("/factory/out/events.jsonl", toBytes(
      '{"type":"result","is_error":false}\n' + "a".repeat(256 * 1024) + "\n",
    ));
    await run.alarm();
    expect(await run.status()).toMatchObject({ stop_reason: "agent_error", agent_result: null });
    expect(container.exec).toHaveBeenLastCalledWith(
      ["tail", "-c", "262144", "--", "/factory/out/events.jsonl"],
      expect.objectContaining({ user: "1000:1000", signal: expect.any(AbortSignal) }),
    );
  });

  it.each([false, true])("caps an output stream at 64 MiB, with an oversized file = %s", async truncated => {
    const { run, start } = fixture();
    await start();
    const chunk = new Uint8Array(1024 * 1024);
    let remaining = 64;
    const cancel = vi.fn();
    const source = {
      size: BigInt(64 * chunk.length + Number(truncated)),
      body: new ReadableStream<Uint8Array>({
        pull(controller) {
          if (remaining-- > 0) controller.enqueue(chunk);
          else if (truncated) controller.enqueue(chunk.subarray(0, 1));
          else controller.close();
        },
        cancel,
      }),
    };
    const path = "/factory/out/stderr.log";
    oversized.set(path, source);
    const response = await run.output("stderr.log");
    expect(response.headers.get("x-factory-truncated")).toBe(truncated ? "1" : null);
    expect(oversized.get(path)?.signal).toBeInstanceOf(AbortSignal);
    const reader = response.body!.getReader();
    let bytes = 0;
    for (let part = await reader.read(); !part.done; part = await reader.read()) bytes += part.value.length;
    expect(bytes).toBe(64 * chunk.length);
    if (truncated) await vi.waitFor(() => expect(cancel).toHaveBeenCalledOnce());
  });

  it("aborts a stalled output read at its timeout", async () => {
    const { run, start } = fixture();
    await start();
    const abort = new AbortController();
    const realTimeout = AbortSignal.timeout;
    const timeout = vi.spyOn(AbortSignal, "timeout").mockImplementation(ms => ms === 600_000 ? abort.signal : realTimeout(ms));
    const cancel = vi.fn();
    try {
      oversized.set("/factory/out/stderr.log", { size: 1n, body: new ReadableStream({ cancel }) });
      const response = await run.output("stderr.log");
      expect(timeout.mock.calls).toEqual([[5_000], [600_000]]);
      const result = response.text();
      const rejected = expect(result).rejects.toMatchObject({ name: "TimeoutError" });
      abort.abort(new DOMException("Timed out", "TimeoutError"));
      await rejected;
      expect(cancel).toHaveBeenCalledOnce();
    } finally {
      timeout.mockRestore();
    }
  });

  it("abandons a stalled result read at 30 seconds and finalizes the run", async () => {
    const { run, start, toBytes, container } = fixture();
    await start();
    disk.set("/factory/ctl/exit-code", toBytes("0\n"));
    disk.set("/factory/out/events.jsonl", toBytes("incomplete"));
    const abort = new AbortController();
    const realTimeout = AbortSignal.timeout;
    const timeout = vi.spyOn(AbortSignal, "timeout").mockImplementation(ms => ms === 30_000 ? abort.signal : realTimeout(ms));
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const cancel = vi.fn();
    try {
      container.exec.mockResolvedValueOnce({ exitCode: Promise.resolve(0) }); // Kill escaped processes.
      container.exec.mockImplementationOnce(async () => {
        const stdout = new ReadableStream({ cancel });
        queueMicrotask(() => abort.abort(new DOMException("Timed out", "TimeoutError")));
        return { stdout, exitCode: Promise.resolve(0) };
      });
      await run.alarm();
      expect(timeout).toHaveBeenCalledWith(30_000);
      expect(await run.status()).toMatchObject({ state: "finished", agent_result: null });
      expect(cancel).toHaveBeenCalledOnce();
    } finally {
      timeout.mockRestore();
      warn.mockRestore();
    }
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
