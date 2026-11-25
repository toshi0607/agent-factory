import { readFileSync } from "node:fs";
import { URL } from "node:url";
import { expect, it, vi } from "vitest";
import config from "../cloudflare.config";
import { agentCommand } from "../src/agent";

it("trims required deployment environment values before binding them", () => {
  const values = {
    OIDC_AUDIENCE: "example-audience",
    ALLOWED_REPOSITORY_ID: "123",
    ALLOWED_REPOSITORY_OWNER_ID: "456",
    ALLOWED_JOB_WORKFLOWS: "example/factory/.github/workflows/example.yml",
    ALLOWED_REFS: "refs/heads/main",
    FACTORY_COMMIT: "abc",
  };
  try {
    for (const [name, value] of Object.entries(values)) {
      vi.stubEnv(name === "FACTORY_COMMIT" ? name : `FACTORY_${name}`, ` ${value}\n`);
    }
    const bindings = config().worker.env;
    for (const [name, value] of Object.entries(values)) {
      expect(bindings[name as keyof typeof values].value).toBe(value);
    }
  } finally {
    vi.unstubAllEnvs();
  }
});

it("keeps the fixed Claude command and environment", () => {
  expect(agentCommand({
    model: "claude-example", systemPromptPath: "/factory/task/system-prompt.txt", userMessage: "--system-prompt=argument",
  })).toMatchInlineSnapshot(`
    {
      "argv": [
        "claude",
        "--print",
        "--bare",
        "--output-format",
        "stream-json",
        "--verbose",
        "--dangerously-skip-permissions",
        "--no-session-persistence",
        "--strict-mcp-config",
        "--disable-slash-commands",
        "--setting-sources",
        "",
        "--tools",
        "Bash,Read,Write,Edit,Glob,Grep",
        "--model",
        "claude-example",
        "--system-prompt-file",
        "/factory/task/system-prompt.txt",
        "--",
        "--system-prompt=argument",
      ],
      "env": {
        "ANTHROPIC_API_KEY": "provided-by-worker",
        "ANTHROPIC_DEFAULT_HAIKU_MODEL": "claude-example",
        "ANTHROPIC_MODEL": "claude-example",
        "ANTHROPIC_SMALL_FAST_MODEL": "claude-example",
        "CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS": "1",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_AUTOUPDATER": "1",
        "DISABLE_TELEMETRY": "1",
        "FACTORY_CANDIDATE": "cloudflare-sandbox",
        "FACTORY_GO_ROOT": "/opt/go",
        "FACTORY_OUT_DIR": "/factory/out",
        "FACTORY_WORK_DIR": "/factory/work",
        "HOME": "/home/agent",
        "PATH": "/opt/go/bin:/usr/local/bin:/usr/bin:/bin",
      },
    }
  `);
});

it.each(["index", "app", "run", "ledger", "outbound", "oidc"])("keeps local switches out of %s.ts", file => {
  const source = readFileSync(new URL(`../src/${file}.ts`, import.meta.url), "utf8");
  expect(source).not.toMatch(/DEV_JWKS|dev-agent|x-dev-|from ["']\.\/dev(?:\.[tj]s)?["']/);
});
