import { readFileSync } from "node:fs";
import { URL } from "node:url";
import { expect, it } from "vitest";
import { agentCommand } from "../src/agent";

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
