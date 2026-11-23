export interface AgentInput {
  model: string;
  systemPromptPath: string;
  userMessage: string;
}

export interface AgentCommand {
  argv: string[];
  env: Record<string, string>;
}

export function agentCommand({ model, systemPromptPath, userMessage }: AgentInput): AgentCommand {
  return {
    argv: [
      "claude", "--print", "--bare", "--output-format", "stream-json", "--verbose",
      "--dangerously-skip-permissions", "--no-session-persistence", "--strict-mcp-config",
      "--disable-slash-commands", "--setting-sources", "", "--tools",
      "Bash", "Read", "Write", "Edit", "Glob", "Grep",
      "--model", model, "--system-prompt-file", systemPromptPath, "--", userMessage,
    ],
    env: {
      ANTHROPIC_API_KEY: "provided-by-worker",
      ANTHROPIC_MODEL: model,
      ANTHROPIC_SMALL_FAST_MODEL: model,
      ANTHROPIC_DEFAULT_HAIKU_MODEL: model,
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
      DISABLE_AUTOUPDATER: "1",
      DISABLE_TELEMETRY: "1",
      HOME: "/home/agent",
      FACTORY_WORK_DIR: "/factory/work",
      FACTORY_OUT_DIR: "/factory/out",
      FACTORY_GO_ROOT: "/opt/go",
      FACTORY_CANDIDATE: "cloudflare-sandbox",
      PATH: "/opt/go/bin:/usr/local/bin:/usr/bin:/bin",
    },
  };
}
