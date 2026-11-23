import type { StartRequest } from "../src/types";

export const startRequest: StartRequest = {
  role: "fixer", model: "claude-example",
  system_prompt: "Read the task.", user_message: "Run the task.",
  budget_cents: 300, minutes: 30,
  prices: { input: 400, output: 2000, cache_write_5m: 500, cache_write_1h: 800, cache_read: 40 },
  egress: [{ host: "proxy.golang.org" }, { host: "storage.googleapis.com", path_prefixes: ["/proxy-golang-org-prod/"] }],
};
