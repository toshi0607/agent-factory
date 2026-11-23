import { agentCommand, type AgentInput } from "./agent";
import { createApp } from "./app";
import { createVerifier, type Verify } from "./oidc";
import { Outbound as ProductionOutbound, type OutboundLedger } from "./outbound";
import { Run as ProductionRun } from "./run";
import type { Env } from "./types";

export { Ledger } from "./ledger";

interface LocalEnv extends Env {
  DEV_JWKS: string;
}

export class Run extends ProductionRun {
  protected override command(input: AgentInput) {
    return { argv: ["bash", "/factory/delivery/dev-agent.sh"], env: agentCommand(input).env };
  }
}

export class Outbound extends ProductionOutbound {
  protected override upstream(ledger: OutboundLedger): typeof fetch {
    return async (input, init) => {
      const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
      if (url.hostname !== "api.anthropic.com") return fetch(input, init);
      const authorization = await ledger.authorize(false);
      const header = new Headers(init?.headers).get("authorization");
      const match = authorization.ok && header === `Bearer ${authorization.token}`;
      const headers = { "x-dev-saw-bearer": match ? "match" : "mismatch" };
      if (url.pathname === "/v1/messages/count_tokens") return Response.json({ input_tokens: 1000 }, { headers });
      const events = [
        { type: "message_start", message: { usage: { input_tokens: 1000 } } },
        { type: "message_delta", usage: { output_tokens: 500 } },
        { type: "message_stop" },
      ];
      const encoder = new TextEncoder();
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          for (const event of events) {
            controller.enqueue(encoder.encode(`event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`));
          }
          controller.close();
        },
      });
      return new Response(body, { headers: { ...headers, "content-type": "text/event-stream" } });
    };
  }
}

let cached: { json: string; verify: Verify } | undefined;
export default createApp({
  verify(authorization, env) {
    const json = (env as LocalEnv).DEV_JWKS;
    if (!cached || cached.json !== json) {
      cached = { json, verify: createVerifier(async () => JSON.parse(json)) };
    }
    return cached.verify(authorization, env);
  },
});
