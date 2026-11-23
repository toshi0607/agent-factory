import { vi } from "vitest";

vi.mock("cloudflare:workers", () => {
  class Entrypoint {
    constructor(protected ctx: unknown, protected env: unknown) {}
  }
  return { DurableObject: Entrypoint, WorkerEntrypoint: Entrypoint };
});
