import { beforeAll, describe, expect, it, vi } from "vitest";
import { createApp } from "../src/app";
import { createVerifier } from "../src/oidc";
import type { Env, OidcEnv } from "../src/types";

const time = 1_800_000_000;
const path = "example/factory/.github/workflows/p0-run.yml";
const env: OidcEnv = {
  OIDC_AUDIENCE: "factory",
  ALLOWED_REPOSITORY_ID: String(crypto.getRandomValues(new Uint32Array(1))[0]),
  ALLOWED_REPOSITORY_OWNER_ID: String(crypto.getRandomValues(new Uint32Array(1))[0]),
  ALLOWED_REFS: "refs/tags/recovery, refs/heads/main",
  ALLOWED_JOB_WORKFLOWS: `example/other/.github/workflows/p0-run.yml, ${path}`,
};
const claims = {
  iss: "https://token.actions.githubusercontent.com",
  aud: env.OIDC_AUDIENCE,
  exp: time + 900, nbf: time - 10, iat: time - 10,
  repository_id: env.ALLOWED_REPOSITORY_ID, repository_owner_id: env.ALLOWED_REPOSITORY_OWNER_ID,
  job_workflow_ref: `${path}@refs/heads/main`,
  job_workflow_sha: "ab".repeat(20),
  ref: "refs/heads/main", run_id: "1234", run_attempt: "2",
};
let pair: CryptoKeyPair;
let jwk: JsonWebKey;

beforeAll(async () => {
  const generated = await crypto.subtle.generateKey({
    name: "RSASSA-PKCS1-v1_5", modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256",
  }, true, ["sign", "verify"]);
  if (!("publicKey" in generated)) throw new Error("Expected an RSA key pair");
  pair = generated;
  const exported = await crypto.subtle.exportKey("jwk", pair.publicKey);
  if (exported instanceof ArrayBuffer) throw new Error("Expected a JWK");
  jwk = exported;
});

function jwks(kid = "primary") {
  return { keys: [{ ...jwk, kid, alg: "RS256", use: "sig" }] };
}

async function jwt(payload: Record<string, unknown> = {}, header: Record<string, unknown> = {}) {
  const base64 = (part: object) => Buffer.from(JSON.stringify(part)).toString("base64url");
  const input = `${base64({ alg: "RS256", kid: "primary", ...header })}.${base64({ ...claims, ...payload })}`;
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, new TextEncoder().encode(input));
  return `Bearer ${input}.${Buffer.from(signature).toString("base64url")}`;
}

const verifier = () => createVerifier(async () => jwks(), () => time * 1000);

describe("GitHub OIDC", () => {
  it.each([[claims.aud], [[claims.aud]]])("accepts a valid token with audience %j", async aud => {
    expect(await verifier()(await jwt({ aud }), env)).toEqual({
      ok: true, caller: {
        repositoryId: env.ALLOWED_REPOSITORY_ID, workflowPath: path, workflowSha: claims.job_workflow_sha,
        run_id: claims.run_id, run_attempt: claims.run_attempt,
      },
    });
  });

  it.each(["none", "HS256", "rs256"])("rejects the %s algorithm before fetching keys", async alg => {
    const fetcher = vi.fn(async () => jwks());
    expect(await createVerifier(fetcher)(await jwt({}, { alg }), env)).toEqual({ ok: false, error: "invalid_token" });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it.each([
    ["issuer", { iss: "https://example.invalid" }, "invalid_token"],
    ["wrong audience", { aud: "different" }, "wrong_audience"],
    ["extra audience", { aud: [claims.aud, "extra"] }, "wrong_audience"],
    ["duplicated audience", { aud: [claims.aud, claims.aud] }, "wrong_audience"],
    ["expired", { exp: time }, "expired"],
    ["future nbf", { nbf: time + 61 }, "invalid_token"],
    ["future iat", { iat: time + 61 }, "invalid_token"],
    ["missing iat", { iat: undefined }, "invalid_token"],
    ["long lifetime", { exp: time + 3600 }, "invalid_token"],
    ["repository id", { repository_id: claims.repository_id + "1" }, "wrong_repository"],
    ["owner id", { repository_owner_id: claims.repository_owner_id + "1" }, "wrong_repository"],
    ["numeric id", { repository_id: Number(claims.repository_id) }, "wrong_repository"],
    ["workflow suffix", { job_workflow_ref: `${path}.evil@x` }, "wrong_workflow"],
    ["wrong repository path", { job_workflow_ref: "unrelated/factory/.github/workflows/p0-run.yml@x" }, "wrong_workflow"],
    ["missing ref", { job_workflow_ref: `${path}@` }, "wrong_workflow"],
    ["different branch", { ref: "refs/heads/main-staging" }, "wrong_ref"],
    ["missing ref claim", { ref: undefined }, "wrong_ref"],
    ["numeric run id", { run_id: 1234 }, "invalid_token"],
    ["missing run id", { run_id: undefined }, "invalid_token"],
    ["empty attempt", { run_attempt: "" }, "invalid_token"],
    ["malformed attempt", { run_attempt: "2a" }, "invalid_token"],
    ["missing attempt", { run_attempt: undefined }, "invalid_token"],
    ["workflow commit", { job_workflow_sha: "g".repeat(40) }, "wrong_workflow"],
  ] as const)("rejects %s", async (_label, payload, error) => {
    expect(await verifier()(await jwt(payload), env)).toEqual({ ok: false, error });
  });

  it("rejects an empty ref list and accepts another exact configured ref", async () => {
    const verify = verifier();
    expect(await verify(await jwt(), { ...env, ALLOWED_REFS: ", ," })).toEqual({ ok: false, error: "misconfigured" });
    expect((await verify(await jwt({ ref: "refs/tags/recovery" }), env)).ok).toBe(true);
  });

  it("allows 60 seconds of clock skew for nbf and iat", async () => {
    expect((await verifier()(await jwt({ nbf: time + 60, iat: time + 60 }), env)).ok).toBe(true);
  });

  it("rejects an unknown kid, a missing kid, and a tampered signature", async () => {
    const verify = verifier();
    expect(await verify(await jwt({}, { kid: "unknown" }), env)).toEqual({ ok: false, error: "invalid_token" });
    expect(await verify(await jwt({}, { kid: undefined }), env)).toEqual({ ok: false, error: "invalid_token" });
    const signed = await jwt();
    const index = signed.lastIndexOf(".") + 1;
    const tampered = signed.slice(0, index) + (signed[index] === "A" ? "B" : "A") + signed.slice(index + 1);
    expect(await verify(tampered, env)).toEqual({ ok: false, error: "invalid_token" });
  });

  it("caches keys, throttles unknown kids and refreshes after ten minutes", async () => {
    let offset = 0;
    let current = jwks();
    const fetcher = vi.fn(async () => current);
    const verify = createVerifier(fetcher, () => time * 1000 + offset);
    const good = await jwt();
    const rotated = await jwt({}, { kid: "rotated" });
    const unknown = await jwt({}, { kid: "unknown" });
    expect((await verify(good, env)).ok).toBe(true);
    expect((await verify(good, env)).ok).toBe(true);
    expect(fetcher).toHaveBeenCalledTimes(1);
    current = jwks("rotated");
    const [knownAfterRefresh, unknownDuringRefresh] = await Promise.all([verify(rotated, env), verify(unknown, env)]);
    expect(knownAfterRefresh.ok).toBe(true);
    expect(unknownDuringRefresh.ok).toBe(false);
    expect(fetcher).toHaveBeenCalledTimes(2);
    offset = 60_000;
    expect((await verify(unknown, env)).ok).toBe(false);
    expect(fetcher).toHaveBeenCalledTimes(3);
    offset += 599_999;
    expect((await verify(rotated, env)).ok).toBe(true);
    expect(fetcher).toHaveBeenCalledTimes(3);
    offset += 1;
    expect((await verify(rotated, env)).ok).toBe(true);
    expect(fetcher).toHaveBeenCalledTimes(4);
  });

  it.each(Object.keys(env) as (keyof OidcEnv)[])("returns 500 when %s is empty or absent", async key => {
    const signed = await jwt();
    const app = createApp({ verify: verifier() });
    const request = new Request("https://worker.invalid/no-route", {
      headers: { authorization: signed },
    }) as Parameters<NonNullable<typeof app.fetch>>[0];
    for (const overrides of [{ [key]: "" }, { [key]: undefined }]) {
      const response = await app.fetch?.(request, { ...env, ...overrides } as Env, {} as ExecutionContext);
      expect(response?.status).toBe(500);
      expect(await response?.json()).toEqual({ error: "misconfigured", message: "Authentication is not configured" });
    }
  });
});
