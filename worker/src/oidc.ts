import { object, type Caller, type OidcEnv } from "./types";

const ISSUER = "https://token.actions.githubusercontent.com";
const JWKS_URL = "https://token.actions.githubusercontent.com/.well-known/jwks";
const CACHE_MS = 10 * 60_000;
const MAX_KEY_AGE_MS = 60 * 60_000;
const REFRESH_MS = 60_000;
const RSA = "RSASSA-PKCS1-v1_5";

type AuthError = "misconfigured" | "invalid_token" | "wrong_audience" | "wrong_repository"
  | "wrong_workflow" | "wrong_ref" | "expired" | "unavailable";

export type Verification = { ok: true; caller: Caller } | { ok: false; error: AuthError };
export type Verify = (authorization: string | null, env: OidcEnv) => Promise<Verification>;
const fail = (error: AuthError): Verification => ({ ok: false, error });

function isAnthropicAudience(audience: string): boolean {
  if (audience.trim().toLowerCase().includes("anthropic.com")) return true;
  try {
    const value = audience.trim();
    const host = new URL(value.startsWith("//") ? "https:" + value : value).hostname.toLowerCase().replace(/\.$/, "");
    return host === "anthropic.com" || host.endsWith(".anthropic.com");
  } catch {
    return false;
  }
}

function decode(part: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(part)) throw new Error("invalid base64url");
  const standard = part.replaceAll("-", "+").replaceAll("_", "/");
  const bytes = atob(standard);
  if (btoa(bytes).replace(/=+$/, "") !== standard) throw new Error("invalid base64url");
  return Uint8Array.from(bytes, char => char.charCodeAt(0));
}

function jsonPart(part: string): Record<string, unknown> | undefined {
  return object(JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(decode(part))));
}

function timestamp(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function claims(payload: Record<string, unknown>, env: OidcEnv, seconds: number): Verification {
  const { iss, aud, exp, nbf, iat, repository_id, repository_owner_id,
    job_workflow_ref, job_workflow_sha, ref, run_id, run_attempt } = payload;
  if (iss !== ISSUER || !timestamp(exp) || !timestamp(nbf) || !timestamp(iat)
    || iat > seconds + 60 || nbf > seconds + 60 || exp <= iat || exp <= nbf || exp - iat > 3600) {
    return fail("invalid_token");
  }
  if (exp <= seconds) return fail("expired");
  const audience = Array.isArray(aud) && aud.length === 1 ? aud[0] : aud;
  if (audience !== env.OIDC_AUDIENCE) return fail("wrong_audience");
  if (repository_id !== env.ALLOWED_REPOSITORY_ID || repository_owner_id !== env.ALLOWED_REPOSITORY_OWNER_ID) {
    return fail("wrong_repository");
  }

  const at = typeof job_workflow_ref === "string" ? job_workflow_ref.indexOf("@") : -1;
  if (typeof job_workflow_ref !== "string" || at < 1 || at === job_workflow_ref.length - 1
    || typeof job_workflow_sha !== "string" || !/^[0-9a-f]{40}$/i.test(job_workflow_sha)) {
    return fail("wrong_workflow");
  }
  const workflowPath = job_workflow_ref.slice(0, at);
  if (!env.ALLOWED_JOB_WORKFLOWS.split(",").some(path => path.trim() === workflowPath)) {
    return fail("wrong_workflow");
  }
  if (typeof ref !== "string" || ref === "" || !env.ALLOWED_REFS.split(",").some(value => value.trim() === ref)) {
    return fail("wrong_ref");
  }
  if (typeof run_id !== "string" || !/^\d+$/.test(run_id)
    || typeof run_attempt !== "string" || !/^\d+$/.test(run_attempt)) return fail("invalid_token");
  return { ok: true, caller: { repositoryId: repository_id, workflowPath, workflowSha: job_workflow_sha, run_id, run_attempt } };
}

export function createVerifier(fetchJwks: () => Promise<unknown>, now = Date.now): Verify {
  let keys: unknown[] | undefined;
  let fetchedAt = -Infinity;
  let unknownRefreshAt = -Infinity;

  async function refresh(): Promise<unknown[] | undefined> {
    try {
      const fetched = object(await fetchJwks())?.keys;
      if (!Array.isArray(fetched)) throw new Error("invalid JWKS");
      keys = fetched;
      fetchedAt = now();
      return fetched;
    } catch {
      return now() <= fetchedAt + MAX_KEY_AGE_MS ? keys : undefined;
    }
  }

  function findKey(jwks: unknown[], kid: string): Record<string, unknown> | undefined {
    const matching = jwks.map(object).filter(key => key?.kid === kid);
    return matching.length === 1 ? matching[0] : undefined;
  }

  async function selectKey(kid: string): Promise<JsonWebKey | "unavailable" | undefined> {
    const cached = now() < fetchedAt + CACHE_MS ? keys : undefined;
    let jwks = cached ?? await refresh();
    if (!jwks) return "unavailable";
    let key = findKey(jwks, kid);
    if (!key && cached && now() >= unknownRefreshAt) {
      unknownRefreshAt = now() + REFRESH_MS;
      jwks = await refresh();
      if (!jwks) return "unavailable";
      key = findKey(jwks, kid);
    }
    if (key?.kty !== "RSA" || typeof key.n !== "string" || typeof key.e !== "string"
      || (key.use !== undefined && key.use !== "sig")
      || (key.alg !== undefined && key.alg !== "RS256")
      || (key.key_ops !== undefined && (!Array.isArray(key.key_ops) || !key.key_ops.includes("verify")))) {
      return undefined;
    }
    return { kty: "RSA", n: key.n, e: key.e };
  }

  return async (authorization, env) => {
    const config = [env.OIDC_AUDIENCE, env.ALLOWED_REPOSITORY_ID,
      env.ALLOWED_REPOSITORY_OWNER_ID, env.ALLOWED_JOB_WORKFLOWS, env.ALLOWED_REFS];
    if (config.some(value => typeof value !== "string" || value.trim() === "")
      || isAnthropicAudience(env.OIDC_AUDIENCE)
      || !env.ALLOWED_JOB_WORKFLOWS.split(",").some(path => path.trim() !== "")
      || !env.ALLOWED_REFS.split(",").some(ref => ref.trim() !== "")) {
      return fail("misconfigured");
    }
    if (!authorization || authorization.length > 32 * 1024) return fail("invalid_token");
    const match = /^Bearer ([\w-]+)\.([\w-]+)\.([\w-]+)$/i.exec(authorization);
    const [, encodedHeader, encodedPayload, signature] = match ?? [];
    if (!encodedHeader || !encodedPayload || !signature) return fail("invalid_token");
    try {
      const header = jsonPart(encodedHeader);
      if (header?.alg !== "RS256" || typeof header.kid !== "string" || !header.kid
        || header.crit !== undefined) return fail("invalid_token");
      const jwk = await selectKey(header.kid);
      if (jwk === "unavailable") return fail(jwk);
      if (!jwk) return fail("invalid_token");
      const key = await crypto.subtle.importKey("jwk", jwk, { name: RSA, hash: "SHA-256" }, false, ["verify"]);
      const input = new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`);
      if (!await crypto.subtle.verify(RSA, key, decode(signature), input)) return fail("invalid_token");
      const payload = jsonPart(encodedPayload);
      return payload ? claims(payload, env, Math.floor(now() / 1000)) : fail("invalid_token");
    } catch {
      return fail("invalid_token");
    }
  };
}

export async function fetchGitHubJwks(): Promise<unknown> {
  const response = await fetch(JWKS_URL, { redirect: "manual", signal: AbortSignal.timeout(5_000) });
  if (!response.ok) throw new Error("JWKS request failed");
  return response.json();
}
