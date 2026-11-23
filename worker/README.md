# Cloudflare Sandbox worker

`src/index.ts` serves the authenticated run API. The Run Durable Object manages
a container and its files. The Ledger Durable Object tracks token expiry,
usage, budget, and egress. The outbound entrypoint enforces the HTTPS allowlist
and adds the bearer credential to the two supported Anthropic Messages endpoints.
The image contains the Sandbox shim, Claude Code, and the Go toolchain.

## Tests

With the pinned dependencies already installed, run these commands from this
directory using Node.js 26.

```sh
npx tsc --noEmit
npx vitest run
```

The tests use Node, generated signing keys, and fake upstream and container
bindings.

## Local development

`npm run dev` selects `wrangler.dev.jsonc` and `src/dev.ts`. The local driver
sets the four OIDC vars and `DEV_JWKS` in `.dev.vars`, signs its test JWTs with
the corresponding private key, uploads `dev-agent.sh`, and supplies a generated
test token. Anthropic requests receive a local SSE fixture or a count response.
The fixture returns `x-dev-saw-bearer` with `match` or `mismatch`. Allowed
read-only hosts use ordinary upstream fetches.

## Deployment inputs

Use `wrangler.jsonc` in a Cloudflare account with Workers, SQLite Durable
Objects, and Containers enabled. Supply `OIDC_AUDIENCE`,
`ALLOWED_REPOSITORY_ID`, `ALLOWED_REPOSITORY_OWNER_ID`,
`ALLOWED_JOB_WORKFLOWS`, and `FACTORY_COMMIT` at deploy time with `--var`.
Set `ALLOWED_JOB_WORKFLOWS` to comma-separated workflow paths without refs.
The caller provides and refreshes the short-lived Claude token through
`PUT /runs/{id}/token`. If the caller ships the current repository
`sandbox/setup.sh`, that script also requires a Go archive in the delivery
manifest, even though the container includes Go at `/opt/go`.
