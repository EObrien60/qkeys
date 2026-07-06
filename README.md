# qkeys

**Boring, reliable scoped API keys for OBH SaaS products.** A small internal
platform component for machine-to-machine access: create, authenticate, scope,
rotate, revoke, and audit API keys — so products never hand-roll unsafe tokens.

> Do one thing well: **authenticate and authorize non-human API callers.**

This is **not** OAuth, not a full IAM system, and not a developer portal. Auth
still owns users, sessions, workspaces, roles, and RBAC. qkeys only issues machine
credentials and carries **scopes** — the app's permission middleware decides what
those scopes allow.

```
create key ─▶ show plaintext once ─▶ store only the hash
                                         │
incoming request: Authorization: Bearer obh_live_k…_secret
                                         ▼
        parse ─▶ lookup by prefix ─▶ verify hash (constant-time)
              ─▶ check active + not expired ─▶ auth context ─▶ record last-used
```

## Layout

```
packages/api-keys   @obh/api-keys        — framework-agnostic core SDK
packages/hono       @obh/api-keys-hono   — Hono middleware (hono is a peer dep)
apps/keysd          obh-keysd            — optional expiry-sweeper worker
```

Each SaaS uses these in-process in its API, against its own Postgres. Tables live
in the `platform.*` schema alongside the other OBH platform components.

## Key format

```
obh_<env>_<keyId>_<secret>        env: live | test | dev
obh_live_k9f2c1a0b3d4e5f6a7_5bKx8…
```

- `obh` — fixed namespace, so a leaked key is greppable and identifiable.
- `keyId` — public lookup id (no underscore), stored as the unique `key_prefix`.
- `secret` — 192 bits of randomness. **Only an HMAC-SHA256 hash of the secret is
  stored** (keyed with a server-side pepper); the plaintext key is shown **once**.

## Quickstart

```bash
pnpm install
docker compose up -d

cd apps/keysd
DATABASE_URL=postgres://postgres:postgres@localhost:5432/qkeys_dev \
API_KEYS_PEPPER=dev-pepper pnpm migrate
```

```ts
import { createApiKeysClient, pgAdapter } from "@obh/api-keys"
import { Pool } from "pg"

const apiKeys = createApiKeysClient({
  db: pgAdapter(new Pool({ connectionString: process.env.DATABASE_URL })),
  pepper: process.env.API_KEYS_PEPPER!,   // required
  events: myEventSink,                     // optional (wire to @obh/events)
})

// Create — plaintext key returned ONCE:
const created = await apiKeys.create({
  workspaceId,
  name: "Customer ERP integration",
  scopes: ["consignments.read", "consignments.write"],
  createdBy: actorId,
})
// created.key === "obh_live_k…_…"  → show to the user now; it's never retrievable again.

// Authenticate an incoming bearer token:
const ctx = await apiKeys.authenticate(rawKey, { ip, userAgent, route, method })
// { principalType: "api_key", principalId, workspaceId, scopes, keyName, environment }
```

## Hono middleware

```ts
import { apiKeyAuth, requireApiScope } from "@obh/api-keys-hono"

app.use("/api/external/*", apiKeyAuth({ client: apiKeys }))

app.post(
  "/api/external/consignments",
  requireApiScope("consignments.write"),
  (c) => {
    const key = c.get("apiKey") // ApiKeyAuthContext
    // ...
  },
)
```

`apiKeyAuth` authenticates the bearer token, stashes the context on `c.get("apiKey")`,
and records a usage row after the handler runs. `requireApiScope` enforces a scope
(403 if missing). The core is framework-agnostic — `authenticateRequest()` and
`requireScopeOrThrow()` back any other framework.

## Scopes

Strings, with exact match plus an optional suffix wildcard — no policy language:

```
consignments.read   consignments.write   pods.read   vehicles.*   *
```

`hasScope(["consignments.*"], "consignments.write") === true`. RBAC is **not**
here; a key just carries scopes and the app decides what they permit.

## API

| Method | Purpose |
| --- | --- |
| `create(input)` | Issue a key; returns plaintext **once**. |
| `authenticate(rawKey, meta?)` | Verify a bearer token → auth context; updates last-used. |
| `revoke(input)` | Permanently disable a key. |
| `rotate(input)` | Create a replacement (same scopes) and revoke the old key, linked via `rotated_from`. |
| `list(input)` | Cursor-paginated, workspace-scoped, newest-first (no secrets). |
| `get({ workspaceId, id })` | Fetch one key (no secret). |
| `recordUsage(input)` | Append a usage row (route/method/ip/status). |
| `hasScope(ctx, scope)` | Scope check helper. |
| `sweepExpired(args?)` | Mark active-but-past-expiry keys `expired`. |

## Events

Wire an `EventSink` to emit control-plane events (consumable by qaudit). Emitted
on **create / revoke / rotate** (and `expired` from the sweep). `api_key.used` is
**not** emitted per request by default (too noisy — set `emitUsageEvents: true` to
opt in). Payloads never contain plaintext key material.

```
api_key.created   api_key.revoked   api_key.rotated   api_key.expired   api_key.used*
```

## Security

- Never stores plaintext keys; plaintext is shown once at create/rotate.
- HMAC-SHA256 keyed with a **required** server-side pepper (`API_KEYS_PEPPER`).
- Constant-time secret comparison; a dummy compare keeps timing stable for unknown keys.
- Revoked and expired keys never authenticate; keys are workspace-scoped.
- The client logs only key ids / prefixes — never secrets or the Authorization header.

## Expiry

`authenticate()` treats any key past `expires_at` as expired **immediately** — no
scheduled job is required for correctness. `obh-keysd` is an optional tidy-up that
flips the `status` column to `expired` and (with a sink) emits `api_key.expired`.

## Schema

`platform.api_keys` (keys, hashed secrets, scopes, status, last-used) and
`platform.api_key_usage` (append-only usage log). See
[`packages/api-keys/src/migrations/0001_init.sql`](packages/api-keys/src/migrations/0001_init.sql).

## Testing

```bash
pnpm test                     # unit tests (key format, scopes, hashing, Hono middleware)

docker compose up -d
DATABASE_URL=postgres://postgres:postgres@localhost:5432/qkeys_dev pnpm test   # + integration
```

Integration tests skip automatically when `DATABASE_URL` is unset. They cover
create/authenticate/revoke/rotate, expired rejection, scope checks, last-used +
usage recording, pagination, the expiry sweep, and assert the raw key never
appears in stored rows or errors.

## License

MIT © OBH Software
