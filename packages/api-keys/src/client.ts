import type { ApiKeysDb, TransactionalApiKeysDb } from "./db"
import { ApiKeyAuthError } from "./errors"
import { DUMMY_HASH, hashSecret, verifySecret } from "./hash"
import { generateKey, parseKey } from "./keyformat"
import { newId } from "./ids"
import { createLogger, type Logger } from "./logger"
import { hasScope } from "./scopes"
import {
  API_KEY_EVENTS,
  type ApiKey,
  type ApiKeyAuthContext,
  type ApiKeyCreated,
  type ApiKeyStatus,
  type CreateInput,
  type Environment,
  type EventSink,
  type ListInput,
  type ListResult,
  type RecordUsageInput,
  type RequestMetadata,
  type RevokeInput,
  type RotateInput,
} from "./types"

export type ApiKeysClientOptions = {
  db: TransactionalApiKeysDb
  /**
   * Server-side pepper for the keyed hash. REQUIRED — the client throws without
   * it. In production set API_KEYS_PEPPER to a long random secret and keep it out
   * of the database. Rotating the pepper invalidates all existing keys.
   */
  pepper: string
  /** Optional event sink (wire to @obh/events). create/revoke/rotate are emitted. */
  events?: EventSink
  /** Emit api_key.used on every successful authenticate (default false — noisy). */
  emitUsageEvents?: boolean
  logger?: Logger
  /** Injectable clock, mainly for tests. */
  now?: () => Date
}

export type ApiKeysClient = {
  create(input: CreateInput): Promise<ApiKeyCreated>
  authenticate(rawKey: string, meta?: RequestMetadata): Promise<ApiKeyAuthContext>
  revoke(input: RevokeInput): Promise<ApiKey>
  rotate(input: RotateInput): Promise<ApiKeyCreated>
  list(input: ListInput): Promise<ListResult>
  get(args: { workspaceId: string; id: string }): Promise<ApiKey | null>
  recordUsage(input: RecordUsageInput): Promise<void>
  hasScope(ctx: ApiKeyAuthContext | string[], required: string): boolean
  /** Mark active-but-past-expiry keys as expired. Returns how many were updated. */
  sweepExpired(args?: { workspaceId?: string; batchSize?: number }): Promise<number>
}

type KeyRow = {
  id: string
  workspace_id: string
  name: string
  description: string | null
  key_prefix: string
  secret_hash: string
  environment: string
  scopes: unknown
  status: string
  created_by: string | null
  revoked_by: string | null
  rotated_from: string | null
  expires_at: string | Date | null
  revoked_at: string | Date | null
  last_used_at: string | Date | null
  last_used_ip: string | null
  last_used_user_agent: string | null
  metadata: unknown
  created_at: string | Date
  updated_at: string | Date
}

const toIsoOrNull = (v: string | Date | null): string | null =>
  v == null ? null : v instanceof Date ? v.toISOString() : new Date(v).toISOString()
const toIso = (v: string | Date): string =>
  v instanceof Date ? v.toISOString() : new Date(v).toISOString()
const toDateOrNull = (v: Date | string | null | undefined): string | null =>
  v == null ? null : v instanceof Date ? v.toISOString() : new Date(v).toISOString()

const asScopes = (v: unknown): string[] => (Array.isArray(v) ? (v as string[]) : [])

// Column list excluding secret_hash — the public projection, safe to return.
const PUBLIC_COLS = `
  id, workspace_id, name, description, key_prefix, environment, scopes, status,
  created_by, revoked_by, rotated_from, expires_at, revoked_at,
  last_used_at, last_used_ip, last_used_user_agent, metadata, created_at, updated_at
`

const rowToApiKey = (row: Omit<KeyRow, "secret_hash">): ApiKey => ({
  id: row.id,
  workspaceId: row.workspace_id,
  name: row.name,
  description: row.description,
  keyPrefix: row.key_prefix,
  environment: row.environment as Environment,
  scopes: asScopes(row.scopes),
  status: row.status as ApiKeyStatus,
  createdBy: row.created_by,
  revokedBy: row.revoked_by,
  rotatedFrom: row.rotated_from,
  expiresAt: toIsoOrNull(row.expires_at),
  revokedAt: toIsoOrNull(row.revoked_at),
  lastUsedAt: toIsoOrNull(row.last_used_at),
  lastUsedIp: row.last_used_ip,
  lastUsedUserAgent: row.last_used_user_agent,
  metadata: (row.metadata as Record<string, unknown>) ?? {},
  createdAt: toIso(row.created_at),
  updatedAt: toIso(row.updated_at),
})

const encodeCursor = (c: { c: string; i: string }): string =>
  Buffer.from(JSON.stringify(c), "utf8").toString("base64url")
const decodeCursor = (raw: string): { c: string; i: string } | null => {
  try {
    const p = JSON.parse(Buffer.from(raw, "base64url").toString("utf8"))
    return p && typeof p.c === "string" && typeof p.i === "string" ? p : null
  } catch {
    return null
  }
}

export function createApiKeysClient(opts: ApiKeysClientOptions): ApiKeysClient {
  if (!opts.pepper) {
    throw new Error(
      "createApiKeysClient: a pepper is required (set API_KEYS_PEPPER). Refusing to run without it.",
    )
  }
  const db = opts.db
  const pepper = opts.pepper
  const log = opts.logger ?? createLogger("info")
  const now = opts.now ?? (() => new Date())

  const emit = async (
    name: string,
    key: Pick<ApiKey, "id" | "workspaceId" | "name" | "scopes" | "environment">,
    actorId?: string | null,
    extra?: Record<string, unknown>,
  ): Promise<void> => {
    if (!opts.events) return
    try {
      await opts.events.emit({
        name,
        workspaceId: key.workspaceId,
        actorId: actorId ?? null,
        // Never include plaintext key material.
        payload: {
          apiKeyId: key.id,
          name: key.name,
          scopes: key.scopes,
          environment: key.environment,
          ...(extra ?? {}),
        },
      })
    } catch (err) {
      // Events are best-effort control-plane signals; never fail the operation.
      log.warn("api key event emit failed", {
        event: name,
        api_key_id: key.id,
        error: err instanceof Error ? err.message : String(err),
      })
    }
  }

  const insertKey = async (
    tx: ApiKeysDb,
    args: {
      workspaceId: string
      name: string
      description: string | null
      environment: Environment
      scopes: string[]
      createdBy: string | null
      expiresAt: string | null
      metadata: Record<string, unknown>
      rotatedFrom?: string | null
    },
  ): Promise<{ id: string; created: ApiKeyCreated }> => {
    const gen = generateKey(args.environment)
    const id = newId("key")
    const secretHash = hashSecret(gen.secret, pepper)
    await tx.query(
      `insert into platform.api_keys
         (id, workspace_id, name, description, key_prefix, secret_hash, environment,
          scopes, status, created_by, rotated_from, expires_at, metadata)
       values ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,'active',$9,$10,$11,$12::jsonb)`,
      [
        id,
        args.workspaceId,
        args.name,
        args.description,
        gen.keyPrefix,
        secretHash,
        args.environment,
        JSON.stringify(args.scopes),
        args.createdBy,
        args.rotatedFrom ?? null,
        args.expiresAt,
        JSON.stringify(args.metadata),
      ],
    )
    return {
      id,
      created: {
        id,
        key: gen.key, // plaintext — returned once, never stored or logged
        name: args.name,
        keyPrefix: gen.keyPrefix,
        environment: args.environment,
        scopes: args.scopes,
        expiresAt: args.expiresAt,
      },
    }
  }

  const create = async (input: CreateInput): Promise<ApiKeyCreated> => {
    if (!input.workspaceId) throw new Error("apiKeys.create: workspaceId is required")
    if (!input.name) throw new Error("apiKeys.create: name is required")
    const environment = input.environment ?? "live"
    const scopes = input.scopes ?? []

    const { id, created } = await insertKey(db, {
      workspaceId: input.workspaceId,
      name: input.name,
      description: input.description ?? null,
      environment,
      scopes,
      createdBy: input.createdBy ?? null,
      expiresAt: toDateOrNull(input.expiresAt),
      metadata: input.metadata ?? {},
    })

    await emit(
      API_KEY_EVENTS.created,
      { id, workspaceId: input.workspaceId, name: input.name, scopes, environment },
      input.createdBy,
    )
    log.info("api key created", { api_key_id: id, workspace_id: input.workspaceId, name: input.name })
    return created
  }

  const authenticate = async (
    rawKey: string,
    meta: RequestMetadata = {},
  ): Promise<ApiKeyAuthContext> => {
    if (!rawKey) throw new ApiKeyAuthError("missing")
    const parsed = parseKey(rawKey)
    if (!parsed) throw new ApiKeyAuthError("invalid_key")

    const res = await db.query<KeyRow>(
      `select * from platform.api_keys where key_prefix = $1`,
      [parsed.keyPrefix],
    )
    const row = res.rows[0]

    // Always run a comparison to keep timing stable whether or not the key exists.
    const ok = verifySecret(parsed.secret, row?.secret_hash ?? DUMMY_HASH, pepper)
    if (!row || !ok) throw new ApiKeyAuthError("invalid_key")

    if (row.status === "revoked") throw new ApiKeyAuthError("revoked")
    const expiresAt = toIsoOrNull(row.expires_at)
    if (row.status === "expired") throw new ApiKeyAuthError("expired")
    if (expiresAt && new Date(expiresAt).getTime() <= now().getTime()) {
      throw new ApiKeyAuthError("expired")
    }

    // Record last-used metadata (best-effort; do not fail auth on write error).
    try {
      await db.query(
        `update platform.api_keys
         set last_used_at = now(), last_used_ip = $2, last_used_user_agent = $3, updated_at = now()
         where id = $1`,
        [row.id, meta.ip ?? null, meta.userAgent ?? null],
      )
    } catch (err) {
      log.warn("failed to update last_used", {
        api_key_id: row.id,
        error: err instanceof Error ? err.message : String(err),
      })
    }

    const scopes = asScopes(row.scopes)
    if (opts.emitUsageEvents) {
      await emit(
        API_KEY_EVENTS.used,
        {
          id: row.id,
          workspaceId: row.workspace_id,
          name: row.name,
          scopes,
          environment: row.environment as Environment,
        },
        null,
        { route: meta.route ?? null, method: meta.method ?? null },
      )
    }

    return {
      principalType: "api_key",
      principalId: row.id,
      workspaceId: row.workspace_id,
      scopes,
      keyName: row.name,
      environment: row.environment as Environment,
    }
  }

  const getRow = async (workspaceId: string, id: string): Promise<KeyRow | null> => {
    const res = await db.query<KeyRow>(
      `select * from platform.api_keys where id = $1 and workspace_id = $2`,
      [id, workspaceId],
    )
    return res.rows[0] ?? null
  }

  const revoke = async (input: RevokeInput): Promise<ApiKey> => {
    const res = await db.query<Omit<KeyRow, "secret_hash">>(
      `update platform.api_keys
       set status = 'revoked', revoked_at = now(), revoked_by = $3, updated_at = now()
       where id = $1 and workspace_id = $2 and status <> 'revoked'
       returning ${PUBLIC_COLS}`,
      [input.id, input.workspaceId, input.revokedBy ?? null],
    )
    let row = res.rows[0]
    if (!row) {
      // Either not found, or already revoked. Distinguish for a clean return/throw.
      const existing = await getRow(input.workspaceId, input.id)
      if (!existing) throw new Error(`apiKeys.revoke: key ${input.id} not found`)
      const { secret_hash: _omit, ...pub } = existing
      return rowToApiKey(pub)
    }
    const key = rowToApiKey(row)
    await emit(
      API_KEY_EVENTS.revoked,
      key,
      input.revokedBy,
      { reason: input.reason ?? null },
    )
    log.info("api key revoked", { api_key_id: key.id, workspace_id: key.workspaceId })
    return key
  }

  const rotate = async (input: RotateInput): Promise<ApiKeyCreated> => {
    const result = await db.transaction(async (tx) => {
      const res = await tx.query<KeyRow>(
        `select * from platform.api_keys where id = $1 and workspace_id = $2 for update`,
        [input.id, input.workspaceId],
      )
      const old = res.rows[0]
      if (!old) throw new Error(`apiKeys.rotate: key ${input.id} not found`)

      const expiresAt =
        input.expiresAt !== undefined ? toDateOrNull(input.expiresAt) : toIsoOrNull(old.expires_at)

      const { id: newKeyId, created } = await insertKey(tx, {
        workspaceId: old.workspace_id,
        name: old.name,
        description: old.description,
        environment: old.environment as Environment,
        scopes: asScopes(old.scopes),
        createdBy: input.rotatedBy ?? old.created_by,
        expiresAt,
        metadata: (old.metadata as Record<string, unknown>) ?? {},
        rotatedFrom: old.id,
      })

      await tx.query(
        `update platform.api_keys
         set status = 'revoked', revoked_at = now(), revoked_by = $2, updated_at = now()
         where id = $1`,
        [old.id, input.rotatedBy ?? null],
      )

      return { newKeyId, created, old }
    })

    await emit(
      API_KEY_EVENTS.rotated,
      {
        id: result.newKeyId,
        workspaceId: result.old.workspace_id,
        name: result.old.name,
        scopes: result.created.scopes,
        environment: result.created.environment,
      },
      input.rotatedBy,
      { rotatedFrom: input.id },
    )
    log.info("api key rotated", {
      api_key_id: result.newKeyId,
      rotated_from: input.id,
      workspace_id: result.old.workspace_id,
    })
    return result.created
  }

  const list = async (input: ListInput): Promise<ListResult> => {
    if (!input.workspaceId) throw new Error("apiKeys.list: workspaceId is required")
    const limit = Math.min(Math.max(1, input.limit ?? 50), 500)
    const params: unknown[] = [input.workspaceId]
    const where = ["workspace_id = $1"]
    if (input.status) {
      params.push(input.status)
      where.push(`status = $${params.length}`)
    }
    if (input.cursor) {
      const cursor = decodeCursor(input.cursor)
      if (cursor) {
        params.push(cursor.c, cursor.i)
        const cIdx = params.length - 1
        const iIdx = params.length
        where.push(`(created_at < $${cIdx} or (created_at = $${cIdx} and id < $${iIdx}))`)
      }
    }
    params.push(limit + 1)
    const res = await db.query<Omit<KeyRow, "secret_hash">>(
      `select ${PUBLIC_COLS} from platform.api_keys
       where ${where.join(" and ")}
       order by created_at desc, id desc
       limit $${params.length}`,
      params,
    )
    const rows = res.rows
    const hasMore = rows.length > limit
    const page = hasMore ? rows.slice(0, limit) : rows
    const keys = page.map(rowToApiKey)
    const last = page[page.length - 1]
    const nextCursor =
      hasMore && last ? encodeCursor({ c: toIso(last.created_at), i: last.id }) : null
    return { keys, nextCursor }
  }

  const get = async (args: { workspaceId: string; id: string }): Promise<ApiKey | null> => {
    const res = await db.query<Omit<KeyRow, "secret_hash">>(
      `select ${PUBLIC_COLS} from platform.api_keys where id = $1 and workspace_id = $2`,
      [args.id, args.workspaceId],
    )
    const row = res.rows[0]
    return row ? rowToApiKey(row) : null
  }

  const recordUsage = async (input: RecordUsageInput): Promise<void> => {
    await db.query(
      `insert into platform.api_key_usage
         (id, api_key_id, workspace_id, route, method, ip, user_agent, status_code)
       values ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        newId("aku"),
        input.apiKeyId,
        input.workspaceId,
        input.route ?? null,
        input.method ?? null,
        input.ip ?? null,
        input.userAgent ?? null,
        input.statusCode ?? null,
      ],
    )
  }

  const sweepExpired = async (
    args: { workspaceId?: string; batchSize?: number } = {},
  ): Promise<number> => {
    const batchSize = Math.min(Math.max(1, args.batchSize ?? 500), 5000)
    const params: unknown[] = [batchSize]
    let scope = ""
    if (args.workspaceId) {
      params.push(args.workspaceId)
      scope = ` and workspace_id = $${params.length}`
    }
    const res = await db.query<Omit<KeyRow, "secret_hash">>(
      `update platform.api_keys
       set status = 'expired', updated_at = now()
       where id in (
         select id from platform.api_keys
         where status = 'active' and expires_at is not null and expires_at <= now()${scope}
         limit $1
       )
       returning ${PUBLIC_COLS}`,
      params,
    )
    for (const row of res.rows) {
      const key = rowToApiKey(row)
      await emit(API_KEY_EVENTS.expired, key, null)
    }
    return res.rows.length
  }

  return {
    create,
    authenticate,
    revoke,
    rotate,
    list,
    get,
    recordUsage,
    sweepExpired,
    hasScope(ctx, required) {
      const scopes = Array.isArray(ctx) ? ctx : ctx.scopes
      return hasScope(scopes, required)
    },
  }
}
