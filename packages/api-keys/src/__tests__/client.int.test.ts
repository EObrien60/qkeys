import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest"
import { pgAdapter } from "../adapters/pg"
import { createApiKeysClient } from "../client"
import { ApiKeyAuthError } from "../errors"
import { parseKey } from "../keyformat"
import { runMigrations } from "../migrations"
import type { ApiKeyEvent, EventSink } from "../types"

// Integration tests: require a real Postgres. Skipped automatically when
// DATABASE_URL is not set, so `pnpm test` stays green on a laptop with no DB.
//
//   docker compose up -d
//   DATABASE_URL=postgres://postgres:postgres@localhost:5432/qkeys_dev pnpm test
const url = process.env.DATABASE_URL
const suite = url ? describe : describe.skip

const PEPPER = "integration-test-pepper-change-me"

suite("integration: api keys client", () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { Pool } = require("pg") as typeof import("pg")
  const pool = new Pool({ connectionString: url })
  const db = pgAdapter(pool as never)

  const events: ApiKeyEvent[] = []
  const sink: EventSink = { emit: (e) => void events.push(e) }
  const client = createApiKeysClient({ db, pepper: PEPPER, events: sink })

  beforeAll(async () => {
    await runMigrations(db)
  })

  beforeEach(async () => {
    events.length = 0
    await db.query("truncate platform.api_key_usage, platform.api_keys restart identity cascade")
  })

  afterAll(async () => {
    await pool.end()
  })

  const createKey = (over: Partial<Parameters<typeof client.create>[0]> = {}) =>
    client.create({
      workspaceId: "ws_1",
      name: "Customer ERP integration",
      scopes: ["consignments.read", "consignments.write"],
      createdBy: "usr_admin",
      ...over,
    })

  it("requires a pepper", () => {
    expect(() => createApiKeysClient({ db, pepper: "" })).toThrow(/pepper/)
  })

  it("creates a key, returns plaintext once, stores only the hash", async () => {
    const created = await createKey()
    expect(created.key).toMatch(/^obh_live_k[0-9a-f]+_/)
    expect(created.id).toMatch(/^key_/)

    const secret = parseKey(created.key)!.secret
    const row = await db.query<{ secret_hash: string; key_prefix: string }>(
      "select secret_hash, key_prefix from platform.api_keys where id=$1",
      [created.id],
    )
    // Only a 64-char hex hash is stored; never the plaintext key or secret.
    expect(row.rows[0]!.secret_hash).toMatch(/^[0-9a-f]{64}$/)
    expect(row.rows[0]!.secret_hash).not.toBe(secret)
    expect(row.rows[0]!.secret_hash).not.toContain(secret)
    expect(created.key).not.toContain(row.rows[0]!.secret_hash)
    expect(row.rows[0]!.key_prefix).toBe(created.keyPrefix)

    // create emits api_key.created with no plaintext in the payload
    expect(events.map((e) => e.name)).toContain("api_key.created")
    const ev = events.find((e) => e.name === "api_key.created")!
    expect(JSON.stringify(ev)).not.toContain(secret)
  })

  it("authenticates a valid key and records last-used metadata", async () => {
    const created = await createKey()
    const ctx = await client.authenticate(created.key, {
      ip: "203.0.113.7",
      userAgent: "erp/1.0",
      route: "/api/external/consignments",
      method: "POST",
    })
    expect(ctx).toMatchObject({
      principalType: "api_key",
      principalId: created.id,
      workspaceId: "ws_1",
      keyName: "Customer ERP integration",
      environment: "live",
    })
    expect(ctx.scopes).toEqual(["consignments.read", "consignments.write"])
    expect(client.hasScope(ctx, "consignments.write")).toBe(true)
    expect(client.hasScope(ctx, "vehicles.read")).toBe(false)

    const row = await db.query<{ last_used_at: string; last_used_ip: string; last_used_user_agent: string }>(
      "select last_used_at, last_used_ip, last_used_user_agent from platform.api_keys where id=$1",
      [created.id],
    )
    expect(row.rows[0]!.last_used_at).not.toBeNull()
    expect(row.rows[0]!.last_used_ip).toBe("203.0.113.7")
    expect(row.rows[0]!.last_used_user_agent).toBe("erp/1.0")
  })

  it("rejects invalid, malformed and unknown keys without leaking the secret", async () => {
    const created = await createKey()
    const tampered = `${created.key}TAMPER`

    await expect(client.authenticate(tampered)).rejects.toMatchObject({ code: "invalid_key" })
    await expect(client.authenticate("garbage")).rejects.toBeInstanceOf(ApiKeyAuthError)
    await expect(client.authenticate("obh_live_kdeadbeef_nope")).rejects.toMatchObject({
      code: "invalid_key",
    })

    // The error must not contain any key material.
    const secret = parseKey(created.key)!.secret
    try {
      await client.authenticate(tampered)
    } catch (err) {
      expect(String((err as Error).message)).not.toContain(secret)
    }
  })

  it("rejects revoked keys and emits api_key.revoked", async () => {
    const created = await createKey()
    const key = await client.revoke({ id: created.id, workspaceId: "ws_1", revokedBy: "usr_admin" })
    expect(key.status).toBe("revoked")
    await expect(client.authenticate(created.key)).rejects.toMatchObject({ code: "revoked" })
    expect(events.map((e) => e.name)).toContain("api_key.revoked")
  })

  it("rejects expired keys", async () => {
    const created = await createKey({ expiresAt: new Date(Date.now() - 60_000) })
    await expect(client.authenticate(created.key)).rejects.toMatchObject({ code: "expired" })
  })

  it("records and queries usage", async () => {
    const created = await createKey()
    await client.recordUsage({
      apiKeyId: created.id,
      workspaceId: "ws_1",
      route: "/api/external/consignments",
      method: "POST",
      statusCode: 201,
    })
    const usage = await db.query<{ n: string }>(
      "select count(*)::text as n from platform.api_key_usage where api_key_id=$1",
      [created.id],
    )
    expect(usage.rows[0]!.n).toBe("1")
  })

  it("rotates: new key works, old key is revoked, scopes preserved", async () => {
    const original = await createKey()
    const rotated = await client.rotate({ id: original.id, workspaceId: "ws_1", rotatedBy: "usr_admin" })

    expect(rotated.id).not.toBe(original.id)
    expect(rotated.scopes).toEqual(original.scopes)

    // New key authenticates, old key rejected as revoked.
    await expect(client.authenticate(rotated.key)).resolves.toMatchObject({ principalId: rotated.id })
    await expect(client.authenticate(original.key)).rejects.toMatchObject({ code: "revoked" })

    const row = await db.query<{ rotated_from: string; status: string }>(
      "select rotated_from, status from platform.api_keys where id=$1",
      [rotated.id],
    )
    expect(row.rows[0]!.rotated_from).toBe(original.id)
    expect(row.rows[0]!.status).toBe("active")

    expect(events.map((e) => e.name)).toContain("api_key.rotated")
  })

  it("lists workspace keys newest-first with a cursor, and gets one by id", async () => {
    const ids: string[] = []
    for (let i = 0; i < 5; i++) {
      ids.push((await createKey({ name: `key ${i}` })).id)
    }
    const first = await client.list({ workspaceId: "ws_1", limit: 2 })
    expect(first.keys).toHaveLength(2)
    expect(first.nextCursor).toBeTruthy()
    // no secret material on listed keys
    expect(JSON.stringify(first.keys)).not.toMatch(/secret/i)

    const second = await client.list({ workspaceId: "ws_1", limit: 2, cursor: first.nextCursor })
    const firstIds = new Set(first.keys.map((k) => k.id))
    expect(second.keys.some((k) => firstIds.has(k.id))).toBe(false)

    const one = await client.get({ workspaceId: "ws_1", id: ids[0]! })
    expect(one?.id).toBe(ids[0])
    expect(await client.get({ workspaceId: "ws_other", id: ids[0]! })).toBeNull()
  })

  it("sweepExpired marks past-expiry keys expired and emits api_key.expired", async () => {
    const created = await createKey({ expiresAt: new Date(Date.now() - 60_000) })
    const n = await client.sweepExpired()
    expect(n).toBe(1)
    const row = await db.query<{ status: string }>(
      "select status from platform.api_keys where id=$1",
      [created.id],
    )
    expect(row.rows[0]!.status).toBe("expired")
    expect(events.map((e) => e.name)).toContain("api_key.expired")
  })

  it("isolates workspaces on authenticate context", async () => {
    const a = await client.create({ workspaceId: "ws_a", name: "A", scopes: ["x.read"] })
    const ctx = await client.authenticate(a.key)
    expect(ctx.workspaceId).toBe("ws_a")
  })
})
