import { ApiKeyAuthError, type ApiKeyAuthContext, type ApiKeysClient } from "@obh/api-keys"
import { Hono } from "hono"
import { describe, expect, it, vi } from "vitest"
import { apiKeyAuth, requireApiScope } from "../index"

// A fake client: "good-key" authenticates with two scopes, anything else fails.
const makeClient = (over: Partial<ApiKeysClient> = {}): ApiKeysClient => {
  const ctx: ApiKeyAuthContext = {
    principalType: "api_key",
    principalId: "key_1",
    workspaceId: "ws_1",
    scopes: ["consignments.read", "vehicles.*"],
    keyName: "Test key",
    environment: "live",
  }
  return {
    async authenticate(raw: string) {
      if (raw === "good-key") return ctx
      throw new ApiKeyAuthError("invalid_key")
    },
    recordUsage: vi.fn(async () => {}),
    hasScope: (c, required) =>
      (Array.isArray(c) ? c : c.scopes).some(
        (g) => g === "*" || g === required || (g.endsWith(".*") && required.startsWith(g.slice(0, -1))),
      ),
    // Unused by these tests:
    create: vi.fn(),
    revoke: vi.fn(),
    rotate: vi.fn(),
    list: vi.fn(),
    get: vi.fn(),
    sweepExpired: vi.fn(),
    ...over,
  } as unknown as ApiKeysClient
}

const app = (client: ApiKeysClient) => {
  const a = new Hono()
  a.use("/api/*", apiKeyAuth({ client }))
  a.get("/api/whoami", (c) => c.json({ id: c.get("apiKey").principalId }))
  a.post("/api/consignments", requireApiScope("consignments.write"), (c) => c.json({ ok: true }))
  a.get("/api/consignments", requireApiScope("consignments.read"), (c) => c.json({ ok: true }))
  return a
}

describe("apiKeyAuth", () => {
  it("rejects a request with no Authorization header (401)", async () => {
    const res = await app(makeClient()).request("/api/whoami")
    expect(res.status).toBe(401)
  })

  it("rejects an invalid key (401)", async () => {
    const res = await app(makeClient()).request("/api/whoami", {
      headers: { Authorization: "Bearer bad-key" },
    })
    expect(res.status).toBe(401)
  })

  it("authenticates a valid key and exposes the context", async () => {
    const res = await app(makeClient()).request("/api/whoami", {
      headers: { Authorization: "Bearer good-key" },
    })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ id: "key_1" })
  })

  it("records usage after the handler runs", async () => {
    const client = makeClient()
    await app(client).request("/api/whoami", { headers: { Authorization: "Bearer good-key" } })
    expect(client.recordUsage).toHaveBeenCalledOnce()
  })
})

describe("requireApiScope", () => {
  it("allows a request that has the scope", async () => {
    const res = await app(makeClient()).request("/api/consignments", {
      headers: { Authorization: "Bearer good-key" },
    })
    expect(res.status).toBe(200)
  })

  it("forbids a request missing the scope (403)", async () => {
    const res = await app(makeClient()).request("/api/consignments", {
      method: "POST",
      headers: { Authorization: "Bearer good-key" },
    })
    expect(res.status).toBe(403)
  })
})
