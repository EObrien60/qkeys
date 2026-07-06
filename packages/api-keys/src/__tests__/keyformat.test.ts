import { describe, expect, it } from "vitest"
import { bearerFromAuthorization, generateKey, parseKey } from "../keyformat"

describe("generateKey", () => {
  it("produces obh_<env>_<keyId>_<secret>", () => {
    const g = generateKey("live")
    expect(g.key.startsWith("obh_live_k")).toBe(true)
    expect(g.keyPrefix).toBe(`obh_live_${g.keyId}`)
    expect(g.key).toBe(`${g.keyPrefix}_${g.secret}`)
    // keyId carries no underscore so parsing is unambiguous
    expect(g.keyId.includes("_")).toBe(false)
    expect(g.secret.length).toBeGreaterThan(20)
  })

  it("honours the environment", () => {
    expect(generateKey("test").key.startsWith("obh_test_")).toBe(true)
    expect(generateKey("dev").key.startsWith("obh_dev_")).toBe(true)
  })

  it("generates unique keys", () => {
    const a = generateKey()
    const b = generateKey()
    expect(a.key).not.toBe(b.key)
  })
})

describe("parseKey", () => {
  it("round-trips a generated key", () => {
    const g = generateKey("live")
    const p = parseKey(g.key)
    expect(p).not.toBeNull()
    expect(p!.environment).toBe("live")
    expect(p!.keyId).toBe(g.keyId)
    expect(p!.keyPrefix).toBe(g.keyPrefix)
    expect(p!.secret).toBe(g.secret)
  })

  it("preserves underscores inside a base64url secret", () => {
    const raw = "obh_live_kabc123_aa_bb__cc"
    const p = parseKey(raw)
    expect(p!.keyPrefix).toBe("obh_live_kabc123")
    expect(p!.secret).toBe("aa_bb__cc")
  })

  it("rejects malformed keys", () => {
    expect(parseKey("")).toBeNull()
    expect(parseKey("nope")).toBeNull()
    expect(parseKey("obh_live_kabc")).toBeNull() // no secret
    expect(parseKey("obh_prod_kabc_secret")).toBeNull() // bad env
    expect(parseKey("xxx_live_kabc_secret")).toBeNull() // bad namespace
    expect(parseKey("obh_live_abc_secret")).toBeNull() // keyId not starting with k
  })
})

describe("bearerFromAuthorization", () => {
  it("extracts the token from a Bearer header", () => {
    expect(bearerFromAuthorization("Bearer obh_live_k1_s")).toBe("obh_live_k1_s")
    expect(bearerFromAuthorization("bearer obh_live_k1_s")).toBe("obh_live_k1_s")
  })
  it("accepts a raw token", () => {
    expect(bearerFromAuthorization("obh_live_k1_s")).toBe("obh_live_k1_s")
  })
  it("returns null for empty input", () => {
    expect(bearerFromAuthorization(null)).toBeNull()
    expect(bearerFromAuthorization(undefined)).toBeNull()
  })
})
