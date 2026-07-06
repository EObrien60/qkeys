import { describe, expect, it } from "vitest"
import { hashSecret, verifySecret } from "../hash"

describe("hashSecret / verifySecret", () => {
  const pepper = "test-pepper-please-change"

  it("is deterministic for the same secret + pepper", () => {
    expect(hashSecret("s3cr3t", pepper)).toBe(hashSecret("s3cr3t", pepper))
  })

  it("changes with the pepper", () => {
    expect(hashSecret("s3cr3t", pepper)).not.toBe(hashSecret("s3cr3t", "other-pepper"))
  })

  it("does not contain the plaintext secret", () => {
    const secret = "super-secret-value"
    expect(hashSecret(secret, pepper)).not.toContain(secret)
  })

  it("verifies a correct secret and rejects a wrong one", () => {
    const stored = hashSecret("correct", pepper)
    expect(verifySecret("correct", stored, pepper)).toBe(true)
    expect(verifySecret("wrong", stored, pepper)).toBe(false)
  })

  it("rejects against a wrong pepper", () => {
    const stored = hashSecret("correct", pepper)
    expect(verifySecret("correct", stored, "wrong-pepper")).toBe(false)
  })

  it("returns false (never throws) on malformed stored hash", () => {
    expect(verifySecret("x", "not-hex-!!", pepper)).toBe(false)
    expect(verifySecret("x", "", pepper)).toBe(false)
  })
})
