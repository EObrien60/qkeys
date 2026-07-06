import { describe, expect, it } from "vitest"
import { hasAllScopes, hasScope, scopeMatches } from "../scopes"

describe("scopeMatches", () => {
  it("exact match", () => {
    expect(scopeMatches("consignments.read", "consignments.read")).toBe(true)
    expect(scopeMatches("consignments.read", "consignments.write")).toBe(false)
  })
  it("global wildcard", () => {
    expect(scopeMatches("*", "anything.at.all")).toBe(true)
  })
  it("suffix wildcard", () => {
    expect(scopeMatches("consignments.*", "consignments.read")).toBe(true)
    expect(scopeMatches("consignments.*", "consignments.write")).toBe(true)
    expect(scopeMatches("consignments.*", "consignments")).toBe(true)
    expect(scopeMatches("consignments.*", "vehicles.read")).toBe(false)
    expect(scopeMatches("consignments.*", "consignmentsx.read")).toBe(false)
  })
})

describe("hasScope / hasAllScopes", () => {
  it("hasScope: any granted satisfies", () => {
    expect(hasScope(["consignments.*", "pods.read"], "consignments.write")).toBe(true)
    expect(hasScope(["pods.read"], "consignments.write")).toBe(false)
  })
  it("hasAllScopes: every required satisfied", () => {
    expect(hasAllScopes(["consignments.*"], ["consignments.read", "consignments.write"])).toBe(true)
    expect(hasAllScopes(["consignments.read"], ["consignments.read", "consignments.write"])).toBe(false)
    expect(hasAllScopes(["*"], ["a.b", "c.d"])).toBe(true)
  })
})
