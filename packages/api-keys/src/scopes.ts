/**
 * Scope matching. Deliberately tiny — exact match plus an optional suffix
 * wildcard. No policy language.
 *
 *   granted "*"               matches any required scope
 *   granted "consignments.*"  matches "consignments.read", "consignments.write"
 *   granted "consignments.read" matches only "consignments.read"
 */
export function scopeMatches(granted: string, required: string): boolean {
  if (granted === "*") return true
  if (granted === required) return true
  if (granted.endsWith(".*")) {
    const prefix = granted.slice(0, -2)
    return required === prefix || required.startsWith(`${prefix}.`)
  }
  return false
}

/** True if any granted scope satisfies the required scope. */
export function hasScope(granted: string[], required: string): boolean {
  return granted.some((g) => scopeMatches(g, required))
}

/** True if every required scope is satisfied by the granted set. */
export function hasAllScopes(granted: string[], required: string[]): boolean {
  return required.every((r) => hasScope(granted, r))
}
