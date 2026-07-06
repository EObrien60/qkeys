/**
 * Why an authentication attempt failed. `invalid_key` is deliberately generic
 * (bad format, unknown prefix, or wrong secret) so callers do not leak which
 * keys exist. `revoked` / `expired` are safe to distinguish for a known key.
 */
export type ApiKeyAuthErrorCode =
  | "missing" // no credential presented
  | "invalid_key" // malformed, unknown, or wrong secret
  | "revoked"
  | "expired"

const HTTP_STATUS: Record<ApiKeyAuthErrorCode, number> = {
  missing: 401,
  invalid_key: 401,
  revoked: 401,
  expired: 401,
}

/**
 * Thrown by authenticate() and the auth middleware. Never carries key material.
 */
export class ApiKeyAuthError extends Error {
  readonly code: ApiKeyAuthErrorCode
  readonly status: number
  constructor(code: ApiKeyAuthErrorCode, message?: string) {
    super(message ?? code)
    this.name = "ApiKeyAuthError"
    this.code = code
    this.status = HTTP_STATUS[code]
  }
}

/**
 * Thrown by requireScope helpers when an authenticated key lacks a scope.
 * Distinct from auth failure: the caller is known, just not permitted.
 */
export class ApiKeyScopeError extends Error {
  readonly status = 403
  readonly requiredScope: string
  constructor(requiredScope: string) {
    super(`missing required scope: ${requiredScope}`)
    this.name = "ApiKeyScopeError"
    this.requiredScope = requiredScope
  }
}
