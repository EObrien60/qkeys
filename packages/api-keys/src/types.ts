/** Which environment a key belongs to. Encoded in the key string. */
export type Environment = "live" | "test" | "dev"

/**
 * Key lifecycle.
 *   active  -> usable
 *   revoked -> permanently disabled (rotation revokes the old key)
 *   expired -> past expires_at; may be set lazily by a sweep, but authenticate
 *              treats any key past expiry as expired regardless of this column.
 */
export type ApiKeyStatus = "active" | "revoked" | "expired"

/** A stored API key, without any secret material. Safe to return/list/log. */
export type ApiKey = {
  id: string
  workspaceId: string
  name: string
  description: string | null
  keyPrefix: string
  environment: Environment
  scopes: string[]
  status: ApiKeyStatus
  createdBy: string | null
  revokedBy: string | null
  rotatedFrom: string | null
  expiresAt: string | null
  revokedAt: string | null
  lastUsedAt: string | null
  lastUsedIp: string | null
  lastUsedUserAgent: string | null
  metadata: Record<string, unknown>
  createdAt: string
  updatedAt: string
}

/** The result of creating or rotating a key. The plaintext `key` is returned ONCE. */
export type ApiKeyCreated = {
  id: string
  key: string
  name: string
  keyPrefix: string
  environment: Environment
  scopes: string[]
  expiresAt: string | null
}

/**
 * The trusted context produced by a successful authentication. App/API
 * permission middleware treats this much like a user auth context, but RBAC is
 * owned by Auth, not here — a key only carries scopes.
 */
export type ApiKeyAuthContext = {
  principalType: "api_key"
  principalId: string
  workspaceId: string
  scopes: string[]
  keyName: string
  environment: Environment
}

/** Request metadata captured on authenticate / usage, for last-used and the log. */
export type RequestMetadata = {
  ip?: string | null
  userAgent?: string | null
  route?: string | null
  method?: string | null
}

/**
 * An app-provided event sink. API Keys is a producer of control-plane events but
 * does not depend on @obh/events — wire this to events.emit() in the app. Never
 * pass plaintext key material through here; the client never does.
 */
export type ApiKeyEvent = {
  name: string
  workspaceId: string
  actorId?: string | null
  payload: Record<string, unknown>
}

export type EventSink = {
  emit(event: ApiKeyEvent): Promise<void> | void
}

/** Canonical event names emitted by the client. */
export const API_KEY_EVENTS = {
  created: "api_key.created",
  used: "api_key.used",
  revoked: "api_key.revoked",
  rotated: "api_key.rotated",
  expired: "api_key.expired",
} as const

export type CreateInput = {
  workspaceId: string
  name: string
  description?: string | null
  scopes: string[]
  environment?: Environment
  createdBy?: string | null
  expiresAt?: Date | string | null
  metadata?: Record<string, unknown>
}

export type RevokeInput = {
  id: string
  workspaceId: string
  revokedBy?: string | null
  reason?: string | null
}

export type RotateInput = {
  id: string
  workspaceId: string
  rotatedBy?: string | null
  /** Override the new key's expiry; defaults to the old key's expiry. */
  expiresAt?: Date | string | null
}

export type ListInput = {
  workspaceId: string
  status?: ApiKeyStatus
  limit?: number
  cursor?: string | null
}

export type ListResult = {
  keys: ApiKey[]
  nextCursor: string | null
}

export type RecordUsageInput = {
  apiKeyId: string
  workspaceId: string
  route?: string | null
  method?: string | null
  ip?: string | null
  userAgent?: string | null
  statusCode?: number | null
}
