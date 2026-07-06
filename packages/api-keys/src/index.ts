// Public surface of @obh/api-keys. Keep this small and boring.

export type {
  Environment,
  ApiKeyStatus,
  ApiKey,
  ApiKeyCreated,
  ApiKeyAuthContext,
  RequestMetadata,
  ApiKeyEvent,
  EventSink,
  CreateInput,
  RevokeInput,
  RotateInput,
  ListInput,
  ListResult,
  RecordUsageInput,
} from "./types"
export { API_KEY_EVENTS } from "./types"

export type { ApiKeysDb, TransactionalApiKeysDb, QueryResult } from "./db"

// Client
export { createApiKeysClient } from "./client"
export type { ApiKeysClient, ApiKeysClientOptions } from "./client"

// Middleware helpers (framework-agnostic)
export { authenticateRequest, requireScopeOrThrow } from "./middleware"

// Errors
export { ApiKeyAuthError, ApiKeyScopeError } from "./errors"
export type { ApiKeyAuthErrorCode } from "./errors"

// Scopes
export { scopeMatches, hasScope, hasAllScopes } from "./scopes"

// Key format + hashing (exported for advanced use and testing)
export { generateKey, parseKey, bearerFromAuthorization } from "./keyformat"
export type { GeneratedKey, ParsedKey } from "./keyformat"
export { hashSecret, verifySecret } from "./hash"

// Infrastructure
export { pgAdapter } from "./adapters/pg"
export { createLogger } from "./logger"
export type { Logger, LogLevel, LogFields } from "./logger"
export { newId } from "./ids"
export { runMigrations, migrations, INIT_SQL } from "./migrations"
export type { Migration } from "./migrations"
