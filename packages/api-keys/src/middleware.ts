import type { ApiKeysClient } from "./client"
import { ApiKeyAuthError, ApiKeyScopeError } from "./errors"
import { bearerFromAuthorization } from "./keyformat"
import { hasScope } from "./scopes"
import type { ApiKeyAuthContext, RequestMetadata } from "./types"

/**
 * Framework-agnostic authentication: turn an Authorization header value into an
 * auth context, or throw ApiKeyAuthError. Web-framework adapters (see
 * @obh/api-keys-hono) are thin wrappers over this.
 */
export async function authenticateRequest(
  client: ApiKeysClient,
  args: { authorization?: string | null; meta?: RequestMetadata },
): Promise<ApiKeyAuthContext> {
  const raw = bearerFromAuthorization(args.authorization)
  if (!raw) throw new ApiKeyAuthError("missing")
  return client.authenticate(raw, args.meta)
}

/** Throw ApiKeyScopeError unless the context carries the required scope. */
export function requireScopeOrThrow(ctx: ApiKeyAuthContext, required: string): void {
  if (!hasScope(ctx.scopes, required)) throw new ApiKeyScopeError(required)
}
