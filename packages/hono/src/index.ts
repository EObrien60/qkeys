import {
  ApiKeyAuthError,
  ApiKeyScopeError,
  authenticateRequest,
  requireScopeOrThrow,
  type ApiKeyAuthContext,
  type ApiKeysClient,
} from "@obh/api-keys"
import type { Context, MiddlewareHandler, Next } from "hono"

// Make c.get/c.set("apiKey") strongly typed for consumers of this package.
declare module "hono" {
  interface ContextVariableMap {
    apiKey: ApiKeyAuthContext
  }
}

/** Context variable key under which the auth context is stored. */
export const API_KEY_CONTEXT_KEY = "apiKey" as const

export type ApiKeyAuthOptions = {
  client: ApiKeysClient
  /**
   * Record a usage row after the handler runs (default true). The status code is
   * taken from the response, so this happens post-handler.
   */
  recordUsage?: boolean
}

const clientIp = (c: Context): string | null => {
  const xff = c.req.header("x-forwarded-for")
  if (xff) return xff.split(",")[0]?.trim() ?? null
  return c.req.header("x-real-ip") ?? null
}

const fail = (c: Context, status: number, code: string, message: string) =>
  c.json({ error: { code, message } }, status as 401 | 403)

/**
 * Hono middleware: authenticate an API key from the Authorization header and
 * stash the auth context on the request. Reject with 401 on failure.
 *
 *   app.use("/api/external/*", apiKeyAuth({ client }))
 *   app.post("/api/external/consignments", requireApiScope("consignments.write"), handler)
 *
 * Read the context in a handler with `c.get("apiKey")`.
 */
export function apiKeyAuth(options: ApiKeyAuthOptions): MiddlewareHandler {
  const recordUsage = options.recordUsage ?? true
  return async (c: Context, next: Next) => {
    let ctx: ApiKeyAuthContext
    try {
      ctx = await authenticateRequest(options.client, {
        authorization: c.req.header("Authorization"),
        meta: {
          ip: clientIp(c),
          userAgent: c.req.header("user-agent") ?? null,
          route: c.req.path,
          method: c.req.method,
        },
      })
    } catch (err) {
      if (err instanceof ApiKeyAuthError) {
        return fail(c, err.status, err.code, "API key authentication failed")
      }
      throw err
    }

    c.set(API_KEY_CONTEXT_KEY, ctx)
    await next()

    if (recordUsage) {
      // Best-effort; never turn a successful request into a failure.
      try {
        await options.client.recordUsage({
          apiKeyId: ctx.principalId,
          workspaceId: ctx.workspaceId,
          route: c.req.path,
          method: c.req.method,
          ip: clientIp(c),
          userAgent: c.req.header("user-agent") ?? null,
          statusCode: c.res.status,
        })
      } catch {
        // swallow — usage logging must not affect the response
      }
    }
  }
}

/**
 * Hono middleware: require a scope on the already-authenticated key. Use after
 * apiKeyAuth(). Rejects with 403 when the scope is missing.
 */
export function requireApiScope(scope: string): MiddlewareHandler {
  return async (c: Context, next: Next) => {
    const ctx = c.get(API_KEY_CONTEXT_KEY) as ApiKeyAuthContext | undefined
    if (!ctx) {
      return fail(c, 401, "missing", "API key authentication required before scope check")
    }
    try {
      requireScopeOrThrow(ctx, scope)
    } catch (err) {
      if (err instanceof ApiKeyScopeError) {
        return fail(c, err.status, "forbidden", err.message)
      }
      throw err
    }
    await next()
  }
}
