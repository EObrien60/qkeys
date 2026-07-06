import { randomBytes } from "node:crypto"
import type { Environment } from "./types"

/**
 * Key string format:
 *
 *   obh_<env>_<keyId>_<secret>
 *   e.g. obh_live_k9f2c1a0b3d4e5f6a7_5bKx8...   (env: live | test | dev)
 *
 * - "obh"     fixed namespace, makes keys grep-able and identifiable if leaked
 * - env       live / test / dev
 * - keyId     public lookup id (contains NO underscore, so parsing is unambiguous)
 * - secret    high-entropy random; base64url may contain "_", so on parse the
 *             secret is everything after the third underscore, rejoined.
 *
 * The lookup prefix stored in the DB (and uniquely indexed) is everything except
 * the secret: `obh_<env>_<keyId>`. Only the hash of the secret is ever stored.
 */

const ENVIRONMENTS: Environment[] = ["live", "test", "dev"]

export type GeneratedKey = {
  keyId: string
  keyPrefix: string
  secret: string
  key: string
}

export type ParsedKey = {
  environment: Environment
  keyId: string
  keyPrefix: string
  secret: string
}

/** Generate a fresh key. `keyId` has no underscore; `secret` has ~192 bits. */
export function generateKey(environment: Environment = "live"): GeneratedKey {
  const keyId = `k${randomBytes(9).toString("hex")}` // 18 hex chars, no underscore
  const secret = randomBytes(24).toString("base64url")
  const keyPrefix = `obh_${environment}_${keyId}`
  return { keyId, keyPrefix, secret, key: `${keyPrefix}_${secret}` }
}

/**
 * Parse a raw key string. Returns null for anything malformed — callers should
 * treat null as an authentication failure without leaking why.
 */
export function parseKey(raw: string): ParsedKey | null {
  if (typeof raw !== "string") return null
  const parts = raw.split("_")
  // ["obh", env, keyId, ...secret]
  if (parts.length < 4) return null
  const [ns, env, keyId, ...secretParts] = parts
  if (ns !== "obh") return null
  if (!ENVIRONMENTS.includes(env as Environment)) return null
  if (!keyId || !keyId.startsWith("k") || keyId.length < 2) return null
  const secret = secretParts.join("_")
  if (!secret) return null
  return {
    environment: env as Environment,
    keyId,
    keyPrefix: `obh_${env}_${keyId}`,
    secret,
  }
}

/** Pull a raw key out of an Authorization header value ("Bearer <key>" or raw). */
export function bearerFromAuthorization(header: string | null | undefined): string | null {
  if (!header) return null
  const trimmed = header.trim()
  const m = /^Bearer\s+(.+)$/i.exec(trimmed)
  return m ? (m[1] as string).trim() : trimmed
}
