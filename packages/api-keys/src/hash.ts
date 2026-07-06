import { createHmac, timingSafeEqual } from "node:crypto"

/**
 * Keyed hash of a key secret. HMAC-SHA256 with a server-side pepper: fast (this
 * is on the hot auth path), and because the secret is high-entropy random (not a
 * human password) a keyed hash is appropriate — we do not need Argon2's slowness.
 * The pepper means a leaked database alone cannot be used to forge keys.
 *
 * Only the hex digest is ever stored; the plaintext secret is never persisted.
 */
export function hashSecret(secret: string, pepper: string): string {
  return createHmac("sha256", pepper).update(secret).digest("hex")
}

/**
 * Constant-time comparison of a presented secret against a stored hash. Returns
 * false (never throws) on any length/format mismatch.
 */
export function verifySecret(secret: string, storedHash: string, pepper: string): boolean {
  const computed = hashSecret(secret, pepper)
  let a: Buffer
  let b: Buffer
  try {
    a = Buffer.from(computed, "hex")
    b = Buffer.from(storedHash, "hex")
  } catch {
    return false
  }
  if (a.length === 0 || a.length !== b.length) return false
  return timingSafeEqual(a, b)
}

/**
 * A stable dummy hash used to keep authenticate() timing similar whether or not
 * a key row was found, reducing a key-existence timing oracle.
 */
export const DUMMY_HASH = "0".repeat(64)
