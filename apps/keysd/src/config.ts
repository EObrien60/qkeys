import type { LogLevel } from "@obh/api-keys"

export type KeysdConfig = {
  databaseUrl: string
  pepper: string
  instanceId: string
  sweepIntervalMs: number
  batchSize: number
  logLevel: LogLevel
  healthPort?: number
  migrateOnBoot: boolean
}

const int = (value: string | undefined, fallback: number): number => {
  const n = value ? Number.parseInt(value, 10) : Number.NaN
  return Number.isFinite(n) ? n : fallback
}
const bool = (value: string | undefined, fallback: boolean): boolean => {
  if (value == null) return fallback
  return /^(1|true|yes|on)$/i.test(value)
}
const LOG_LEVELS: LogLevel[] = ["debug", "info", "warn", "error"]
const logLevel = (value: string | undefined): LogLevel =>
  LOG_LEVELS.includes(value as LogLevel) ? (value as LogLevel) : "info"

/**
 * Read worker configuration from the environment. Throws if DATABASE_URL or
 * API_KEYS_PEPPER is missing.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): KeysdConfig {
  const databaseUrl = env.DATABASE_URL
  if (!databaseUrl) throw new Error("DATABASE_URL is required")
  const pepper = env.API_KEYS_PEPPER
  if (!pepper) throw new Error("API_KEYS_PEPPER is required")

  return {
    databaseUrl,
    pepper,
    instanceId: env.KEYSD_INSTANCE_ID || `keysd-${process.pid}`,
    sweepIntervalMs: int(env.KEYSD_SWEEP_INTERVAL_MS, 60_000),
    batchSize: int(env.KEYSD_BATCH_SIZE, 500),
    logLevel: logLevel(env.KEYSD_LOG_LEVEL),
    healthPort: env.KEYSD_HEALTH_PORT ? int(env.KEYSD_HEALTH_PORT, 0) : undefined,
    migrateOnBoot: bool(env.KEYSD_MIGRATE_ON_BOOT, false),
  }
}
