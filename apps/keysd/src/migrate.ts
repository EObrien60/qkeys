#!/usr/bin/env node
import { createLogger, pgAdapter, runMigrations } from "@obh/api-keys"
import { Pool } from "pg"
import { loadConfig } from "./config"

/**
 * One-shot: apply the platform.api_keys / platform.api_key_usage schema.
 * Idempotent — safe to run repeatedly.
 *
 *   pnpm --filter @obh/keysd migrate
 */
async function main(): Promise<void> {
  const cfg = loadConfig()
  const log = createLogger(cfg.logLevel)
  const pool = new Pool({ connectionString: cfg.databaseUrl })
  const db = pgAdapter(pool)
  try {
    log.info("applying api keys migrations")
    await runMigrations(db)
    log.info("migrate complete")
  } finally {
    await pool.end()
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
