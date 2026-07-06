#!/usr/bin/env node
import { createApiKeysClient, createLogger, pgAdapter, runMigrations } from "@obh/api-keys"
import { Pool } from "pg"
import { loadConfig } from "./config"
import { startHealthServer } from "./health"

/**
 * obh-keysd: an optional maintenance worker. Its only job is to periodically
 * mark active-but-past-expiry keys as `expired`. This is NOT required for
 * correctness — authenticate() already treats any past-expiry key as expired —
 * it just keeps the status column tidy and (when wired to an event sink) emits
 * api_key.expired. Runs safely as a single instance; sweeps are idempotent.
 */
async function main(): Promise<void> {
  const cfg = loadConfig()
  const log = createLogger(cfg.logLevel)
  const pool = new Pool({ connectionString: cfg.databaseUrl })
  const db = pgAdapter(pool)

  // No event sink here (standalone). An app that wants api_key.expired events
  // constructs the client with its own @obh/events-backed sink.
  const client = createApiKeysClient({ db, pepper: cfg.pepper, logger: log })

  log.info("keysd starting", {
    instance_id: cfg.instanceId,
    sweep_interval_ms: cfg.sweepIntervalMs,
    batch_size: cfg.batchSize,
    log_level: cfg.logLevel,
    health_port: cfg.healthPort,
  })

  if (cfg.migrateOnBoot) {
    log.info("running migrations")
    await runMigrations(db)
  }

  const health = cfg.healthPort ? startHealthServer(cfg.healthPort, db) : undefined

  let running = true
  let ticking = false

  const tick = async (): Promise<void> => {
    if (!running || ticking) return
    ticking = true
    try {
      let total = 0
      // Drain in batches so a large backlog doesn't wait a whole interval.
      for (;;) {
        const n = await client.sweepExpired({ batchSize: cfg.batchSize })
        total += n
        if (n < cfg.batchSize) break
      }
      if (total) log.info("expired keys swept", { count: total })
    } catch (err) {
      log.error("sweep failed", { error: err instanceof Error ? err.message : String(err) })
    } finally {
      ticking = false
    }
  }

  const timer = setInterval(() => void tick(), cfg.sweepIntervalMs)
  void tick() // run one sweep immediately on boot

  const shutdown = async (signal: string): Promise<void> => {
    if (!running) return
    running = false
    log.info("keysd stopping", { signal })
    clearInterval(timer)
    let waited = 0
    while (ticking && waited < 30_000) {
      await new Promise((r) => setTimeout(r, 100))
      waited += 100
    }
    health?.close()
    await pool.end()
    log.info("keysd stopped")
    process.exit(0)
  }

  process.on("SIGTERM", () => void shutdown("SIGTERM"))
  process.on("SIGINT", () => void shutdown("SIGINT"))
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
