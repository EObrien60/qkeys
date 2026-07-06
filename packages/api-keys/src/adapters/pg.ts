import type { ApiKeysDb, QueryResult, TransactionalApiKeysDb } from "../db"

/**
 * Structural types for the slice of node-postgres we use. Typed structurally so
 * the core never has to depend on `pg` at build time; pass a real pg.Pool.
 */
type PgQueryable = {
  query: (text: string, params?: unknown[]) => Promise<{ rows: unknown[] }>
}
type PgClient = PgQueryable & { release: () => void }
type PgPool = PgQueryable & { connect: () => Promise<PgClient> }

/**
 * Wrap a node-postgres Pool as a TransactionalApiKeysDb.
 *
 *   import { Pool } from "pg"
 *   const db = pgAdapter(new Pool({ connectionString: process.env.DATABASE_URL }))
 */
export function pgAdapter(pool: PgPool): TransactionalApiKeysDb {
  const query = async <T>(sql: string, params?: unknown[]): Promise<QueryResult<T>> => {
    const res = await pool.query(sql, params)
    return { rows: res.rows as T[] }
  }

  return {
    query,
    async transaction<T>(fn: (tx: ApiKeysDb) => Promise<T>): Promise<T> {
      const client = await pool.connect()
      const tx: ApiKeysDb = {
        async query<U>(sql: string, params?: unknown[]): Promise<QueryResult<U>> {
          const res = await client.query(sql, params)
          return { rows: res.rows as U[] }
        },
      }
      try {
        await client.query("begin")
        const result = await fn(tx)
        await client.query("commit")
        return result
      } catch (err) {
        try {
          await client.query("rollback")
        } catch {
          // ignore rollback failure; surface the original error
        }
        throw err
      } finally {
        client.release()
      }
    },
  }
}
