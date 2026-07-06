/**
 * The tiny database contract the engine depends on. Anything that can run a
 * parameterised SQL query satisfies ApiKeysDb; this keeps the core free of any
 * particular Postgres client or ORM. Support raw `pg` first (see adapters/pg.ts).
 *
 * Most methods only need ApiKeysDb. rotate() needs TransactionalApiKeysDb so the
 * new-key insert and old-key revoke commit atomically.
 */
export type QueryResult<T = unknown> = { rows: T[] }

export type ApiKeysDb = {
  query<T = unknown>(sql: string, params?: unknown[]): Promise<QueryResult<T>>
}

export type TransactionalApiKeysDb = ApiKeysDb & {
  transaction<T>(fn: (tx: ApiKeysDb) => Promise<T>): Promise<T>
}
