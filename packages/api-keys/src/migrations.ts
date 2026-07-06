import type { ApiKeysDb } from "./db"

/**
 * Schema for API keys. Idempotent (safe to run repeatedly). This string is the
 * source of truth; src/migrations/0001_init.sql is a verbatim copy kept for DBAs
 * who prefer to apply SQL by hand. All tables live in the `platform` schema.
 */
export const INIT_SQL = `
create schema if not exists platform;

create table if not exists platform.api_keys (
  id text primary key,

  workspace_id text not null,

  name text not null,
  description text null,

  key_prefix text not null,
  secret_hash text not null,

  environment text not null default 'live',

  scopes jsonb not null default '[]'::jsonb,

  status text not null default 'active',

  created_by text null,
  revoked_by text null,
  rotated_from text null references platform.api_keys(id),

  expires_at timestamptz null,
  revoked_at timestamptz null,

  last_used_at timestamptz null,
  last_used_ip text null,
  last_used_user_agent text null,

  metadata jsonb not null default '{}'::jsonb,

  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create unique index if not exists api_keys_prefix_idx
  on platform.api_keys (key_prefix);

create index if not exists api_keys_workspace_idx
  on platform.api_keys (workspace_id, created_at desc);

create index if not exists api_keys_status_idx
  on platform.api_keys (status);

create table if not exists platform.api_key_usage (
  id text primary key,

  api_key_id text not null references platform.api_keys(id),
  workspace_id text not null,

  route text null,
  method text null,

  ip text null,
  user_agent text null,

  status_code integer null,

  created_at timestamptz not null default now()
);

create index if not exists api_key_usage_key_time_idx
  on platform.api_key_usage (api_key_id, created_at desc);

create index if not exists api_key_usage_workspace_time_idx
  on platform.api_key_usage (workspace_id, created_at desc);
`

export type Migration = { id: string; sql: string }

export const migrations: Migration[] = [{ id: "0001_init", sql: INIT_SQL }]

/**
 * Apply all migrations. Each migration is idempotent DDL, so this is safe to run
 * on every boot if you like.
 */
export async function runMigrations(db: ApiKeysDb): Promise<void> {
  for (const migration of migrations) {
    await db.query(migration.sql)
  }
}
