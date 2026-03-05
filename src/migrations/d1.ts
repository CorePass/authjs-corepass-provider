/**
 * D1 full migration: Auth.js tables + CorePass tables + WebAuthn authenticators.
 * Run once per database (e.g. from a Cloudflare Worker or migrate script).
 * Requires @auth/d1-adapter to be installed for Auth.js tables; CorePass + authenticators are always applied.
 *
 * Pending tables:
 * - corepass_pending: generic key/payload store for pending.strategy "db" (setPending/consumePending). One row per key; payload_json + expires_at.
 * - corepass_pending_registrations: structured pending passkey registrations (credential_id, credential_public_key, etc.) until enrichment finalizes; used by legacy store implementations.
 */

type D1Run = { prepare: (sql: string) => { run: () => Promise<unknown> } }

const COREPASS_D1_SCHEMA = `
CREATE TABLE IF NOT EXISTS corepass_identities (
  core_id    TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL UNIQUE,
  ref_id     TEXT,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS corepass_profiles (
  user_id       TEXT PRIMARY KEY,
  core_id       TEXT NOT NULL UNIQUE,
  o18y          INTEGER,
  o21y          INTEGER,
  kyc           INTEGER,
  kyc_doc       TEXT,
  provided_till INTEGER,
  created_at    INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  updated_at    INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS corepass_pending_registrations (
  token                  TEXT PRIMARY KEY,
  credential_id          TEXT NOT NULL UNIQUE,
  credential_public_key  TEXT NOT NULL,
  counter                INTEGER NOT NULL DEFAULT 0,
  credential_device_type TEXT NOT NULL,
  credential_backed_up   INTEGER NOT NULL DEFAULT 0,
  transports             TEXT,
  email                  TEXT,
  ref_id                 TEXT,
  aaguid                 TEXT,
  created_at             INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  expires_at             INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_corepass_pending_expires_at ON corepass_pending_registrations(expires_at);
CREATE TABLE IF NOT EXISTS corepass_pending (
  key TEXT PRIMARY KEY,
  payload_json TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS idx_corepass_pending_expires ON corepass_pending(expires_at);
`

const AUTHENTICATORS_TABLE_SQL = `
CREATE TABLE IF NOT EXISTS authenticators (
  credential_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  provider_account_id TEXT NOT NULL,
  credential_public_key TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  credential_device_type TEXT NOT NULL,
  credential_backed_up INTEGER NOT NULL DEFAULT 0,
  transports TEXT
);
CREATE INDEX IF NOT EXISTS idx_authenticators_user_id ON authenticators(user_id);
`

async function runStatements(db: D1Run, sql: string): Promise<void> {
	const statements = sql.split(";").map((s) => s.trim()).filter(Boolean)
	for (const statement of statements) {
		try {
			await db.prepare(statement).run()
		} catch (e) {
			if (typeof console !== "undefined" && console.warn) {
				console.warn("[corepass] D1 migration statement failed:", (e as Error).message)
			}
		}
	}
}

/**
 * Creates the full D1 structure: (1) Auth.js tables (users, accounts, sessions, verification_tokens)
 * via @auth/d1-adapter if available, (2) CorePass tables, (3) WebAuthn authenticators table.
 * Call once per database; safe to run multiple times (IF NOT EXISTS).
 *
 * @param db - Cloudflare D1 database binding (e.g. env.DB)
 */
export async function migrateD1(db: D1Run): Promise<void> {
	try {
		const { up } = (await import("@auth/d1-adapter")) as { up: (db: D1Run) => Promise<void> }
		await up(db)
	} catch (e) {
		if (typeof console !== "undefined" && console.warn) {
			console.warn("[corepass] Auth.js D1 migration skipped (install @auth/d1-adapter for Auth.js tables):", (e as Error).message)
		}
	}
	await runStatements(db, COREPASS_D1_SCHEMA)
	await runStatements(db, AUTHENTICATORS_TABLE_SQL)
}
