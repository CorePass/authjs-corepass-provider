/**
 * Neon (serverless Postgres): re-exports the canonical authenticators table SQL from postgres migration.
 * Apply in your Neon database. Use the same schema as your CorePass tables if non-default.
 *
 * @see https://authjs.dev/getting-started/providers/passkey
 */

export { AUTHENTICATORS_TABLE_SQL_POSTGRES as AUTHENTICATORS_TABLE_SQL_NEON } from "./postgres.js"
