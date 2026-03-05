/**
 * Hasura (Postgres): re-exports the canonical authenticators table SQL from postgres migration.
 * Apply in your Postgres database and track the table in Hasura.
 *
 * @see https://authjs.dev/getting-started/providers/passkey
 */

export { AUTHENTICATORS_TABLE_SQL_POSTGRES as AUTHENTICATORS_TABLE_SQL_HASURA } from "./postgres.js"
