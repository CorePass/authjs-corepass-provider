/**
 * Kysely (Postgres): re-exports the canonical authenticators table SQL from postgres migration.
 * Apply in addition to your Auth.js and CorePass schema (e.g. in a Kysely migration or run manually).
 * Use the same schema prefix as your CorePass tables if you use a non-default schema.
 *
 * @see https://authjs.dev/getting-started/providers/passkey
 */

export { AUTHENTICATORS_TABLE_SQL_POSTGRES as AUTHENTICATORS_TABLE_SQL_KYSELY } from "./postgres.js"
