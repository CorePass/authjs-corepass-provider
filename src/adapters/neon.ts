import type { PgLike } from "./postgres.js"
import { corepassPostgresAdapter } from "./postgres.js"

/**
 * Neon is serverless Postgres; use the same pool interface as Postgres. Includes WebAuthn (authenticators table; see migrations/neon).
 * Merge with your Auth.js Neon adapter: adapter = { ...authAdapter, ...corepassNeonAdapter({ pool, schema? }) }
 * @see https://authjs.dev/getting-started/database — Neon
 */
export function corepassNeonAdapter(opts: { pool: PgLike; schema?: string }) {
	return corepassPostgresAdapter(opts)
}
