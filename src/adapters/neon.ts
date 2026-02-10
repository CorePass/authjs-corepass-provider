import type { CorePassStore, CorePassTx } from "../types.js"
import type { PgLike } from "./postgres.js"
import { corepassPostgresAdapter } from "./postgres.js"

/**
 * Neon is serverless Postgres; use the same pool interface as Postgres.
 * Merge with your Auth.js Neon adapter: adapter = { ...authAdapter, ...corepassNeonAdapter(pool) }
 * @see https://authjs.dev/getting-started/database — Neon
 */
export function corepassNeonAdapter(opts: { pool: PgLike; schema?: string }): CorePassStore & CorePassTx {
	return corepassPostgresAdapter(opts)
}
