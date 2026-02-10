import type { CorePassStore, CorePassTx, CorePassTxContext } from "../types.js"

export type PgLike = {
	query: (text: string, params?: unknown[]) => Promise<{ rows: unknown[] }>
	connect?: () => Promise<{
		query: (text: string, params?: unknown[]) => Promise<{ rows: unknown[] }>
		release: () => void
	}>
}

function nowSec(): number {
	return Math.floor(Date.now() / 1000)
}

function boolToDb(v: boolean | null | undefined): number | null {
	if (v === null || v === undefined) return null
	return v ? 1 : 0
}

function boolFromDb(v: unknown): boolean | null {
	if (v === null || v === undefined) return null
	if (typeof v === "boolean") return v
	return (v as number) === 1
}

/**
 * CorePass store + pending (key/payload) + optional transaction support for PostgreSQL.
 * Merge with your Auth.js Postgres adapter: adapter = { ...authAdapter, ...corepassPostgresAdapter({ pool, schema }) }
 */
export function corepassPostgresAdapter(opts: {
	pool: PgLike
	schema?: string
}): CorePassStore & CorePassTx {
	const { pool, schema } = opts
	const pre = schema ? `${schema}.` : ""

	return {
		async setPending(params, ctx) {
			const client = (ctx as { tx?: PgLike })?.tx ?? pool
			const expiresAtSec = Math.floor(params.expiresAt.getTime() / 1000)
			const payloadJson = JSON.stringify(params.payload)
			await (client as PgLike).query(
				`INSERT INTO ${pre}corepass_pending (key, payload_json, expires_at, created_at)
				 VALUES ($1, $2::jsonb, $3, $4)
				 ON CONFLICT (key) DO UPDATE SET payload_json = EXCLUDED.payload_json, expires_at = EXCLUDED.expires_at`,
				[params.key, payloadJson, expiresAtSec, nowSec()]
			)
		},

		async consumePending(params, ctx) {
			const client = (ctx as { tx?: PgLike })?.tx ?? pool
			const res = await (client as PgLike).query(
				`DELETE FROM ${pre}corepass_pending WHERE key = $1 RETURNING payload_json`,
				[params.key]
			)
			const row = res.rows[0] as { payload_json: string } | undefined
			if (!row) return null
			try {
				return JSON.parse(row.payload_json) as unknown
			} catch {
				return null
			}
		},

		async getIdentityByCoreId(params, ctx) {
			const client = (ctx as { tx?: PgLike })?.tx ?? pool
			const res = await (client as PgLike).query(
				`SELECT core_id, user_id, ref_id FROM ${pre}corepass_identities WHERE core_id = $1`,
				[params.coreId]
			)
			const row = res.rows[0] as { core_id: string; user_id: string; ref_id: string | null } | undefined
			if (!row) return null
			return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id ?? null }
		},

		async getIdentityByUserId(params, ctx) {
			const client = (ctx as { tx?: PgLike })?.tx ?? pool
			const res = await (client as PgLike).query(
				`SELECT core_id, user_id, ref_id FROM ${pre}corepass_identities WHERE user_id = $1`,
				[params.userId]
			)
			const row = res.rows[0] as { core_id: string; user_id: string; ref_id: string | null } | undefined
			if (!row) return null
			return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id ?? null }
		},

		async upsertIdentity(identity, ctx) {
			const client = (ctx as { tx?: PgLike })?.tx ?? pool
			const now = nowSec()
			await (client as PgLike).query(
				`INSERT INTO ${pre}corepass_identities (core_id, user_id, ref_id, created_at, updated_at)
				 VALUES ($1, $2, $3, $4, $4)
				 ON CONFLICT (core_id) DO UPDATE SET
				   user_id = EXCLUDED.user_id,
				   ref_id = COALESCE(${pre}corepass_identities.ref_id, EXCLUDED.ref_id),
				   updated_at = $4`,
				[identity.coreId, identity.userId, identity.refId ?? null, now]
			)
		},

		async upsertProfile(profile, ctx) {
			const client = (ctx as { tx?: PgLike })?.tx ?? pool
			const now = nowSec()
			await (client as PgLike).query(
				`INSERT INTO ${pre}corepass_profiles (user_id, core_id, o18y, o21y, kyc, kyc_doc, provided_till, created_at, updated_at)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
				 ON CONFLICT (user_id) DO UPDATE SET
				   core_id = EXCLUDED.core_id,
				   o18y = EXCLUDED.o18y,
				   o21y = EXCLUDED.o21y,
				   kyc = EXCLUDED.kyc,
				   kyc_doc = EXCLUDED.kyc_doc,
				   provided_till = EXCLUDED.provided_till,
				   updated_at = $8`,
				[
					profile.userId,
					profile.coreId,
					boolToDb(profile.o18y),
					boolToDb(profile.o21y),
					boolToDb(profile.kyc),
					profile.kycDoc ?? null,
					profile.providedTill ?? null,
					now,
				]
			)
		},

		async getProfile(params, ctx) {
			const client = (ctx as { tx?: PgLike })?.tx ?? pool
			const res = await (client as PgLike).query(
				`SELECT user_id, core_id, o18y, o21y, kyc, kyc_doc, provided_till FROM ${pre}corepass_profiles WHERE user_id = $1`,
				[params.userId]
			)
			const row = res.rows[0] as {
				user_id: string
				core_id: string
				o18y: unknown
				o21y: unknown
				kyc: unknown
				kyc_doc: string | null
				provided_till: number | null
			} | undefined
			if (!row) return null
			return {
				userId: row.user_id,
				coreId: row.core_id,
				o18y: boolFromDb(row.o18y),
				o21y: boolFromDb(row.o21y),
				kyc: boolFromDb(row.kyc),
				kycDoc: row.kyc_doc ?? null,
				providedTill: row.provided_till ?? null,
			}
		},

		async withTransaction<T>(fn: (ctx: CorePassTxContext) => Promise<T>): Promise<T> {
			const connect = pool.connect
			if (!connect) {
				return fn({}) as Promise<T>
			}
			const client = await connect()
			try {
				await (client as { query: (s: string) => Promise<unknown> }).query("BEGIN")
				const result = await fn({ tx: client })
				await (client as { query: (s: string) => Promise<unknown> }).query("COMMIT")
				return result
			} catch (e) {
				await (client as { query: (s: string) => Promise<unknown> }).query("ROLLBACK").catch(() => {})
				throw e
			} finally {
				client.release()
			}
		},
	}
}
