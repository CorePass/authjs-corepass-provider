import type { CorePassStore, CorePassTx } from "../types.js"

/**
 * Minimal MikroORM EntityManager-like (raw execute). Use with em.getConnection().execute().
 * @see https://authjs.dev/getting-started/database — MikroORM
 */
export type MikroORMLike = {
	execute: (sql: string, params?: unknown[]) => Promise<unknown[] | number>
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

export type CorePassMikroORMAdapterOptions = {
	client: MikroORMLike
	schema?: string
}

/**
 * CorePass store + pending for MikroORM (Postgres). Use with EntityManager.getConnection().execute().
 * Merge with your Auth.js MikroORM adapter: adapter = { ...authAdapter, ...corepassMikroORMAdapter({ client: em.getConnection(), schema }) }
 */
export function corepassMikroORMAdapter(opts: CorePassMikroORMAdapterOptions): CorePassStore & CorePassTx {
	const { client, schema } = opts
	const pre = schema ? `"${schema}".` : ""

	async function query<T>(sql: string, params: unknown[] = []): Promise<T[]> {
		const result = await client.execute(sql, params)
		return (Array.isArray(result) ? result : []) as T[]
	}

	async function execute(sql: string, params: unknown[] = []): Promise<void> {
		await client.execute(sql, params)
	}

	return {
		async setPending(params, _ctx) {
			const expiresAtSec = Math.floor(params.expiresAt.getTime() / 1000)
			const payloadJson = JSON.stringify(params.payload)
			await execute(
				`INSERT INTO ${pre}corepass_pending (key, payload_json, expires_at, created_at)
				 VALUES ($1, $2, $3, $4)
				 ON CONFLICT (key) DO UPDATE SET payload_json = EXCLUDED.payload_json, expires_at = EXCLUDED.expires_at`,
				[params.key, payloadJson, expiresAtSec, nowSec()]
			)
		},

		async consumePending(params, _ctx) {
			const rows = await query<{ payload_json: string }>(
				`DELETE FROM ${pre}corepass_pending WHERE key = $1 RETURNING payload_json`,
				[params.key]
			)
			const row = rows[0]
			if (!row) return null
			try {
				return JSON.parse(row.payload_json) as unknown
			} catch {
				return null
			}
		},

		async getIdentityByCoreId(params, _ctx) {
			const rows = await query<{ core_id: string; user_id: string; ref_id: string | null }>(
				`SELECT core_id, user_id, ref_id FROM ${pre}corepass_identities WHERE core_id = $1`,
				[params.coreId]
			)
			const row = rows[0]
			if (!row) return null
			return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id ?? null }
		},

		async getIdentityByUserId(params, _ctx) {
			const rows = await query<{ core_id: string; user_id: string; ref_id: string | null }>(
				`SELECT core_id, user_id, ref_id FROM ${pre}corepass_identities WHERE user_id = $1`,
				[params.userId]
			)
			const row = rows[0]
			if (!row) return null
			return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id ?? null }
		},

		async upsertIdentity(identity, _ctx) {
			const now = nowSec()
			await execute(
				`INSERT INTO ${pre}corepass_identities (core_id, user_id, ref_id, created_at, updated_at)
				 VALUES ($1, $2, $3, $4, $4)
				 ON CONFLICT (core_id) DO UPDATE SET user_id = EXCLUDED.user_id,
				 ref_id = COALESCE(${pre}corepass_identities.ref_id, EXCLUDED.ref_id), updated_at = $4`,
				[identity.coreId, identity.userId, identity.refId ?? null, now]
			)
		},

		async upsertProfile(profile, _ctx) {
			const now = nowSec()
			await execute(
				`INSERT INTO ${pre}corepass_profiles (user_id, core_id, o18y, o21y, kyc, kyc_doc, provided_till, created_at, updated_at)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
				 ON CONFLICT (user_id) DO UPDATE SET core_id = EXCLUDED.core_id, o18y = EXCLUDED.o18y,
				 o21y = EXCLUDED.o21y, kyc = EXCLUDED.kyc, kyc_doc = EXCLUDED.kyc_doc,
				 provided_till = EXCLUDED.provided_till, updated_at = $8`,
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

		async getProfile(params, _ctx) {
			const rows = await query<{
				user_id: string
				core_id: string
				o18y: unknown
				o21y: unknown
				kyc: unknown
				kyc_doc: string | null
				provided_till: number | null
			}>(`SELECT user_id, core_id, o18y, o21y, kyc, kyc_doc, provided_till FROM ${pre}corepass_profiles WHERE user_id = $1`, [
				params.userId,
			])
			const row = rows[0]
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
	}
}
