import type { CorePassStore, CorePassTx } from "../types.js"

/**
 * Minimal SurrealDB-like client. Use with surrealdb.js: db.query() with SQL.
 * query() may return ResultSet[] where each has .result (array of rows), or a flat array of rows.
 * @see https://authjs.dev/getting-started/database — SurrealDB
 */
export type SurrealDBLike = {
	query: (sql: string, params?: Record<string, unknown>) => Promise<unknown>
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

export type CorePassSurrealDBAdapterOptions = {
	client: SurrealDBLike
	namespace?: string
	database?: string
}

/**
 * CorePass store + pending for SurrealDB. Use with surrealdb.js.
 * Merge with your Auth.js SurrealDB adapter: adapter = { ...authAdapter, ...corepassSurrealDBAdapter({ client }) }
 * Tables: corepass_pending, corepass_identities, corepass_profiles (create with appropriate schema).
 */
export function corepassSurrealDBAdapter(opts: CorePassSurrealDBAdapterOptions): CorePassStore & CorePassTx {
	const { client } = opts

	async function getRows<T>(sql: string, params: Record<string, unknown> = {}): Promise<T[]> {
		const raw = await client.query(sql, params)
		const arr = Array.isArray(raw) ? raw : []
		const first = arr[0]
		const rows = first != null && typeof first === "object" && "result" in first ? (first as { result: unknown[] }).result : arr
		return (Array.isArray(rows) ? rows : []) as T[]
	}

	return {
		async setPending(params, _ctx) {
			const expiresAtSec = Math.floor(params.expiresAt.getTime() / 1000)
			await client.query(`DELETE FROM corepass_pending WHERE key = $key`, { key: params.key })
			await client.query(
				`INSERT INTO corepass_pending (key, payload_json, expires_at, created_at) VALUES ($key, $payload, $exp, $now)`,
				{
					key: params.key,
					payload: JSON.stringify(params.payload),
					exp: expiresAtSec,
					now: nowSec(),
				}
			)
		},

		async consumePending(params, _ctx) {
			const rows = await getRows<{ payload_json: string }>(
				`DELETE FROM corepass_pending WHERE key = $key RETURN payload_json`,
				{ key: params.key }
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
			const rows = await getRows<{ core_id: string; user_id: string; ref_id: string | null }>(
				`SELECT core_id, user_id, ref_id FROM corepass_identities WHERE core_id = $coreId`,
				{ coreId: params.coreId }
			)
			const row = rows[0]
			if (!row) return null
			return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id ?? null }
		},

		async getIdentityByUserId(params, _ctx) {
			const rows = await getRows<{ core_id: string; user_id: string; ref_id: string | null }>(
				`SELECT core_id, user_id, ref_id FROM corepass_identities WHERE user_id = $userId`,
				{ userId: params.userId }
			)
			const row = rows[0]
			if (!row) return null
			return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id ?? null }
		},

		async upsertIdentity(identity, _ctx) {
			await client.query(
				`INSERT INTO corepass_identities (core_id, user_id, ref_id, created_at, updated_at) VALUES ($coreId, $userId, $refId, $now, $now)
				 ON DUPLICATE KEY UPDATE user_id = $userId, ref_id = $refId, updated_at = $now`,
				{
					coreId: identity.coreId,
					userId: identity.userId,
					refId: identity.refId ?? null,
					now: nowSec(),
				}
			)
		},

		async upsertProfile(profile, _ctx) {
			await client.query(
				`INSERT INTO corepass_profiles (user_id, core_id, o18y, o21y, kyc, kyc_doc, provided_till, created_at, updated_at) VALUES ($userId, $coreId, $o18y, $o21y, $kyc, $kycDoc, $pt, $now, $now)
				 ON DUPLICATE KEY UPDATE core_id = $coreId, o18y = $o18y, o21y = $o21y, kyc = $kyc, kyc_doc = $kycDoc, provided_till = $pt, updated_at = $now`,
				{
					userId: profile.userId,
					coreId: profile.coreId,
					o18y: boolToDb(profile.o18y),
					o21y: boolToDb(profile.o21y),
					kyc: boolToDb(profile.kyc),
					kycDoc: profile.kycDoc ?? null,
					pt: profile.providedTill ?? null,
					now: nowSec(),
				}
			)
		},

		async getProfile(params, _ctx) {
			const rows = await getRows<{
				user_id: string
				core_id: string
				o18y: unknown
				o21y: unknown
				kyc: unknown
				kyc_doc: string | null
				provided_till: number | null
			}>(`SELECT user_id, core_id, o18y, o21y, kyc, kyc_doc, provided_till FROM corepass_profiles WHERE user_id = $userId`, {
				userId: params.userId,
			})
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
