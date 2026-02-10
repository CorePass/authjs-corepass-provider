import type { CorePassStore, CorePassTx } from "../types.js"

/**
 * Minimal EdgeDB-like client (execute query with params). Use with edgedb client.
 * @see https://authjs.dev/getting-started/database — EdgeDB
 */
export type EdgeDBLike = {
	query: (query: string, args?: Record<string, unknown>) => Promise<unknown[]>
	querySingle: (query: string, args?: Record<string, unknown>) => Promise<unknown>
	execute: (query: string, args?: Record<string, unknown>) => Promise<void>
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
 * CorePass store + pending for EdgeDB. Use with edgedb client (run raw SQL or EdgeQL).
 * This adapter expects a minimal client that can run parameterized queries and return rows.
 * Merge with your Auth.js EdgeDB adapter: adapter = { ...authAdapter, ...corepassEdgeDBAdapter(client) }
 */
export function corepassEdgeDBAdapter(client: EdgeDBLike): CorePassStore & CorePassTx {
	async function query<T>(q: string, args: Record<string, unknown>): Promise<T[]> {
		const result = await client.query(q, args)
		return (Array.isArray(result) ? result : []) as T[]
	}

	return {
		async setPending(params, _ctx) {
			const expiresAtSec = Math.floor(params.expiresAt.getTime() / 1000)
			await client.execute(
				`INSERT corepass::Pending { key := <str>$key, payload_json := <str>$payload, expires_at := <int64>$exp, created_at := <int64>$now }
				 UNLESS CONFLICT ON .key ELSE (UPDATE corepass::Pending SET { payload_json := <str>$payload, expires_at := <int64>$exp })`,
				{
					key: params.key,
					payload: JSON.stringify(params.payload),
					exp: expiresAtSec,
					now: nowSec(),
				}
			)
		},

		async consumePending(params, _ctx) {
			const rows = await query<{ payload_json: string }>(
				`SELECT corepass::Pending { payload_json } FILTER .key = <str>$key`,
				{ key: params.key }
			)
			const row = rows[0]
			if (!row) return null
			await client.execute(`DELETE corepass::Pending FILTER .key = <str>$key`, { key: params.key })
			try {
				return JSON.parse(row.payload_json) as unknown
			} catch {
				return null
			}
		},

		async getIdentityByCoreId(params, _ctx) {
			const rows = await query<{ core_id: string; user_id: string; ref_id: string | null }>(
				`SELECT corepass::Identity { core_id, user_id, ref_id } FILTER .core_id = <str>$coreId`,
				{ coreId: params.coreId }
			)
			const row = rows[0]
			if (!row) return null
			return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id ?? null }
		},

		async getIdentityByUserId(params, _ctx) {
			const rows = await query<{ core_id: string; user_id: string; ref_id: string | null }>(
				`SELECT corepass::Identity { core_id, user_id, ref_id } FILTER .user_id = <str>$userId`,
				{ userId: params.userId }
			)
			const row = rows[0]
			if (!row) return null
			return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id ?? null }
		},

		async upsertIdentity(identity, _ctx) {
			await client.execute(
				`INSERT corepass::Identity { core_id := <str>$coreId, user_id := <str>$userId, ref_id := <str>$refId, updated_at := <int64>$now }
				 UNLESS CONFLICT ON .core_id ELSE (UPDATE corepass::Identity SET { user_id := <str>$userId, ref_id := <str>$refId, updated_at := <int64>$now })`,
				{
					coreId: identity.coreId,
					userId: identity.userId,
					refId: identity.refId ?? null,
					now: nowSec(),
				}
			)
		},

		async upsertProfile(profile, _ctx) {
			await client.execute(
				`INSERT corepass::Profile { user_id := <str>$userId, core_id := <str>$coreId, o18y := <int64>$o18y, o21y := <int64>$o21y, kyc := <int64>$kyc, kyc_doc := <str>$kycDoc, provided_till := <int64>$pt, updated_at := <int64>$now }
				 UNLESS CONFLICT ON .user_id ELSE (UPDATE corepass::Profile SET { core_id := <str>$coreId, o18y := <int64>$o18y, o21y := <int64>$o21y, kyc := <int64>$kyc, kyc_doc := <str>$kycDoc, provided_till := <int64>$pt, updated_at := <int64>$now })`,
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
			const rows = await query<{
				user_id: string
				core_id: string
				o18y: unknown
				o21y: unknown
				kyc: unknown
				kyc_doc: string | null
				provided_till: number | null
			}>(`SELECT corepass::Profile { user_id, core_id, o18y, o21y, kyc, kyc_doc, provided_till } FILTER .user_id = <str>$userId`, {
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
