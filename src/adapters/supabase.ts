import type { CorePassStore, CorePassTx } from "../types.js"

export type SupabaseLike = {
	from: (table: string) => {
		select: (cols: string) => { eq: (col: string, value: unknown) => Promise<{ data: unknown[]; error: unknown }> }
		upsert: (row: Record<string, unknown>, opts: { onConflict: string }) => Promise<{ data: unknown; error: unknown }>
		delete: () => { eq: (col: string, value: unknown) => { select: (cols: string) => Promise<{ data: unknown[]; error: unknown }> } }
	}
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

function maybeFirst<T>(res: { data: unknown[] | null; error: unknown }): T | null {
	if (res.error || !res.data || res.data.length === 0) return null
	return res.data[0] as T
}

/**
 * CorePass store + pending (key/payload) for Supabase (Postgres).
 * Merge with your Auth.js Supabase adapter: adapter = { ...authAdapter, ...corepassSupabaseAdapter(supabase) }
 */
export function corepassSupabaseAdapter(supabase: SupabaseLike): CorePassStore & CorePassTx {
	const tablePending = "corepass_pending"
	const tableIdentities = "corepass_identities"
	const tableProfiles = "corepass_profiles"

	return {
		async setPending(params, _ctx) {
			const expiresAtSec = Math.floor(params.expiresAt.getTime() / 1000)
			const payloadJson = typeof params.payload === "string" ? params.payload : JSON.stringify(params.payload)
			await supabase.from(tablePending).upsert(
				{
					key: params.key,
					payload_json: payloadJson,
					expires_at: expiresAtSec,
					created_at: nowSec(),
				},
				{ onConflict: "key" }
			)
		},

		async consumePending(params, _ctx) {
			const res = await supabase.from(tablePending).delete().eq("key", params.key).select("payload_json")
			const row = maybeFirst<{ payload_json: string | unknown }>(res as { data: unknown[]; error: unknown })
			if (!row?.payload_json) return null
			const raw = row.payload_json
			if (typeof raw === "string") {
				try {
					return JSON.parse(raw) as unknown
				} catch {
					return null
				}
			}
			return raw
		},

		async getIdentityByCoreId(params, _ctx) {
			const res = await supabase.from(tableIdentities).select("core_id, user_id, ref_id").eq("core_id", params.coreId)
			const row = maybeFirst<{ core_id: string; user_id: string; ref_id: string | null }>(res as { data: unknown[]; error: unknown })
			if (!row) return null
			return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id ?? null }
		},

		async getIdentityByUserId(params, _ctx) {
			const res = await supabase.from(tableIdentities).select("core_id, user_id, ref_id").eq("user_id", params.userId)
			const row = maybeFirst<{ core_id: string; user_id: string; ref_id: string | null }>(res as { data: unknown[]; error: unknown })
			if (!row) return null
			return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id ?? null }
		},

		async upsertIdentity(identity, _ctx) {
			await supabase.from(tableIdentities).upsert(
				{
					core_id: identity.coreId,
					user_id: identity.userId,
					ref_id: identity.refId ?? null,
					updated_at: nowSec(),
				},
				{ onConflict: "core_id" }
			)
		},

		async upsertProfile(profile, _ctx) {
			await supabase.from(tableProfiles).upsert(
				{
					user_id: profile.userId,
					core_id: profile.coreId,
					o18y: boolToDb(profile.o18y),
					o21y: boolToDb(profile.o21y),
					kyc: boolToDb(profile.kyc),
					kyc_doc: profile.kycDoc ?? null,
					provided_till: profile.providedTill ?? null,
					updated_at: nowSec(),
				},
				{ onConflict: "user_id" }
			)
		},

		async getProfile(params, _ctx) {
			const res = await supabase
				.from(tableProfiles)
				.select("user_id, core_id, o18y, o21y, kyc, kyc_doc, provided_till")
				.eq("user_id", params.userId)
			const row = maybeFirst<{
				user_id: string
				core_id: string
				o18y: unknown
				o21y: unknown
				kyc: unknown
				kyc_doc: string | null
				provided_till: number | null
			}>(res as { data: unknown[]; error: unknown })
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
