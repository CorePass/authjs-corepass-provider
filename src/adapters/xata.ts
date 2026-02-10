import type { CorePassStore, CorePassTx } from "../types.js"

/**
 * Minimal Xata-like client for CorePass tables.
 * Use with @xata.io/client: pass your table instances or a wrapper that implements this interface.
 * Tables: corepass_pending (id = key), corepass_identities (id = core_id), corepass_profiles (id = user_id).
 */
export type XataLike = {
	getRecord: (table: "corepass_pending" | "corepass_identities" | "corepass_profiles", id: string) => Promise<Record<string, unknown> | null>
	createOrUpdateRecord: (
		table: "corepass_pending" | "corepass_identities" | "corepass_profiles",
		id: string,
		data: Record<string, unknown>
	) => Promise<void>
	deleteRecord: (table: "corepass_pending" | "corepass_identities" | "corepass_profiles", id: string) => Promise<void>
	/** Query identities by user_id (e.g. filter "user_id = ?"). */
	getIdentityByUserId?: (userId: string) => Promise<{ core_id: string; user_id: string; ref_id: string | null } | null>
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
 * CorePass store + pending for Xata.
 * Merge with your Auth.js Xata adapter: adapter = { ...authAdapter, ...corepassXataAdapter(xata) }
 * Implement XataLike e.g. from @xata.io/client table helpers (get, create, update, delete, query).
 */
export function corepassXataAdapter(client: XataLike): CorePassStore & CorePassTx {
	return {
		async setPending(params, _ctx) {
			const expiresAtSec = Math.floor(params.expiresAt.getTime() / 1000)
			await client.createOrUpdateRecord("corepass_pending", params.key, {
				key: params.key,
				payload_json: JSON.stringify(params.payload),
				expires_at: expiresAtSec,
				created_at: nowSec(),
			})
		},

		async consumePending(params, _ctx) {
			const row = await client.getRecord("corepass_pending", params.key)
			if (!row) return null
			await client.deleteRecord("corepass_pending", params.key)
			const raw = row.payload_json
			if (typeof raw !== "string") return null
			try {
				return JSON.parse(raw) as unknown
			} catch {
				return null
			}
		},

		async getIdentityByCoreId(params, _ctx) {
			const row = await client.getRecord("corepass_identities", params.coreId)
			if (!row) return null
			return {
				coreId: String(row.core_id ?? params.coreId),
				userId: String(row.user_id ?? ""),
				refId: row.ref_id != null ? String(row.ref_id) : null,
			}
		},

		async getIdentityByUserId(params, _ctx) {
			if (client.getIdentityByUserId) {
				const row = await client.getIdentityByUserId(params.userId)
				if (!row) return null
				return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id }
			}
			return null
		},

		async upsertIdentity(identity, _ctx) {
			await client.createOrUpdateRecord("corepass_identities", identity.coreId, {
				core_id: identity.coreId,
				user_id: identity.userId,
				ref_id: identity.refId ?? null,
				updated_at: nowSec(),
			})
		},

		async upsertProfile(profile, _ctx) {
			await client.createOrUpdateRecord("corepass_profiles", profile.userId, {
				user_id: profile.userId,
				core_id: profile.coreId,
				o18y: boolToDb(profile.o18y),
				o21y: boolToDb(profile.o21y),
				kyc: boolToDb(profile.kyc),
				kyc_doc: profile.kycDoc ?? null,
				provided_till: profile.providedTill ?? null,
				updated_at: nowSec(),
			})
		},

		async getProfile(params, _ctx) {
			const row = await client.getRecord("corepass_profiles", params.userId)
			if (!row) return null
			return {
				userId: String(row.user_id ?? params.userId),
				coreId: String(row.core_id ?? ""),
				o18y: boolFromDb(row.o18y),
				o21y: boolFromDb(row.o21y),
				kyc: boolFromDb(row.kyc),
				kycDoc: row.kyc_doc != null ? String(row.kyc_doc) : null,
				providedTill: typeof row.provided_till === "number" ? row.provided_till : null,
			}
		},
	}
}
