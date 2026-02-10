import type { CorePassStore, CorePassTx } from "../types.js"

/**
 * Minimal Fauna-like client. Use with faunadb: client.query() to run FQL.
 * Collections: corepass_pending, corepass_identities, corepass_profiles.
 * @see https://authjs.dev/getting-started/database — FaunaDB
 */
export type FaunaLike = {
	query: (fql: unknown) => Promise<unknown>
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
 * Adapter that delegates to a Fauna client. You must implement the FQL operations;
 * this type expects query() to return data in a consistent shape (e.g. { data: [...] } or single doc).
 */
export type FaunaCorePassLike = {
	createOrUpdatePending: (key: string, payload: string, expiresAtSec: number) => Promise<void>
	getAndDeletePending: (key: string) => Promise<string | null>
	getIdentityByCoreId: (coreId: string) => Promise<{ core_id: string; user_id: string; ref_id: string | null } | null>
	getIdentityByUserId: (userId: string) => Promise<{ core_id: string; user_id: string; ref_id: string | null } | null>
	upsertIdentity: (identity: { core_id: string; user_id: string; ref_id: string | null }) => Promise<void>
	upsertProfile: (profile: Record<string, unknown>) => Promise<void>
	getProfile: (userId: string) => Promise<{
		user_id: string
		core_id: string
		o18y: unknown
		o21y: unknown
		kyc: unknown
		kyc_doc: string | null
		provided_till: number | null
	} | null>
}

/**
 * CorePass store + pending for Fauna. Pass a wrapper that implements FaunaCorePassLike (using Fauna FQL).
 * Merge with your Auth.js Fauna adapter: adapter = { ...authAdapter, ...corepassFaunaAdapter(faunaCorePass) }
 */
export function corepassFaunaAdapter(client: FaunaCorePassLike): CorePassStore & CorePassTx {
	return {
		async setPending(params, _ctx) {
			const expiresAtSec = Math.floor(params.expiresAt.getTime() / 1000)
			await client.createOrUpdatePending(params.key, JSON.stringify(params.payload), expiresAtSec)
		},

		async consumePending(params, _ctx) {
			const raw = await client.getAndDeletePending(params.key)
			if (!raw) return null
			try {
				return JSON.parse(raw) as unknown
			} catch {
				return null
			}
		},

		async getIdentityByCoreId(params, _ctx) {
			const row = await client.getIdentityByCoreId(params.coreId)
			if (!row) return null
			return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id }
		},

		async getIdentityByUserId(params, _ctx) {
			const row = await client.getIdentityByUserId(params.userId)
			if (!row) return null
			return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id }
		},

		async upsertIdentity(identity, _ctx) {
			await client.upsertIdentity({
				core_id: identity.coreId,
				user_id: identity.userId,
				ref_id: identity.refId ?? null,
			})
		},

		async upsertProfile(profile, _ctx) {
			await client.upsertProfile({
				user_id: profile.userId,
				core_id: profile.coreId,
				o18y: boolToDb(profile.o18y),
				o21y: boolToDb(profile.o21y),
				kyc: boolToDb(profile.kyc),
				kyc_doc: profile.kycDoc ?? null,
				provided_till: profile.providedTill ?? null,
			})
		},

		async getProfile(params, _ctx) {
			const row = await client.getProfile(params.userId)
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
