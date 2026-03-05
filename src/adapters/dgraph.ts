import type { AdapterAuthenticator } from "@auth/core/adapters"
import type { CorePassStore, CorePassTx } from "../types.js"

/**
 * Dgraph adapter uses a small interface you implement with DQL or GraphQL.
 * Add the optional WebAuthn methods for passkey support; apply AUTHENTICATORS_SCHEMA_DGRAPH from migrations/dgraph to your Dgraph schema.
 * @see https://authjs.dev/getting-started/database — Dgraph
 */
export type DgraphCorePassLike = {
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
	/** Optional: for WebAuthn passkey support. Implement and apply AUTHENTICATORS_SCHEMA_DGRAPH. */
	getAuthenticator?: (credentialID: string) => Promise<AdapterAuthenticator | null>
	createAuthenticator?: (authenticator: AdapterAuthenticator) => Promise<AdapterAuthenticator>
	updateAuthenticatorCounter?: (credentialID: string, newCounter: number) => Promise<AdapterAuthenticator>
	listAuthenticatorsByUserId?: (userId: string) => Promise<AdapterAuthenticator[]>
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
 * CorePass store + pending + optional WebAuthn authenticator methods for Dgraph.
 * Pass a wrapper that implements DgraphCorePassLike (using DQL/GraphQL).
 * If the client implements getAuthenticator/createAuthenticator/updateAuthenticatorCounter/listAuthenticatorsByUserId, passkey is supported.
 * Merge with your Auth.js Dgraph adapter: adapter = { ...authAdapter, ...corepassDgraphAdapter(dgraphCorePass) }
 */
export function corepassDgraphAdapter(client: DgraphCorePassLike): CorePassStore & CorePassTx & {
	getAuthenticator(credentialID: string): Promise<AdapterAuthenticator | null>
	createAuthenticator(authenticator: AdapterAuthenticator): Promise<AdapterAuthenticator>
	updateAuthenticatorCounter(credentialID: string, newCounter: number): Promise<AdapterAuthenticator>
	listAuthenticatorsByUserId(userId: string): Promise<AdapterAuthenticator[]>
} {
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

		// WebAuthn / Passkey: delegate to client when implemented
		async getAuthenticator(credentialID: string): Promise<AdapterAuthenticator | null> {
			if (client.getAuthenticator) return client.getAuthenticator(credentialID)
			return null
		},
		async createAuthenticator(authenticator: AdapterAuthenticator): Promise<AdapterAuthenticator> {
			if (client.createAuthenticator) return client.createAuthenticator(authenticator)
			throw new Error("Passkey not supported: implement createAuthenticator on your Dgraph client and apply AUTHENTICATORS_SCHEMA_DGRAPH")
		},
		async updateAuthenticatorCounter(credentialID: string, newCounter: number): Promise<AdapterAuthenticator> {
			if (client.updateAuthenticatorCounter) return client.updateAuthenticatorCounter(credentialID, newCounter)
			throw new Error("Passkey not supported: implement updateAuthenticatorCounter on your Dgraph client")
		},
		async listAuthenticatorsByUserId(userId: string): Promise<AdapterAuthenticator[]> {
			if (client.listAuthenticatorsByUserId) return client.listAuthenticatorsByUserId(userId)
			return []
		},
	}
}
