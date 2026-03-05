import type { AdapterAuthenticator } from "@auth/core/adapters"
import type { CorePassStore, CorePassTx } from "../types.js"

const AUTHENTICATORS_TABLE = "corepass_authenticators" as const
type CorePassTable = "corepass_pending" | "corepass_identities" | "corepass_profiles" | typeof AUTHENTICATORS_TABLE

/**
 * Minimal Xata-like client for CorePass tables.
 * Use with @xata.io/client: pass your table instances or a wrapper that implements this interface.
 * Tables: corepass_pending (id = key), corepass_identities (id = core_id), corepass_profiles (id = user_id), corepass_authenticators (id = credential_id).
 */
export type XataLike = {
	getRecord: (table: CorePassTable, id: string) => Promise<Record<string, unknown> | null>
	createOrUpdateRecord: (table: CorePassTable, id: string, data: Record<string, unknown>) => Promise<void>
	deleteRecord: (table: CorePassTable, id: string) => Promise<void>
	/** Query identities by user_id (e.g. filter "user_id = ?"). */
	getIdentityByUserId?: (userId: string) => Promise<{ core_id: string; user_id: string; ref_id: string | null } | null>
	/** Optional: query authenticators by user_id for listAuthenticatorsByUserId. */
	getAuthenticatorsByUserId?: (userId: string) => Promise<Record<string, unknown>[]>
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

function rowToAuthenticator(row: Record<string, unknown>): AdapterAuthenticator {
	return {
		credentialID: String(row.credential_id ?? ""),
		userId: String(row.user_id ?? ""),
		providerAccountId: String(row.provider_account_id ?? ""),
		credentialPublicKey: String(row.credential_public_key ?? ""),
		counter: typeof row.counter === "number" ? row.counter : 0,
		credentialDeviceType: String(row.credential_device_type ?? ""),
		credentialBackedUp: (row.credential_backed_up as number) === 1,
		transports: row.transports != null ? String(row.transports) : null,
	}
}

/**
 * CorePass store + pending + WebAuthn for Xata. Table: corepass_authenticators (id = credential_id). Optional getAuthenticatorsByUserId for list. See migrations/xata.
 * Merge with your Auth.js Xata adapter: adapter = { ...authAdapter, ...corepassXataAdapter(xata) }
 */
export function corepassXataAdapter(client: XataLike): CorePassStore & CorePassTx & {
	getAuthenticator(credentialID: string): Promise<AdapterAuthenticator | null>
	createAuthenticator(authenticator: AdapterAuthenticator): Promise<AdapterAuthenticator>
	updateAuthenticatorCounter(credentialID: string, newCounter: number): Promise<AdapterAuthenticator>
	listAuthenticatorsByUserId(userId: string): Promise<AdapterAuthenticator[]>
} {
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

		async getAuthenticator(credentialID: string): Promise<AdapterAuthenticator | null> {
			const row = await client.getRecord(AUTHENTICATORS_TABLE, credentialID)
			if (!row) return null
			return rowToAuthenticator(row)
		},
		async createAuthenticator(authenticator: AdapterAuthenticator): Promise<AdapterAuthenticator> {
			await client.createOrUpdateRecord(AUTHENTICATORS_TABLE, authenticator.credentialID, {
				credential_id: authenticator.credentialID,
				user_id: authenticator.userId,
				provider_account_id: authenticator.providerAccountId,
				credential_public_key: authenticator.credentialPublicKey,
				counter: authenticator.counter,
				credential_device_type: authenticator.credentialDeviceType,
				credential_backed_up: authenticator.credentialBackedUp ? 1 : 0,
				transports: authenticator.transports ?? null,
			})
			return authenticator
		},
		async updateAuthenticatorCounter(credentialID: string, newCounter: number): Promise<AdapterAuthenticator> {
			const row = await client.getRecord(AUTHENTICATORS_TABLE, credentialID)
			if (!row) throw new Error(`Authenticator not found: ${credentialID}`)
			await client.createOrUpdateRecord(AUTHENTICATORS_TABLE, credentialID, { ...row, counter: newCounter })
			return rowToAuthenticator({ ...row, counter: newCounter })
		},
		async listAuthenticatorsByUserId(userId: string): Promise<AdapterAuthenticator[]> {
			if (!client.getAuthenticatorsByUserId) return []
			const rows = await client.getAuthenticatorsByUserId(userId)
			return rows.map(rowToAuthenticator)
		},
	}
}
