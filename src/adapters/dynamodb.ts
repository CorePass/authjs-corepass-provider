import type { AdapterAuthenticator } from "@auth/core/adapters"
import type { CorePassStore, CorePassTx } from "../types.js"

/**
 * Minimal DynamoDB-like client for CorePass.
 * Use with @aws-sdk/lib-dynamodb (DynamoDBDocumentClient): put/get/delete/query by partition key.
 * Tables: corepass_pending (pk = key), corepass_identities (pk = core_id; optional GSI for user_id), corepass_profiles (pk = user_id), authenticators (pk = credential_id; optional GSI on user_id for listAuthenticatorsByUserId).
 */
export type DynamoLike = {
	put: (table: string, item: Record<string, unknown>) => Promise<void>
	get: (table: string, key: Record<string, unknown>) => Promise<Record<string, unknown> | null>
	delete: (table: string, key: Record<string, unknown>) => Promise<void>
	/** Query by partition key. For identities by user_id use queryByUserId. */
	queryByPk?: (table: string, pkName: string, pkValue: string) => Promise<Record<string, unknown>[]>
	/** If your identities table has a GSI on user_id, provide this to support getIdentityByUserId. */
	queryByUserId?: (userId: string) => Promise<{ core_id: string; user_id: string; ref_id: string | null } | null>
	/** If your authenticators table has a GSI on user_id, provide this to support listAuthenticatorsByUserId. */
	queryAuthenticatorsByUserId?: (userId: string) => Promise<Record<string, unknown>[]>
}

const PENDING_TABLE = "corepass_pending"
const IDENTITIES_TABLE = "corepass_identities"
const PROFILES_TABLE = "corepass_profiles"
const AUTHENTICATORS_TABLE = "authenticators"

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

export type CorePassDynamoAdapterOptions = {
	client: DynamoLike
	pendingTable?: string
	identitiesTable?: string
	profilesTable?: string
	authenticatorsTable?: string
}

/**
 * CorePass store + pending + WebAuthn authenticator methods for DynamoDB.
 * Merge with your Auth.js DynamoDB adapter: adapter = { ...authAdapter, ...corepassDynamoAdapter(opts) }
 * Authenticators table: pk = credential_id; implement queryAuthenticatorsByUserId (e.g. GSI on user_id) for listAuthenticatorsByUserId.
 */
export function corepassDynamoAdapter(opts: CorePassDynamoAdapterOptions): CorePassStore & CorePassTx & {
	getAuthenticator(credentialID: string): Promise<AdapterAuthenticator | null>
	createAuthenticator(authenticator: AdapterAuthenticator): Promise<AdapterAuthenticator>
	updateAuthenticatorCounter(credentialID: string, newCounter: number): Promise<AdapterAuthenticator>
	listAuthenticatorsByUserId(userId: string): Promise<AdapterAuthenticator[]>
} {
	const {
		client,
		pendingTable = PENDING_TABLE,
		identitiesTable = IDENTITIES_TABLE,
		profilesTable = PROFILES_TABLE,
		authenticatorsTable = AUTHENTICATORS_TABLE,
	} = opts

	return {
		async setPending(params, _ctx) {
			const expiresAtSec = Math.floor(params.expiresAt.getTime() / 1000)
			await client.put(pendingTable, {
				key: params.key,
				payload_json: JSON.stringify(params.payload),
				expires_at: expiresAtSec,
				created_at: nowSec(),
			})
		},

		async consumePending(params, _ctx) {
			const row = await client.get(pendingTable, { key: params.key })
			if (!row) return null
			await client.delete(pendingTable, { key: params.key })
			const raw = row.payload_json
			if (typeof raw !== "string") return null
			try {
				return JSON.parse(raw) as unknown
			} catch {
				return null
			}
		},

		async getIdentityByCoreId(params, _ctx) {
			const row = await client.get(identitiesTable, { core_id: params.coreId })
			if (!row) return null
			return {
				coreId: String(row.core_id ?? params.coreId),
				userId: String(row.user_id ?? ""),
				refId: row.ref_id != null ? String(row.ref_id) : null,
			}
		},

		async getIdentityByUserId(params, _ctx) {
			if (client.queryByUserId) {
				const row = await client.queryByUserId(params.userId)
				if (!row) return null
				return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id }
			}
			return null
		},

		async upsertIdentity(identity, _ctx) {
			await client.put(identitiesTable, {
				core_id: identity.coreId,
				user_id: identity.userId,
				ref_id: identity.refId ?? null,
				updated_at: nowSec(),
			})
		},

		async upsertProfile(profile, _ctx) {
			await client.put(profilesTable, {
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
			const row = await client.get(profilesTable, { user_id: params.userId })
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

		// WebAuthn / Passkey (Auth.js adapter optional methods)
		async getAuthenticator(credentialID: string): Promise<AdapterAuthenticator | null> {
			const row = await client.get(authenticatorsTable, { credential_id: credentialID })
			if (!row) return null
			return rowToAuthenticator(row)
		},
		async createAuthenticator(authenticator: AdapterAuthenticator): Promise<AdapterAuthenticator> {
			await client.put(authenticatorsTable, {
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
			const row = await client.get(authenticatorsTable, { credential_id: credentialID })
			if (!row) throw new Error(`Authenticator not found: ${credentialID}`)
			await client.put(authenticatorsTable, {
				...row,
				counter: newCounter,
			})
			return rowToAuthenticator({ ...row, counter: newCounter })
		},
		async listAuthenticatorsByUserId(userId: string): Promise<AdapterAuthenticator[]> {
			if (!client.queryAuthenticatorsByUserId) return []
			const rows = await client.queryAuthenticatorsByUserId(userId)
			return rows.map(rowToAuthenticator)
		},
	}
}
