import type { AdapterAuthenticator } from "@auth/core/adapters"
import type { CorePassStore, CorePassTx } from "../types.js"

/**
 * Minimal Azure Table Storage-like client for CorePass.
 * Use with @azure/data-tables: TableClient (createEntity, getEntity, upsertEntity, deleteEntity, listEntities).
 * PartitionKey/RowKey: pending pk="PENDING", rk=key; identities pk="IDENTITY", rk=core_id; profiles pk="PROFILE", rk=user_id; authenticators pk="AUTHENTICATOR", rk=credentialID.
 * queryEntities required for getIdentityByUserId and listAuthenticatorsByUserId (filter by user_id).
 */
export type AzureTablesLike = {
	upsertEntity: (table: string, entity: Record<string, unknown>) => Promise<void>
	getEntity: (table: string, partitionKey: string, rowKey: string) => Promise<Record<string, unknown> | null>
	deleteEntity: (table: string, partitionKey: string, rowKey: string) => Promise<void>
	/** List entities with optional filter; for getIdentityByUserId query identities where user_id = value. */
	queryEntities?: (
		table: string,
		partitionKey: string,
		filter?: string
	) => Promise<Record<string, unknown>[]>
}

const TABLE_NAME = "corepass"
const PK_PENDING = "PENDING"
const PK_IDENTITY = "IDENTITY"
const PK_PROFILE = "PROFILE"
const PK_AUTHENTICATOR = "AUTHENTICATOR"

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
		credentialID: String(row.rowKey ?? ""),
		userId: String(row.user_id ?? ""),
		providerAccountId: String(row.provider_account_id ?? ""),
		credentialPublicKey: String(row.credential_public_key ?? ""),
		counter: typeof row.counter === "number" ? row.counter : 0,
		credentialDeviceType: String(row.credential_device_type ?? ""),
		credentialBackedUp: (row.credential_backed_up as number) === 1,
		transports: row.transports != null ? String(row.transports) : null,
	}
}

function escapeODataString(s: string): string {
	return s.replace(/'/g, "''")
}

export type CorePassAzureTablesAdapterOptions = {
	client: AzureTablesLike
	tableName?: string
}

/**
 * CorePass store + pending + WebAuthn authenticator methods for Azure Table Storage.
 * Merge with your Auth.js Azure Tables adapter: adapter = { ...authAdapter, ...corepassAzureTablesAdapter(opts) }
 * Single table design: partitionKey + rowKey. queryEntities required for getIdentityByUserId and listAuthenticatorsByUserId.
 * Run migrateAzureTables(tableClient) once to ensure the table exists.
 */
export function corepassAzureTablesAdapter(opts: CorePassAzureTablesAdapterOptions): CorePassStore & CorePassTx & {
	getAuthenticator(credentialID: string): Promise<AdapterAuthenticator | null>
	createAuthenticator(authenticator: AdapterAuthenticator): Promise<AdapterAuthenticator>
	updateAuthenticatorCounter(credentialID: string, newCounter: number): Promise<AdapterAuthenticator>
	listAuthenticatorsByUserId(userId: string): Promise<AdapterAuthenticator[]>
} {
	const { client, tableName = TABLE_NAME } = opts
	const t = tableName

	return {
		async setPending(params, _ctx) {
			const expiresAtSec = Math.floor(params.expiresAt.getTime() / 1000)
			await client.upsertEntity(t, {
				partitionKey: PK_PENDING,
				rowKey: params.key,
				payload_json: JSON.stringify(params.payload),
				expires_at: expiresAtSec,
				created_at: nowSec(),
			})
		},

		async consumePending(params, _ctx) {
			const row = await client.getEntity(t, PK_PENDING, params.key)
			if (!row) return null
			await client.deleteEntity(t, PK_PENDING, params.key)
			const raw = row.payload_json
			if (typeof raw !== "string") return null
			try {
				return JSON.parse(raw) as unknown
			} catch {
				return null
			}
		},

		async getIdentityByCoreId(params, _ctx) {
			const row = await client.getEntity(t, PK_IDENTITY, params.coreId)
			if (!row) return null
			return {
				coreId: String(row.core_id ?? params.coreId),
				userId: String(row.user_id ?? ""),
				refId: row.ref_id != null ? String(row.ref_id) : null,
			}
		},

		async getIdentityByUserId(params, _ctx) {
			if (!client.queryEntities) return null
			const rows = await client.queryEntities(t, PK_IDENTITY, `user_id eq '${params.userId.replace(/'/g, "''")}'`)
			const row = rows[0]
			if (!row) return null
			return {
				coreId: String(row.core_id ?? ""),
				userId: String(row.user_id ?? params.userId),
				refId: row.ref_id != null ? String(row.ref_id) : null,
			}
		},

		async upsertIdentity(identity, _ctx) {
			await client.upsertEntity(t, {
				partitionKey: PK_IDENTITY,
				rowKey: identity.coreId,
				core_id: identity.coreId,
				user_id: identity.userId,
				ref_id: identity.refId ?? null,
				updated_at: nowSec(),
			})
		},

		async upsertProfile(profile, _ctx) {
			await client.upsertEntity(t, {
				partitionKey: PK_PROFILE,
				rowKey: profile.userId,
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
			const row = await client.getEntity(t, PK_PROFILE, params.userId)
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
			const row = await client.getEntity(t, PK_AUTHENTICATOR, credentialID)
			if (!row) return null
			return rowToAuthenticator(row)
		},
		async createAuthenticator(authenticator: AdapterAuthenticator): Promise<AdapterAuthenticator> {
			await client.upsertEntity(t, {
				partitionKey: PK_AUTHENTICATOR,
				rowKey: authenticator.credentialID,
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
			const row = await client.getEntity(t, PK_AUTHENTICATOR, credentialID)
			if (!row) throw new Error(`Authenticator not found: ${credentialID}`)
			await client.upsertEntity(t, {
				partitionKey: PK_AUTHENTICATOR,
				rowKey: credentialID,
				user_id: row.user_id,
				provider_account_id: row.provider_account_id,
				credential_public_key: row.credential_public_key,
				counter: newCounter,
				credential_device_type: row.credential_device_type,
				credential_backed_up: row.credential_backed_up,
				transports: row.transports ?? null,
			})
			return rowToAuthenticator({ ...row, counter: newCounter })
		},
		async listAuthenticatorsByUserId(userId: string): Promise<AdapterAuthenticator[]> {
			if (!client.queryEntities) return []
			const rows = await client.queryEntities(
				t,
				PK_AUTHENTICATOR,
				`user_id eq '${escapeODataString(userId)}'`
			)
			return rows.map(rowToAuthenticator)
		},
	}
}
