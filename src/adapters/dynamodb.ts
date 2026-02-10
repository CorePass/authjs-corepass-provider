import type { CorePassStore, CorePassTx } from "../types.js"

/**
 * Minimal DynamoDB-like client for CorePass.
 * Use with @aws-sdk/lib-dynamodb (DynamoDBDocumentClient): put/get/delete/query by partition key.
 * Tables: corepass_pending (pk = key), corepass_identities (pk = core_id; optional GSI for user_id), corepass_profiles (pk = user_id).
 */
export type DynamoLike = {
	put: (table: string, item: Record<string, unknown>) => Promise<void>
	get: (table: string, key: Record<string, unknown>) => Promise<Record<string, unknown> | null>
	delete: (table: string, key: Record<string, unknown>) => Promise<void>
	/** Query by partition key; returns first match or null. For identities by user_id use queryByUserId. */
	queryByPk?: (table: string, pkName: string, pkValue: string) => Promise<Record<string, unknown>[]>
	/** If your identities table has a GSI on user_id, provide this to support getIdentityByUserId. */
	queryByUserId?: (userId: string) => Promise<{ core_id: string; user_id: string; ref_id: string | null } | null>
}

const PENDING_TABLE = "corepass_pending"
const IDENTITIES_TABLE = "corepass_identities"
const PROFILES_TABLE = "corepass_profiles"

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

export type CorePassDynamoAdapterOptions = {
	client: DynamoLike
	pendingTable?: string
	identitiesTable?: string
	profilesTable?: string
}

/**
 * CorePass store + pending for DynamoDB.
 * Merge with your Auth.js DynamoDB adapter: adapter = { ...authAdapter, ...corepassDynamoAdapter(opts) }
 * Ensure tables have pk = key (pending), pk = core_id (identities), pk = user_id (profiles); optional GSI on identities(user_id) and pass queryByUserId for getIdentityByUserId.
 */
export function corepassDynamoAdapter(opts: CorePassDynamoAdapterOptions): CorePassStore & CorePassTx {
	const { client, pendingTable = PENDING_TABLE, identitiesTable = IDENTITIES_TABLE, profilesTable = PROFILES_TABLE } = opts

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
	}
}
