import type { CorePassStore, CorePassTx } from "../types.js"

/**
 * Minimal MongoDB-like collection interface for CorePass.
 * Use with mongodb Driver: Db.collection(name) returns a Collection with findOne, insertOne, updateOne, deleteOne, find.
 */
export type MongoCollectionLike = {
	findOne: (filter: Record<string, unknown>) => Promise<Record<string, unknown> | null>
	insertOne: (doc: Record<string, unknown>) => Promise<unknown>
	updateOne: (filter: Record<string, unknown>, update: { $set: Record<string, unknown> }, opts?: { upsert: boolean }) => Promise<unknown>
	deleteOne: (filter: Record<string, unknown>) => Promise<unknown>
	find: (filter: Record<string, unknown>) => { limit: (n: number) => Promise<Record<string, unknown>[]> }
}

export type MongoLike = {
	collection: (name: string) => MongoCollectionLike
}

const PENDING_COLLECTION = "corepass_pending"
const IDENTITIES_COLLECTION = "corepass_identities"
const PROFILES_COLLECTION = "corepass_profiles"

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

export type CorePassMongoAdapterOptions = {
	client: MongoLike
	pendingCollection?: string
	identitiesCollection?: string
	profilesCollection?: string
}

/**
 * CorePass store + pending for MongoDB.
 * Merge with your Auth.js MongoDB adapter: adapter = { ...authAdapter, ...corepassMongoAdapter(opts) }
 * Collections use key/core_id/user_id as _id or a unique field for lookups.
 */
export function corepassMongoAdapter(opts: CorePassMongoAdapterOptions): CorePassStore & CorePassTx {
	const {
		client,
		pendingCollection = PENDING_COLLECTION,
		identitiesCollection = IDENTITIES_COLLECTION,
		profilesCollection = PROFILES_COLLECTION,
	} = opts
	const pending = client.collection(pendingCollection)
	const identities = client.collection(identitiesCollection)
	const profiles = client.collection(profilesCollection)

	return {
		async setPending(params, _ctx) {
			const expiresAtSec = Math.floor(params.expiresAt.getTime() / 1000)
			await pending.updateOne(
				{ key: params.key },
				{
					$set: {
						key: params.key,
						payload_json: JSON.stringify(params.payload),
						expires_at: expiresAtSec,
						created_at: nowSec(),
					},
				},
				{ upsert: true }
			)
		},

		async consumePending(params, _ctx) {
			const row = await pending.findOne({ key: params.key })
			if (!row) return null
			await pending.deleteOne({ key: params.key })
			const raw = row.payload_json
			if (typeof raw !== "string") return null
			try {
				return JSON.parse(raw) as unknown
			} catch {
				return null
			}
		},

		async getIdentityByCoreId(params, _ctx) {
			const row = await identities.findOne({ core_id: params.coreId })
			if (!row) return null
			return {
				coreId: String(row.core_id ?? params.coreId),
				userId: String(row.user_id ?? ""),
				refId: row.ref_id != null ? String(row.ref_id) : null,
			}
		},

		async getIdentityByUserId(params, _ctx) {
			const row = await identities.findOne({ user_id: params.userId })
			if (!row) return null
			return {
				coreId: String(row.core_id ?? ""),
				userId: String(row.user_id ?? params.userId),
				refId: row.ref_id != null ? String(row.ref_id) : null,
			}
		},

		async upsertIdentity(identity, _ctx) {
			await identities.updateOne(
				{ core_id: identity.coreId },
				{
					$set: {
						core_id: identity.coreId,
						user_id: identity.userId,
						ref_id: identity.refId ?? null,
						updated_at: nowSec(),
					},
				},
				{ upsert: true }
			)
		},

		async upsertProfile(profile, _ctx) {
			await profiles.updateOne(
				{ user_id: profile.userId },
				{
					$set: {
						user_id: profile.userId,
						core_id: profile.coreId,
						o18y: boolToDb(profile.o18y),
						o21y: boolToDb(profile.o21y),
						kyc: boolToDb(profile.kyc),
						kyc_doc: profile.kycDoc ?? null,
						provided_till: profile.providedTill ?? null,
						updated_at: nowSec(),
					},
				},
				{ upsert: true }
			)
		},

		async getProfile(params, _ctx) {
			const row = await profiles.findOne({ user_id: params.userId })
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
