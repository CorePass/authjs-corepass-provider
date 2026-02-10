import type { CorePassStore, CorePassTx } from "../types.js"

/**
 * Minimal Firestore-like client. Use with Firebase Admin or firebase/firestore.
 * Collections: corepass_pending (doc id = key), corepass_identities (doc id = core_id), corepass_profiles (doc id = user_id).
 * @see https://authjs.dev/getting-started/database — Firebase
 */
export type FirestoreLike = {
	collection: (name: string) => {
		doc: (id: string) => {
			get: () => Promise<{ exists: boolean; data: () => Record<string, unknown> }>
			set: (data: Record<string, unknown>) => Promise<void>
			delete: () => Promise<void>
		}
		where: (field: string, op: string, value: string) => {
			limit: (n: number) => { get: () => Promise<{ docs: { data: () => Record<string, unknown> }[] }> }
		}
	}
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

export type CorePassFirebaseAdapterOptions = {
	client: FirestoreLike
	pendingCollection?: string
	identitiesCollection?: string
	profilesCollection?: string
}

/**
 * CorePass store + pending for Firebase Firestore.
 * Merge with your Auth.js Firebase adapter: adapter = { ...authAdapter, ...corepassFirebaseAdapter({ client: firestore }) }
 */
export function corepassFirebaseAdapter(opts: CorePassFirebaseAdapterOptions): CorePassStore & CorePassTx {
	const {
		client,
		pendingCollection = PENDING_COLLECTION,
		identitiesCollection = IDENTITIES_COLLECTION,
		profilesCollection = PROFILES_COLLECTION,
	} = opts

	return {
		async setPending(params, _ctx) {
			const expiresAtSec = Math.floor(params.expiresAt.getTime() / 1000)
			await client.collection(pendingCollection).doc(params.key).set({
				key: params.key,
				payload_json: JSON.stringify(params.payload),
				expires_at: expiresAtSec,
				created_at: nowSec(),
			})
		},

		async consumePending(params, _ctx) {
			const ref = client.collection(pendingCollection).doc(params.key)
			const snap = await ref.get()
			if (!snap.exists) return null
			const data = snap.data()
			const raw = data?.payload_json
			await ref.delete()
			if (typeof raw !== "string") return null
			try {
				return JSON.parse(raw) as unknown
			} catch {
				return null
			}
		},

		async getIdentityByCoreId(params, _ctx) {
			const snap = await client.collection(identitiesCollection).doc(params.coreId).get()
			if (!snap.exists) return null
			const row = snap.data()!
			return {
				coreId: String(row.core_id ?? params.coreId),
				userId: String(row.user_id ?? ""),
				refId: row.ref_id != null ? String(row.ref_id) : null,
			}
		},

		async getIdentityByUserId(params, _ctx) {
			const snap = await client
				.collection(identitiesCollection)
				.where("user_id", "==", params.userId)
				.limit(1)
				.get()
			const doc = snap.docs[0]
			if (!doc) return null
			const row = doc.data()
			return {
				coreId: String(row.core_id ?? ""),
				userId: String(row.user_id ?? params.userId),
				refId: row.ref_id != null ? String(row.ref_id) : null,
			}
		},

		async upsertIdentity(identity, _ctx) {
			await client.collection(identitiesCollection).doc(identity.coreId).set({
				core_id: identity.coreId,
				user_id: identity.userId,
				ref_id: identity.refId ?? null,
				updated_at: nowSec(),
			})
		},

		async upsertProfile(profile, _ctx) {
			await client.collection(profilesCollection).doc(profile.userId).set({
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
			const snap = await client.collection(profilesCollection).doc(params.userId).get()
			if (!snap.exists) return null
			const row = snap.data()!
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
