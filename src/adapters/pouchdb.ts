import type { AdapterAuthenticator } from "@auth/core/adapters"
import type { CorePassStore, CorePassTx } from "../types.js"

/**
 * Minimal PouchDB-like interface for CorePass.
 * Use with pouchdb-browser or pouchdb-node: get(id), put(doc), remove(doc), allDocs({ key, startkey, endkey }) or find(selector).
 */
export type PouchDBLike = {
	get: (id: string) => Promise<{ _id: string; _rev?: string; [key: string]: unknown } | null>
	put: (doc: Record<string, unknown> & { _id: string; _rev?: string }) => Promise<unknown>
	remove: (doc: { _id: string; _rev: string }) => Promise<unknown>
	/** Mango query; for getIdentityByUserId use find({ selector: { user_id } }). Requires index on user_id for identity docs. */
	find?: (query: { selector: Record<string, unknown> }) => Promise<{ docs: Record<string, unknown>[] }>
}

const PENDING_PREFIX = "corepass_pending:"
const IDENTITY_PREFIX = "corepass_identity:"
const PROFILE_PREFIX = "corepass_profile:"
const AUTHENTICATOR_PREFIX = "corepass_authenticator:"

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

function docToAuthenticator(doc: Record<string, unknown>): AdapterAuthenticator {
	return {
		credentialID: String(doc.credential_id ?? ""),
		userId: String(doc.user_id ?? ""),
		providerAccountId: String(doc.provider_account_id ?? ""),
		credentialPublicKey: String(doc.credential_public_key ?? ""),
		counter: typeof doc.counter === "number" ? doc.counter : 0,
		credentialDeviceType: String(doc.credential_device_type ?? ""),
		credentialBackedUp: (doc.credential_backed_up as number) === 1,
		transports: doc.transports != null ? String(doc.transports) : null,
	}
}

/**
 * CorePass store + pending + WebAuthn for PouchDB. Doc _id: corepass_pending:{key}, corepass_identity:{core_id}, corepass_profile:{user_id}, corepass_authenticator:{credential_id}. Optional find() for listAuthenticatorsByUserId. See migrations/pouchdb.
 * Merge with your Auth.js PouchDB adapter: adapter = { ...authAdapter, ...corepassPouchAdapter(db) }
 */
export function corepassPouchAdapter(db: PouchDBLike): CorePassStore & CorePassTx & {
	getAuthenticator(credentialID: string): Promise<AdapterAuthenticator | null>
	createAuthenticator(authenticator: AdapterAuthenticator): Promise<AdapterAuthenticator>
	updateAuthenticatorCounter(credentialID: string, newCounter: number): Promise<AdapterAuthenticator>
	listAuthenticatorsByUserId(userId: string): Promise<AdapterAuthenticator[]>
} {
	function idPending(key: string) {
		return PENDING_PREFIX + key
	}
	function idIdentity(coreId: string) {
		return IDENTITY_PREFIX + coreId
	}
	function idProfile(userId: string) {
		return PROFILE_PREFIX + userId
	}
	function idAuthenticator(credentialId: string) {
		return AUTHENTICATOR_PREFIX + credentialId
	}

	return {
		async setPending(params, _ctx) {
			const _id = idPending(params.key)
			const existing = await db.get(_id)
			const expiresAtSec = Math.floor(params.expiresAt.getTime() / 1000)
			await db.put({
				_id,
				...(existing?._rev && { _rev: existing._rev }),
				key: params.key,
				payload_json: JSON.stringify(params.payload),
				expires_at: expiresAtSec,
				created_at: nowSec(),
			} as Record<string, unknown> & { _id: string; _rev?: string })
		},

		async consumePending(params, _ctx) {
			const _id = idPending(params.key)
			const doc = await db.get(_id)
			if (!doc || !doc._rev) return null
			await db.remove({ _id, _rev: doc._rev })
			const raw = doc.payload_json
			if (typeof raw !== "string") return null
			try {
				return JSON.parse(raw) as unknown
			} catch {
				return null
			}
		},

		async getIdentityByCoreId(params, _ctx) {
			const doc = await db.get(idIdentity(params.coreId))
			if (!doc) return null
			return {
				coreId: String(doc.core_id ?? params.coreId),
				userId: String(doc.user_id ?? ""),
				refId: doc.ref_id != null ? String(doc.ref_id) : null,
			}
		},

		async getIdentityByUserId(params, _ctx) {
			if (db.find) {
				const res = await db.find({ selector: { user_id: params.userId } } as { selector: Record<string, unknown> })
				const doc = res.docs[0]
				if (!doc) return null
				return {
					coreId: String(doc.core_id ?? ""),
					userId: String(doc.user_id ?? params.userId),
					refId: doc.ref_id != null ? String(doc.ref_id) : null,
				}
			}
			return null
		},

		async upsertIdentity(identity, _ctx) {
			const _id = idIdentity(identity.coreId)
			const existing = await db.get(_id)
			await db.put({
				_id,
				...(existing?._rev && { _rev: existing._rev }),
				core_id: identity.coreId,
				user_id: identity.userId,
				ref_id: identity.refId ?? null,
				updated_at: nowSec(),
			} as Record<string, unknown> & { _id: string; _rev?: string })
		},

		async upsertProfile(profile, _ctx) {
			const _id = idProfile(profile.userId)
			const existing = await db.get(_id)
			await db.put({
				_id,
				...(existing?._rev && { _rev: existing._rev }),
				user_id: profile.userId,
				core_id: profile.coreId,
				o18y: boolToDb(profile.o18y),
				o21y: boolToDb(profile.o21y),
				kyc: boolToDb(profile.kyc),
				kyc_doc: profile.kycDoc ?? null,
				provided_till: profile.providedTill ?? null,
				updated_at: nowSec(),
			} as Record<string, unknown> & { _id: string; _rev?: string })
		},

		async getProfile(params, _ctx) {
			const doc = await db.get(idProfile(params.userId))
			if (!doc) return null
			return {
				userId: String(doc.user_id ?? params.userId),
				coreId: String(doc.core_id ?? ""),
				o18y: boolFromDb(doc.o18y),
				o21y: boolFromDb(doc.o21y),
				kyc: boolFromDb(doc.kyc),
				kycDoc: doc.kyc_doc != null ? String(doc.kyc_doc) : null,
				providedTill: typeof doc.provided_till === "number" ? doc.provided_till : null,
			}
		},

		async getAuthenticator(credentialID: string): Promise<AdapterAuthenticator | null> {
			const doc = await db.get(idAuthenticator(credentialID))
			if (!doc) return null
			return docToAuthenticator(doc)
		},
		async createAuthenticator(authenticator: AdapterAuthenticator): Promise<AdapterAuthenticator> {
			const _id = idAuthenticator(authenticator.credentialID)
			const existing = await db.get(_id)
			await db.put({
				_id,
				...(existing?._rev && { _rev: existing._rev }),
				credential_id: authenticator.credentialID,
				user_id: authenticator.userId,
				provider_account_id: authenticator.providerAccountId,
				credential_public_key: authenticator.credentialPublicKey,
				counter: authenticator.counter,
				credential_device_type: authenticator.credentialDeviceType,
				credential_backed_up: authenticator.credentialBackedUp ? 1 : 0,
				transports: authenticator.transports ?? null,
			} as Record<string, unknown> & { _id: string; _rev?: string })
			return authenticator
		},
		async updateAuthenticatorCounter(credentialID: string, newCounter: number): Promise<AdapterAuthenticator> {
			const _id = idAuthenticator(credentialID)
			const doc = await db.get(_id)
			if (!doc || !doc._rev) throw new Error(`Authenticator not found: ${credentialID}`)
			await db.put({
				...doc,
				_id,
				_rev: doc._rev,
				counter: newCounter,
			} as Record<string, unknown> & { _id: string; _rev: string })
			return docToAuthenticator({ ...doc, counter: newCounter })
		},
		async listAuthenticatorsByUserId(userId: string): Promise<AdapterAuthenticator[]> {
			if (!db.find) return []
			const res = await db.find({ selector: { user_id: userId } } as { selector: Record<string, unknown> })
			return res.docs.map(docToAuthenticator)
		},
	}
}
