import type { AdapterAuthenticator } from "@auth/core/adapters"
import type { CorePassStore, CorePassTx } from "../types.js"

/**
 * Minimal Upstash Redis-like client. Use with @upstash/redis.
 * Keys: corepass_pending:{key}, corepass_identity:{core_id}, corepass_profile:{user_id}, corepass_authenticator:{credential_id}. Values are JSON.
 * @see https://authjs.dev/getting-started/database — Upstash Redis
 */
export type UpstashRedisLike = {
	get: (key: string) => Promise<string | null>
	set: (key: string, value: string, options?: { ex?: number }) => Promise<unknown>
	del: (key: string) => Promise<unknown>
	keys: (pattern: string) => Promise<string[]>
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
 * CorePass store + pending + WebAuthn for Upstash Redis. listAuthenticatorsByUserId uses keys("corepass_authenticator:*"). See migrations/upstash-redis.
 * Merge with your Auth.js Upstash Redis adapter: adapter = { ...authAdapter, ...corepassUpstashRedisAdapter(redis) }
 */
export function corepassUpstashRedisAdapter(redis: UpstashRedisLike): CorePassStore & CorePassTx & {
	getAuthenticator(credentialID: string): Promise<AdapterAuthenticator | null>
	createAuthenticator(authenticator: AdapterAuthenticator): Promise<AdapterAuthenticator>
	updateAuthenticatorCounter(credentialID: string, newCounter: number): Promise<AdapterAuthenticator>
	listAuthenticatorsByUserId(userId: string): Promise<AdapterAuthenticator[]>
} {
	return {
		async setPending(params, _ctx) {
			const key = PENDING_PREFIX + params.key
			const expiresAtSec = Math.floor(params.expiresAt.getTime() / 1000)
			const ttl = Math.max(1, expiresAtSec - nowSec())
			const value = JSON.stringify({
				payload: params.payload,
				created_at: nowSec(),
			})
			await redis.set(key, value, { ex: ttl })
		},

		async consumePending(params, _ctx) {
			const key = PENDING_PREFIX + params.key
			const raw = await redis.get(key)
			if (!raw) return null
			await redis.del(key)
			try {
				const parsed = JSON.parse(raw) as { payload?: unknown }
				return parsed.payload ?? null
			} catch {
				return null
			}
		},

		async getIdentityByCoreId(params, _ctx) {
			const key = IDENTITY_PREFIX + params.coreId
			const raw = await redis.get(key)
			if (!raw) return null
			try {
				const row = JSON.parse(raw) as { core_id: string; user_id: string; ref_id: string | null }
				return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id }
			} catch {
				return null
			}
		},

		async getIdentityByUserId(params, _ctx) {
			const keys = await redis.keys(IDENTITY_PREFIX + "*")
			for (const key of keys) {
				const raw = await redis.get(key)
				if (!raw) continue
				try {
					const row = JSON.parse(raw) as { core_id: string; user_id: string; ref_id: string | null }
					if (row.user_id === params.userId) return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id }
				} catch {
					// skip
				}
			}
			return null
		},

		async upsertIdentity(identity, _ctx) {
			const key = IDENTITY_PREFIX + identity.coreId
			await redis.set(key, JSON.stringify({
				core_id: identity.coreId,
				user_id: identity.userId,
				ref_id: identity.refId ?? null,
				updated_at: nowSec(),
			}))
		},

		async upsertProfile(profile, _ctx) {
			const key = PROFILE_PREFIX + profile.userId
			await redis.set(key, JSON.stringify({
				user_id: profile.userId,
				core_id: profile.coreId,
				o18y: boolToDb(profile.o18y),
				o21y: boolToDb(profile.o21y),
				kyc: boolToDb(profile.kyc),
				kyc_doc: profile.kycDoc ?? null,
				provided_till: profile.providedTill ?? null,
				updated_at: nowSec(),
			}))
		},

		async getProfile(params, _ctx) {
			const key = PROFILE_PREFIX + params.userId
			const raw = await redis.get(key)
			if (!raw) return null
			try {
				const row = JSON.parse(raw) as {
					user_id: string
					core_id: string
					o18y: unknown
					o21y: unknown
					kyc: unknown
					kyc_doc: string | null
					provided_till: number | null
				}
				return {
					userId: row.user_id,
					coreId: row.core_id,
					o18y: boolFromDb(row.o18y),
					o21y: boolFromDb(row.o21y),
					kyc: boolFromDb(row.kyc),
					kycDoc: row.kyc_doc ?? null,
					providedTill: row.provided_till ?? null,
				}
			} catch {
				return null
			}
		},

		async getAuthenticator(credentialID: string): Promise<AdapterAuthenticator | null> {
			const key = AUTHENTICATOR_PREFIX + credentialID
			const raw = await redis.get(key)
			if (!raw) return null
			try {
				const row = JSON.parse(raw) as Record<string, unknown>
				return rowToAuthenticator(row)
			} catch {
				return null
			}
		},
		async createAuthenticator(authenticator: AdapterAuthenticator): Promise<AdapterAuthenticator> {
			const key = AUTHENTICATOR_PREFIX + authenticator.credentialID
			const value = JSON.stringify({
				credential_id: authenticator.credentialID,
				user_id: authenticator.userId,
				provider_account_id: authenticator.providerAccountId,
				credential_public_key: authenticator.credentialPublicKey,
				counter: authenticator.counter,
				credential_device_type: authenticator.credentialDeviceType,
				credential_backed_up: authenticator.credentialBackedUp ? 1 : 0,
				transports: authenticator.transports ?? null,
			})
			await redis.set(key, value)
			return authenticator
		},
		async updateAuthenticatorCounter(credentialID: string, newCounter: number): Promise<AdapterAuthenticator> {
			const key = AUTHENTICATOR_PREFIX + credentialID
			const raw = await redis.get(key)
			if (!raw) throw new Error(`Authenticator not found: ${credentialID}`)
			const row = JSON.parse(raw) as Record<string, unknown>
			row.counter = newCounter
			await redis.set(key, JSON.stringify(row))
			return rowToAuthenticator(row)
		},
		async listAuthenticatorsByUserId(userId: string): Promise<AdapterAuthenticator[]> {
			const keys = await redis.keys(AUTHENTICATOR_PREFIX + "*")
			const out: AdapterAuthenticator[] = []
			for (const key of keys) {
				const raw = await redis.get(key)
				if (!raw) continue
				try {
					const row = JSON.parse(raw) as Record<string, unknown>
					if (String(row.user_id) === userId) out.push(rowToAuthenticator(row))
				} catch {
					// skip
				}
			}
			return out
		},
	}
}
