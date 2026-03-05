import type { AdapterAuthenticator } from "@auth/core/adapters"
import type { CorePassStore, CorePassTx } from "../types.js"

/** D1/SQLite–like interface (Cloudflare D1). Includes .all() for list queries. */
export type D1Like = {
	prepare: (sql: string) => {
		bind: (...params: unknown[]) => {
			run: () => Promise<unknown>
			first: <T = unknown>() => Promise<T | null>
			all?: <T = unknown>() => Promise<{ results: T[] }>
		}
		run?: () => Promise<unknown>
	}
}

function rowToAuthenticator(row: Record<string, unknown>): AdapterAuthenticator {
	return {
		credentialID: row.credential_id as string,
		userId: row.user_id as string,
		providerAccountId: row.provider_account_id as string,
		credentialPublicKey: row.credential_public_key as string,
		counter: (row.counter as number) ?? 0,
		credentialDeviceType: row.credential_device_type as string,
		credentialBackedUp: (row.credential_backed_up as number) === 1,
		transports: (row.transports as string) ?? null,
	}
}

function nowSec(): number {
	return Math.floor(Date.now() / 1000)
}

function boolToDb(v: boolean | null | undefined): 0 | 1 | null {
	if (v === null || v === undefined) return null
	return v ? 1 : 0
}

function boolFromDb(v: unknown): boolean | null {
	if (v === null || v === undefined) return null
	if (typeof v === "boolean") return v
	return (v as number) === 1
}

/**
 * CorePass store + pending + WebAuthn authenticator methods for D1/SQLite.
 * Tables must exist before use; run migrateD1(db) once to create Auth.js + CorePass + authenticators.
 * Merge with your Auth.js D1 adapter: adapter = { ...D1Adapter(db), ...corepassD1Adapter(db) }
 * @see https://authjs.dev/getting-started/providers/passkey
 */
export async function corepassD1Adapter(db: D1Like): Promise<CorePassStore & CorePassTx & {
	getAuthenticator(credentialID: string): Promise<AdapterAuthenticator | null>
	createAuthenticator(authenticator: AdapterAuthenticator): Promise<AdapterAuthenticator>
	updateAuthenticatorCounter(credentialID: string, newCounter: number): Promise<AdapterAuthenticator>
	listAuthenticatorsByUserId(userId: string): Promise<AdapterAuthenticator[]>
}> {
	return {
		async setPending(params, _ctx) {
			const expiresAtSec = Math.floor(params.expiresAt.getTime() / 1000)
			const payloadJson = JSON.stringify(params.payload)
			await db
				.prepare(
					`INSERT INTO corepass_pending (key, payload_json, expires_at, created_at)
					 VALUES (?1, ?2, ?3, ?4)
					 ON CONFLICT(key) DO UPDATE SET payload_json = excluded.payload_json, expires_at = excluded.expires_at`
				)
				.bind(params.key, payloadJson, expiresAtSec, nowSec())
				.run()
		},

		async consumePending(params, _ctx) {
			const row = await db
				.prepare(`SELECT payload_json FROM corepass_pending WHERE key = ?1`)
				.bind(params.key)
				.first<{ payload_json: string }>()
			if (!row) return null
			await db.prepare(`DELETE FROM corepass_pending WHERE key = ?1`).bind(params.key).run()
			try {
				return JSON.parse(row.payload_json) as unknown
			} catch {
				return null
			}
		},

		async getIdentityByCoreId(params, _ctx) {
			const row = await db
				.prepare(`SELECT core_id, user_id, ref_id FROM corepass_identities WHERE core_id = ?1`)
				.bind(params.coreId)
				.first<{ core_id: string; user_id: string; ref_id: string | null }>()
			if (!row) return null
			return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id ?? null }
		},

		async getIdentityByUserId(params, _ctx) {
			const row = await db
				.prepare(`SELECT core_id, user_id, ref_id FROM corepass_identities WHERE user_id = ?1`)
				.bind(params.userId)
				.first<{ core_id: string; user_id: string; ref_id: string | null }>()
			if (!row) return null
			return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id ?? null }
		},

		async upsertIdentity(identity, _ctx) {
			const now = nowSec()
			await db
				.prepare(
					`INSERT INTO corepass_identities (core_id, user_id, ref_id, created_at, updated_at)
					 VALUES (?1, ?2, ?3, ?4, ?4)
					 ON CONFLICT(core_id) DO UPDATE SET
					   user_id = excluded.user_id,
					   ref_id = COALESCE(corepass_identities.ref_id, excluded.ref_id),
					   updated_at = ?4`
				)
				.bind(identity.coreId, identity.userId, identity.refId ?? null, now)
				.run()
		},

		async upsertProfile(profile, _ctx) {
			const now = nowSec()
			await db
				.prepare(
					`INSERT INTO corepass_profiles (user_id, core_id, o18y, o21y, kyc, kyc_doc, provided_till, created_at, updated_at)
					 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
					 ON CONFLICT(user_id) DO UPDATE SET
					   core_id = excluded.core_id,
					   o18y = excluded.o18y,
					   o21y = excluded.o21y,
					   kyc = excluded.kyc,
					   kyc_doc = excluded.kyc_doc,
					   provided_till = excluded.provided_till,
					   updated_at = ?8`
				)
				.bind(
					profile.userId,
					profile.coreId,
					boolToDb(profile.o18y),
					boolToDb(profile.o21y),
					boolToDb(profile.kyc),
					profile.kycDoc ?? null,
					profile.providedTill ?? null,
					now
				)
				.run()
		},

		async getProfile(params, _ctx) {
			const row = await db
				.prepare(
					`SELECT user_id, core_id, o18y, o21y, kyc, kyc_doc, provided_till FROM corepass_profiles WHERE user_id = ?1`
				)
				.bind(params.userId)
				.first<{
					user_id: string
					core_id: string
					o18y: number | null
					o21y: number | null
					kyc: number | null
					kyc_doc: string | null
					provided_till: number | null
				}>()
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

		// WebAuthn / Passkey (Auth.js adapter optional methods)
		async getAuthenticator(credentialID: string): Promise<AdapterAuthenticator | null> {
			const row = await db
				.prepare(
					"SELECT credential_id, user_id, provider_account_id, credential_public_key, counter, credential_device_type, credential_backed_up, transports FROM authenticators WHERE credential_id = ?1"
				)
				.bind(credentialID)
				.first<Record<string, unknown>>()
			return row ? rowToAuthenticator(row) : null
		},
		async createAuthenticator(authenticator: AdapterAuthenticator): Promise<AdapterAuthenticator> {
			await db
				.prepare(
					"INSERT INTO authenticators (credential_id, user_id, provider_account_id, credential_public_key, counter, credential_device_type, credential_backed_up, transports) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
				)
				.bind(
					authenticator.credentialID,
					authenticator.userId,
					authenticator.providerAccountId,
					authenticator.credentialPublicKey,
					authenticator.counter,
					authenticator.credentialDeviceType,
					authenticator.credentialBackedUp ? 1 : 0,
					authenticator.transports ?? null
				)
				.run()
			return authenticator
		},
		async updateAuthenticatorCounter(credentialID: string, newCounter: number): Promise<AdapterAuthenticator> {
			await db
				.prepare("UPDATE authenticators SET counter = ?1 WHERE credential_id = ?2")
				.bind(newCounter, credentialID)
				.run()
			const row = await db
				.prepare(
					"SELECT credential_id, user_id, provider_account_id, credential_public_key, counter, credential_device_type, credential_backed_up, transports FROM authenticators WHERE credential_id = ?1"
				)
				.bind(credentialID)
				.first<Record<string, unknown>>()
			if (!row) throw new Error(`Authenticator not found: ${credentialID}`)
			return rowToAuthenticator(row)
		},
		async listAuthenticatorsByUserId(userId: string): Promise<AdapterAuthenticator[]> {
			const stmt = db
				.prepare(
					"SELECT credential_id, user_id, provider_account_id, credential_public_key, counter, credential_device_type, credential_backed_up, transports FROM authenticators WHERE user_id = ?1"
				)
				.bind(userId)
			const result = stmt.all ? await stmt.all<Record<string, unknown>>() : { results: [] }
			const rows = result && typeof result === "object" && "results" in result ? (result.results ?? []) : []
			return rows.map(rowToAuthenticator)
		},
	}
}
