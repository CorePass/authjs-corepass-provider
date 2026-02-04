import type {
	CorePassPendingRegistration,
	CorePassProfile,
	CorePassStore,
	CorePassUserIdentity,
} from "./types.js"

type BoolDb = 0 | 1 | boolean | null

function boolToDb(v: boolean | null): 0 | 1 | null {
	if (v === null) return null
	return v ? 1 : 0
}

function boolFromDb(v: BoolDb): boolean | null {
	if (v === null) return null
	if (typeof v === "boolean") return v
	return v === 1 ? true : v === 0 ? false : null
}

function nowSec(): number {
	return Math.floor(Date.now() / 1000)
}

// -----------------------------
// D1 / SQLite
// -----------------------------

export type D1Like = {
	prepare: (sql: string) => {
		bind: (...params: unknown[]) => {
			run: () => Promise<unknown>
			first: <T = unknown>() => Promise<T | null>
			all?: <T = unknown>() => Promise<{ results: T[] }>
		}
	}
}

export function d1CorePassStore(db: D1Like): CorePassStore {
	return {
		async createPendingRegistration(reg) {
			await db
				.prepare(
					`INSERT INTO corepass_pending_registrations
					(token, credential_id, credential_public_key, counter, credential_device_type, credential_backed_up, transports, email, ref_id, aaguid, created_at, expires_at)
					VALUES
					(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)`
				)
				.bind(
					reg.token,
					reg.credentialId,
					reg.credentialPublicKey,
					reg.counter,
					reg.credentialDeviceType,
					reg.credentialBackedUp ? 1 : 0,
					reg.transports,
					reg.email,
					reg.refId,
					reg.aaguid,
					reg.createdAt,
					reg.expiresAt
				)
				.run()
		},

		async getPendingRegistrationByCredentialId(credentialId) {
			const row = (await db
				.prepare(
					`SELECT token, credential_id, credential_public_key, counter, credential_device_type, credential_backed_up, transports, email, ref_id, aaguid, created_at, expires_at
					FROM corepass_pending_registrations
					WHERE credential_id = ?1`
				)
				.bind(credentialId)
				.first()) as
				| {
						token: string
						credential_id: string
						credential_public_key: string
						counter: number
						credential_device_type: string
						credential_backed_up: number
						transports: string | null
						email: string | null
						ref_id: string | null
						aaguid: string | null
						created_at: number
						expires_at: number
				  }
				| null

			if (!row) return null
			return {
				token: row.token,
				credentialId: row.credential_id,
				credentialPublicKey: row.credential_public_key,
				counter: row.counter ?? 0,
				credentialDeviceType: row.credential_device_type,
				credentialBackedUp: (row.credential_backed_up ?? 0) === 1,
				transports: row.transports ?? null,
				email: row.email ?? null,
				refId: row.ref_id ?? null,
				aaguid: row.aaguid ?? null,
				createdAt: row.created_at ?? nowSec(),
				expiresAt: row.expires_at ?? nowSec(),
			} satisfies CorePassPendingRegistration
		},

		async deletePendingRegistrationByToken(token) {
			await db
				.prepare(`DELETE FROM corepass_pending_registrations WHERE token = ?1`)
				.bind(token)
				.run()
		},

		async getIdentityByCoreId(coreId) {
			const row = (await db
				.prepare(`SELECT core_id, user_id, ref_id FROM corepass_identities WHERE core_id = ?1`)
				.bind(coreId)
				.first()) as { core_id: string; user_id: string; ref_id: string | null } | null
			if (!row) return null
			return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id ?? null } satisfies CorePassUserIdentity
		},

		async getIdentityByUserId(userId) {
			const row = (await db
				.prepare(`SELECT core_id, user_id, ref_id FROM corepass_identities WHERE user_id = ?1`)
				.bind(userId)
				.first()) as { core_id: string; user_id: string; ref_id: string | null } | null
			if (!row) return null
			return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id ?? null } satisfies CorePassUserIdentity
		},

		async upsertIdentity(identity) {
			await db
				.prepare(
					`INSERT INTO corepass_identities (core_id, user_id, ref_id, created_at, updated_at)
					VALUES (?1, ?2, ?3, strftime('%s','now'), strftime('%s','now'))
					ON CONFLICT(core_id) DO UPDATE SET
						user_id = excluded.user_id,
						ref_id = COALESCE(corepass_identities.ref_id, excluded.ref_id),
						updated_at = strftime('%s','now')`
				)
				.bind(identity.coreId, identity.userId, identity.refId)
				.run()
		},

		async upsertProfile(profile) {
			await db
				.prepare(
					`INSERT INTO corepass_profiles
					(user_id, core_id, o18y, o21y, kyc, kyc_doc, provided_till, created_at, updated_at)
					VALUES
					(?1, ?2, ?3, ?4, ?5, ?6, ?7, strftime('%s','now'), strftime('%s','now'))
					ON CONFLICT(user_id) DO UPDATE SET
						core_id = excluded.core_id,
						o18y = excluded.o18y,
						o21y = excluded.o21y,
						kyc = excluded.kyc,
						kyc_doc = excluded.kyc_doc,
						provided_till = excluded.provided_till,
						updated_at = strftime('%s','now')`
				)
				.bind(
					profile.userId,
					profile.coreId,
					boolToDb(profile.o18y),
					boolToDb(profile.o21y),
					boolToDb(profile.kyc),
					profile.kycDoc,
					profile.providedTill
				)
				.run()
		},
	}
}

// -----------------------------
// Postgres (node-postgres / any SQL client)
// -----------------------------

export type PgLike = {
	query: (text: string, params?: unknown[]) => Promise<{ rows: any[] }>
}

export function postgresCorePassStore(pg: PgLike): CorePassStore {
	return {
		async createPendingRegistration(reg) {
			await pg.query(
				`INSERT INTO corepass_pending_registrations
				(token, credential_id, credential_public_key, counter, credential_device_type, credential_backed_up, transports, email, ref_id, aaguid, created_at, expires_at)
				VALUES
				($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
				[
					reg.token,
					reg.credentialId,
					reg.credentialPublicKey,
					reg.counter,
					reg.credentialDeviceType,
					reg.credentialBackedUp,
					reg.transports,
					reg.email,
					reg.refId,
					reg.aaguid,
					reg.createdAt,
					reg.expiresAt,
				]
			)
		},

		async getPendingRegistrationByCredentialId(credentialId) {
			const res = await pg.query(
				`SELECT token, credential_id, credential_public_key, counter, credential_device_type, credential_backed_up, transports, email, ref_id, aaguid, created_at, expires_at
				FROM corepass_pending_registrations
				WHERE credential_id = $1`,
				[credentialId]
			)
			const row = res.rows[0]
			if (!row) return null
			return {
				token: row.token,
				credentialId: row.credential_id,
				credentialPublicKey: row.credential_public_key,
				counter: Number(row.counter ?? 0),
				credentialDeviceType: row.credential_device_type,
				credentialBackedUp: Boolean(row.credential_backed_up),
				transports: row.transports ?? null,
				email: row.email ?? null,
				refId: row.ref_id ?? null,
				aaguid: row.aaguid ?? null,
				createdAt: Number(row.created_at ?? nowSec()),
				expiresAt: Number(row.expires_at ?? nowSec()),
			} satisfies CorePassPendingRegistration
		},

		async deletePendingRegistrationByToken(token) {
			await pg.query(`DELETE FROM corepass_pending_registrations WHERE token = $1`, [token])
		},

		async getIdentityByCoreId(coreId) {
			const res = await pg.query(
				`SELECT core_id, user_id, ref_id FROM corepass_identities WHERE core_id = $1`,
				[coreId]
			)
			const row = res.rows[0]
			if (!row) return null
			return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id ?? null } satisfies CorePassUserIdentity
		},

		async getIdentityByUserId(userId) {
			const res = await pg.query(
				`SELECT core_id, user_id, ref_id FROM corepass_identities WHERE user_id = $1`,
				[userId]
			)
			const row = res.rows[0]
			if (!row) return null
			return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id ?? null } satisfies CorePassUserIdentity
		},

		async upsertIdentity(identity) {
			await pg.query(
				`INSERT INTO corepass_identities (core_id, user_id, ref_id, created_at, updated_at)
				VALUES ($1,$2,$3, EXTRACT(EPOCH FROM NOW())::BIGINT, EXTRACT(EPOCH FROM NOW())::BIGINT)
				ON CONFLICT (core_id) DO UPDATE SET
					user_id = EXCLUDED.user_id,
					ref_id = COALESCE(corepass_identities.ref_id, EXCLUDED.ref_id),
					updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT`,
				[identity.coreId, identity.userId, identity.refId]
			)
		},

		async upsertProfile(profile) {
			await pg.query(
				`INSERT INTO corepass_profiles (user_id, core_id, o18y, o21y, kyc, kyc_doc, provided_till, created_at, updated_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7, EXTRACT(EPOCH FROM NOW())::BIGINT, EXTRACT(EPOCH FROM NOW())::BIGINT)
				ON CONFLICT (user_id) DO UPDATE SET
					core_id = EXCLUDED.core_id,
					o18y = EXCLUDED.o18y,
					o21y = EXCLUDED.o21y,
					kyc = EXCLUDED.kyc,
					kyc_doc = EXCLUDED.kyc_doc,
					provided_till = EXCLUDED.provided_till,
					updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT`,
				[
					profile.userId,
					profile.coreId,
					profile.o18y,
					profile.o21y,
					profile.kyc,
					profile.kycDoc,
					profile.providedTill,
				]
			)
		},
	}
}

// -----------------------------
// Supabase (Postgres)
// -----------------------------

export type SupabaseLike = {
	from: (table: string) => any
}

export function supabaseCorePassStore(supabase: SupabaseLike): CorePassStore {
	const tablePending = "corepass_pending_registrations"
	const tableIdentities = "corepass_identities"
	const tableProfiles = "corepass_profiles"

	const maybeSingle = async (q: any) => {
		if (typeof q.maybeSingle === "function") return await q.maybeSingle()
		return await q.single()
	}

	return {
		async createPendingRegistration(reg) {
			await supabase.from(tablePending).insert({
				token: reg.token,
				credential_id: reg.credentialId,
				credential_public_key: reg.credentialPublicKey,
				counter: reg.counter,
				credential_device_type: reg.credentialDeviceType,
				credential_backed_up: reg.credentialBackedUp,
				transports: reg.transports,
				email: reg.email,
				ref_id: reg.refId,
				aaguid: reg.aaguid,
				created_at: reg.createdAt,
				expires_at: reg.expiresAt,
			})
		},

		async getPendingRegistrationByCredentialId(credentialId) {
			const res = await maybeSingle(
				supabase
					.from(tablePending)
					.select(
						"token, credential_id, credential_public_key, counter, credential_device_type, credential_backed_up, transports, email, ref_id, aaguid, created_at, expires_at"
					)
					.eq("credential_id", credentialId)
			)
			const row = (res?.data ?? null) as any
			if (!row) return null
			return {
				token: row.token,
				credentialId: row.credential_id,
				credentialPublicKey: row.credential_public_key,
				counter: Number(row.counter ?? 0),
				credentialDeviceType: row.credential_device_type,
				credentialBackedUp: Boolean(row.credential_backed_up),
				transports: row.transports ?? null,
				email: row.email ?? null,
				refId: row.ref_id ?? null,
				aaguid: row.aaguid ?? null,
				createdAt: Number(row.created_at ?? nowSec()),
				expiresAt: Number(row.expires_at ?? nowSec()),
			} satisfies CorePassPendingRegistration
		},

		async deletePendingRegistrationByToken(token) {
			await supabase.from(tablePending).delete().eq("token", token)
		},

		async getIdentityByCoreId(coreId) {
			const res = await maybeSingle(
				supabase.from(tableIdentities).select("core_id, user_id, ref_id").eq("core_id", coreId)
			)
			const row = (res?.data ?? null) as any
			if (!row) return null
			return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id ?? null } satisfies CorePassUserIdentity
		},

		async getIdentityByUserId(userId) {
			const res = await maybeSingle(
				supabase.from(tableIdentities).select("core_id, user_id, ref_id").eq("user_id", userId)
			)
			const row = (res?.data ?? null) as any
			if (!row) return null
			return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id ?? null } satisfies CorePassUserIdentity
		},

		async upsertIdentity(identity) {
			await supabase
				.from(tableIdentities)
				.upsert(
					{
						core_id: identity.coreId,
						user_id: identity.userId,
						ref_id: identity.refId,
						updated_at: nowSec(),
					},
					{ onConflict: "core_id" }
				)
		},

		async upsertProfile(profile) {
			await supabase
				.from(tableProfiles)
				.upsert(
					{
						user_id: profile.userId,
						core_id: profile.coreId,
						o18y: profile.o18y,
						o21y: profile.o21y,
						kyc: profile.kyc,
						kyc_doc: profile.kycDoc,
						provided_till: profile.providedTill,
						updated_at: nowSec(),
					},
					{ onConflict: "user_id" }
				)
		},
	}
}
