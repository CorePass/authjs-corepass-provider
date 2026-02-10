import type { CorePassStore, CorePassTx, CorePassTxContext } from "../types.js"

/**
 * Minimal Prisma-like client (raw SQL). Use with PrismaClient: it has $executeRawUnsafe and $queryRawUnsafe.
 * Apply the CorePass schema (corepass_pending, corepass_identities, corepass_profiles) to your database.
 * @see https://authjs.dev/getting-started/database — Prisma
 */
export type PrismaLike = {
	$executeRawUnsafe: (query: string, ...values: unknown[]) => Promise<unknown>
	$queryRawUnsafe: <T = unknown>(query: string, ...values: unknown[]) => Promise<T>
	$transaction?: <T>(fn: (tx: PrismaLike) => Promise<T>) => Promise<T>
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

export type CorePassPrismaAdapterOptions = {
	client: PrismaLike
	schema?: string
}

/**
 * CorePass store + pending for Prisma (raw SQL). Use with @prisma/client.
 * Merge with your Auth.js Prisma adapter: adapter = { ...authAdapter, ...corepassPrismaAdapter({ client: prisma, schema }) }
 */
export function corepassPrismaAdapter(opts: CorePassPrismaAdapterOptions): CorePassStore & CorePassTx {
	const { client, schema } = opts
	const pre = schema ? `"${schema}".` : ""

	function run(clientOrTx: PrismaLike) {
		return {
			async setPending(params: { key: string; payload: unknown; expiresAt: Date }) {
				const expiresAtSec = Math.floor(params.expiresAt.getTime() / 1000)
				const payloadJson = JSON.stringify(params.payload)
				await clientOrTx.$executeRawUnsafe(
					`INSERT INTO ${pre}corepass_pending (key, payload_json, expires_at, created_at)
					 VALUES ($1, $2, $3, $4)
					 ON CONFLICT (key) DO UPDATE SET payload_json = EXCLUDED.payload_json, expires_at = EXCLUDED.expires_at`,
					params.key,
					payloadJson,
					expiresAtSec,
					nowSec()
				)
			},
			async consumePending(params: { key: string }) {
				const rows = await clientOrTx.$queryRawUnsafe<[{ payload_json: string }]>(
					`DELETE FROM ${pre}corepass_pending WHERE key = $1 RETURNING payload_json`,
					params.key
				)
				const row = rows[0]
				if (!row) return null
				try {
					return JSON.parse(row.payload_json) as unknown
				} catch {
					return null
				}
			},
			async getIdentityByCoreId(params: { coreId: string }) {
				const rows = await clientOrTx.$queryRawUnsafe<[{ core_id: string; user_id: string; ref_id: string | null }]>(
					`SELECT core_id, user_id, ref_id FROM ${pre}corepass_identities WHERE core_id = $1`,
					params.coreId
				)
				const row = rows[0]
				if (!row) return null
				return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id ?? null }
			},
			async getIdentityByUserId(params: { userId: string }) {
				const rows = await clientOrTx.$queryRawUnsafe<[{ core_id: string; user_id: string; ref_id: string | null }]>(
					`SELECT core_id, user_id, ref_id FROM ${pre}corepass_identities WHERE user_id = $1`,
					params.userId
				)
				const row = rows[0]
				if (!row) return null
				return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id ?? null }
			},
			async upsertIdentity(identity: { coreId: string; userId: string; refId?: string | null }) {
				const now = nowSec()
				await clientOrTx.$executeRawUnsafe(
					`INSERT INTO ${pre}corepass_identities (core_id, user_id, ref_id, created_at, updated_at)
					 VALUES ($1, $2, $3, $4, $4)
					 ON CONFLICT (core_id) DO UPDATE SET user_id = EXCLUDED.user_id,
					 ref_id = COALESCE(${pre}corepass_identities.ref_id, EXCLUDED.ref_id), updated_at = $4`,
					identity.coreId,
					identity.userId,
					identity.refId ?? null,
					now
				)
			},
			async upsertProfile(profile: {
				userId: string
				coreId: string
				o18y?: boolean | null
				o21y?: boolean | null
				kyc?: boolean | null
				kycDoc?: string | null
				providedTill?: number | null
			}) {
				const now = nowSec()
				await clientOrTx.$executeRawUnsafe(
					`INSERT INTO ${pre}corepass_profiles (user_id, core_id, o18y, o21y, kyc, kyc_doc, provided_till, created_at, updated_at)
					 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
					 ON CONFLICT (user_id) DO UPDATE SET core_id = EXCLUDED.core_id, o18y = EXCLUDED.o18y,
					 o21y = EXCLUDED.o21y, kyc = EXCLUDED.kyc, kyc_doc = EXCLUDED.kyc_doc,
					 provided_till = EXCLUDED.provided_till, updated_at = $8`,
					profile.userId,
					profile.coreId,
					boolToDb(profile.o18y),
					boolToDb(profile.o21y),
					boolToDb(profile.kyc),
					profile.kycDoc ?? null,
					profile.providedTill ?? null,
					now
				)
			},
			async getProfile(params: { userId: string }) {
				const rows = await clientOrTx.$queryRawUnsafe<[
					{ user_id: string; core_id: string; o18y: unknown; o21y: unknown; kyc: unknown; kyc_doc: string | null; provided_till: number | null }
				]>(
					`SELECT user_id, core_id, o18y, o21y, kyc, kyc_doc, provided_till FROM ${pre}corepass_profiles WHERE user_id = $1`,
					params.userId
				)
				const row = rows[0]
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
		}
	}

	const r = run(client)

	return {
		async setPending(params, ctx) {
			const tx = (ctx as { tx?: PrismaLike })?.tx
			await run(tx ?? client).setPending(params)
		},
		async consumePending(params, ctx) {
			const tx = (ctx as { tx?: PrismaLike })?.tx
			return run(tx ?? client).consumePending(params)
		},
		async getIdentityByCoreId(params, ctx) {
			const tx = (ctx as { tx?: PrismaLike })?.tx
			return run(tx ?? client).getIdentityByCoreId(params)
		},
		async getIdentityByUserId(params, ctx) {
			const tx = (ctx as { tx?: PrismaLike })?.tx
			return run(tx ?? client).getIdentityByUserId(params)
		},
		async upsertIdentity(identity, ctx) {
			const tx = (ctx as { tx?: PrismaLike })?.tx
			await run(tx ?? client).upsertIdentity(identity)
		},
		async upsertProfile(profile, ctx) {
			const tx = (ctx as { tx?: PrismaLike })?.tx
			await run(tx ?? client).upsertProfile(profile)
		},
		async getProfile(params, ctx) {
			const tx = (ctx as { tx?: PrismaLike })?.tx
			return run(tx ?? client).getProfile(params)
		},
		async withTransaction<T>(fn: (ctx: CorePassTxContext) => Promise<T>): Promise<T> {
			if (client.$transaction) {
				return client.$transaction((tx) => fn({ tx }) as Promise<T>)
			}
			return fn({}) as Promise<T>
		},
	}
}
