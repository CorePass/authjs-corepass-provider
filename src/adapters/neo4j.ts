import type { CorePassStore, CorePassTx } from "../types.js"

/**
 * Minimal Neo4j driver-like session. Use with neo4j-driver: session.run(cypher, params).
 * @see https://authjs.dev/getting-started/database — Neo4j
 */
export type Neo4jLike = {
	run: (cypher: string, params?: Record<string, unknown>) => Promise<{
		records: { get: (key: string) => unknown }[]
	}>
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

/**
 * CorePass store + pending for Neo4j. Uses nodes: CorePassPending (key, payload_json, expires_at),
 * CorePassIdentity (core_id, user_id, ref_id), CorePassProfile (user_id, core_id, o18y, o21y, kyc, kyc_doc, provided_till).
 * Merge with your Auth.js Neo4j adapter: adapter = { ...authAdapter, ...corepassNeo4jAdapter(session) }
 */
export function corepassNeo4jAdapter(session: Neo4jLike): CorePassStore & CorePassTx {
	return {
		async setPending(params, _ctx) {
			const expiresAtSec = Math.floor(params.expiresAt.getTime() / 1000)
			await session.run(
				`MERGE (p:CorePassPending { key: $key })
				 SET p.payload_json = $payload, p.expires_at = $expires_at, p.created_at = $created_at`,
				{
					key: params.key,
					payload: JSON.stringify(params.payload),
					expires_at: expiresAtSec,
					created_at: nowSec(),
				}
			)
		},

		async consumePending(params, _ctx) {
			const res = await session.run(
				`MATCH (p:CorePassPending { key: $key }) WITH p, p.payload_json AS payload_json DELETE p RETURN payload_json`,
				{ key: params.key }
			)
			const rec = res.records[0]
			if (!rec) return null
			const payload = rec.get("payload_json") as string | undefined
			if (!payload) return null
			try {
				return JSON.parse(payload) as unknown
			} catch {
				return null
			}
		},

		async getIdentityByCoreId(params, _ctx) {
			const res = await session.run(
				`MATCH (i:CorePassIdentity { core_id: $coreId }) RETURN i.core_id AS core_id, i.user_id AS user_id, i.ref_id AS ref_id`,
				{ coreId: params.coreId }
			)
			const rec = res.records[0]
			if (!rec) return null
			const core_id = rec.get("core_id") as string
			const user_id = rec.get("user_id") as string
			const ref_id = rec.get("ref_id") as string | null
			return { coreId: core_id, userId: user_id, refId: ref_id ?? null }
		},

		async getIdentityByUserId(params, _ctx) {
			const res = await session.run(
				`MATCH (i:CorePassIdentity { user_id: $userId }) RETURN i.core_id AS core_id, i.user_id AS user_id, i.ref_id AS ref_id`,
				{ userId: params.userId }
			)
			const rec = res.records[0]
			if (!rec) return null
			const core_id = rec.get("core_id") as string
			const user_id = rec.get("user_id") as string
			const ref_id = rec.get("ref_id") as string | null
			return { coreId: core_id, userId: user_id, refId: ref_id ?? null }
		},

		async upsertIdentity(identity, _ctx) {
			await session.run(
				`MERGE (i:CorePassIdentity { core_id: $coreId })
				 SET i.user_id = $userId, i.ref_id = $refId, i.updated_at = $now`,
				{
					coreId: identity.coreId,
					userId: identity.userId,
					refId: identity.refId ?? null,
					now: nowSec(),
				}
			)
		},

		async upsertProfile(profile, _ctx) {
			await session.run(
				`MERGE (p:CorePassProfile { user_id: $userId })
				 SET p.core_id = $coreId, p.o18y = $o18y, p.o21y = $o21y, p.kyc = $kyc, p.kyc_doc = $kycDoc, p.provided_till = $provided_till, p.updated_at = $now`,
				{
					userId: profile.userId,
					coreId: profile.coreId,
					o18y: boolToDb(profile.o18y),
					o21y: boolToDb(profile.o21y),
					kyc: boolToDb(profile.kyc),
					kycDoc: profile.kycDoc ?? null,
					provided_till: profile.providedTill ?? null,
					now: nowSec(),
				}
			)
		},

		async getProfile(params, _ctx) {
			const res = await session.run(
				`MATCH (p:CorePassProfile { user_id: $userId })
				 RETURN p.user_id AS user_id, p.core_id AS core_id, p.o18y AS o18y, p.o21y AS o21y, p.kyc AS kyc, p.kyc_doc AS kyc_doc, p.provided_till AS provided_till`,
				{ userId: params.userId }
			)
			const rec = res.records[0]
			if (!rec) return null
			return {
				userId: rec.get("user_id") as string,
				coreId: rec.get("core_id") as string,
				o18y: boolFromDb(rec.get("o18y")),
				o21y: boolFromDb(rec.get("o21y")),
				kyc: boolFromDb(rec.get("kyc")),
				kycDoc: (rec.get("kyc_doc") as string | null) ?? null,
				providedTill: (rec.get("provided_till") as number | null) ?? null,
			}
		},
	}
}
