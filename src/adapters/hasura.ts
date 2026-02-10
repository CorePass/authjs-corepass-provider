import type { CorePassStore, CorePassTx } from "../types.js"

/**
 * Minimal Hasura-like client (GraphQL request). Use with graphql-request or fetch to Hasura.
 * @see https://authjs.dev/getting-started/database — Hasura
 */
export type HasuraLike = {
	request: (query: string, variables?: Record<string, unknown>) => Promise<{ data?: unknown; errors?: unknown[] }>
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

export type CorePassHasuraAdapterOptions = {
	client: HasuraLike
	/** Table names if different from default (corepass_pending, corepass_identities, corepass_profiles). */
	pendingTable?: string
	identitiesTable?: string
	profilesTable?: string
}

/**
 * CorePass store + pending for Hasura (Postgres-backed GraphQL). Expects tables corepass_pending, corepass_identities, corepass_profiles.
 * Merge with your Auth.js Hasura adapter: adapter = { ...authAdapter, ...corepassHasuraAdapter({ client }) }
 */
export function corepassHasuraAdapter(opts: CorePassHasuraAdapterOptions): CorePassStore & CorePassTx {
	const { client } = opts
	const pendingTable = opts.pendingTable ?? "corepass_pending"
	const identitiesTable = opts.identitiesTable ?? "corepass_identities"
	const profilesTable = opts.profilesTable ?? "corepass_profiles"

	async function runMutation(mutation: string, variables: Record<string, unknown>): Promise<void> {
		const res = await client.request(mutation, variables)
		if (res.errors?.length) throw new Error(String(res.errors[0]))
	}

	async function runQuery<T>(query: string, variables: Record<string, unknown>): Promise<T[]> {
		const res = await client.request(query, variables)
		if (res.errors?.length) throw new Error(String(res.errors[0]))
		const data = res.data as Record<string, unknown> | undefined
		if (!data) return []
		const key = Object.keys(data)[0] as string
		const arr = data[key] as unknown[]
		return (Array.isArray(arr) ? arr : []) as T[]
	}

	return {
		async setPending(params, _ctx) {
			const expiresAtSec = Math.floor(params.expiresAt.getTime() / 1000)
			await runMutation(
				`mutation($key: String!, $payload_json: String!, $expires_at: Int!, $created_at: Int!) {
					insert_${pendingTable}_one(object: { key: $key, payload_json: $payload_json, expires_at: $expires_at, created_at: $created_at }, on_conflict: { constraint: corepass_pending_key_key, update_columns: [payload_json, expires_at] }) { key }
				}`,
				{
					key: params.key,
					payload_json: JSON.stringify(params.payload),
					expires_at: expiresAtSec,
					created_at: nowSec(),
				}
			)
		},

		async consumePending(params, _ctx) {
			const res = await client.request(
				`mutation($key: String!) {
					delete_${pendingTable}(where: { key: { _eq: $key } }) { returning { payload_json } }
				}`,
				{ key: params.key }
			)
			if (res.errors?.length) throw new Error(String(res.errors[0]))
			const data = res.data as Record<string, { returning: { payload_json: string }[] }> | undefined
			const returning = data?.[`delete_${pendingTable}`]?.returning
			const payload = Array.isArray(returning) && returning[0] ? returning[0].payload_json : null
			if (!payload) return null
			try {
				return JSON.parse(payload) as unknown
			} catch {
				return null
			}
		},

		async getIdentityByCoreId(params, _ctx) {
			const rows = await runQuery<{ core_id: string; user_id: string; ref_id: string | null }>(
				`query($coreId: String!) { ${identitiesTable}(where: { core_id: { _eq: $coreId } }) { core_id user_id ref_id } }`,
				{ coreId: params.coreId }
			)
			const row = rows[0]
			if (!row) return null
			return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id ?? null }
		},

		async getIdentityByUserId(params, _ctx) {
			const rows = await runQuery<{ core_id: string; user_id: string; ref_id: string | null }>(
				`query($userId: String!) { ${identitiesTable}(where: { user_id: { _eq: $userId } }) { core_id user_id ref_id } }`,
				{ userId: params.userId }
			)
			const row = rows[0]
			if (!row) return null
			return { coreId: row.core_id, userId: row.user_id, refId: row.ref_id ?? null }
		},

		async upsertIdentity(identity, _ctx) {
			await runMutation(
				`mutation($coreId: String!, $user_id: String!, $ref_id: String, $now: Int!) {
					insert_${identitiesTable}_one(object: { core_id: $coreId, user_id: $user_id, ref_id: $ref_id, created_at: $now, updated_at: $now }, on_conflict: { constraint: corepass_identities_core_id_key, update_columns: [user_id, ref_id, updated_at] }) { core_id }
				}`,
				{
					coreId: identity.coreId,
					user_id: identity.userId,
					ref_id: identity.refId ?? null,
					now: nowSec(),
				}
			)
		},

		async upsertProfile(profile, _ctx) {
			await runMutation(
				`mutation($userId: String!, $core_id: String!, $o18y: Int, $o21y: Int, $kyc: Int, $kyc_doc: String, $provided_till: Int, $now: Int!) {
					insert_${profilesTable}_one(object: { user_id: $userId, core_id: $core_id, o18y: $o18y, o21y: $o21y, kyc: $kyc, kyc_doc: $kyc_doc, provided_till: $provided_till, created_at: $now, updated_at: $now }, on_conflict: { constraint: corepass_profiles_user_id_key, update_columns: [core_id, o18y, o21y, kyc, kyc_doc, provided_till, updated_at] }) { user_id }
				}`,
				{
					userId: profile.userId,
					core_id: profile.coreId,
					o18y: boolToDb(profile.o18y),
					o21y: boolToDb(profile.o21y),
					kyc: boolToDb(profile.kyc),
					kyc_doc: profile.kycDoc ?? null,
					provided_till: profile.providedTill ?? null,
					now: nowSec(),
				}
			)
		},

		async getProfile(params, _ctx) {
			const rows = await runQuery<{
				user_id: string
				core_id: string
				o18y: unknown
				o21y: unknown
				kyc: unknown
				kyc_doc: string | null
				provided_till: number | null
			}>(`query($userId: String!) { ${profilesTable}(where: { user_id: { _eq: $userId } }) { user_id core_id o18y o21y kyc kyc_doc provided_till } }`, {
				userId: params.userId,
			})
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
