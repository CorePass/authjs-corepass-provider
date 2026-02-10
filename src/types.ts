import type { Adapter } from "@auth/core/adapters"

export type CorePassTxContext = { tx?: unknown }

export type CorePassTx = {
	withTransaction?<T>(fn: (ctx: CorePassTxContext) => Promise<T>): Promise<T>
}

export type CorePassUserIdentity = {
	coreId: string
	userId: string
	refId: string | null
}

export type CorePassProfile = {
	userId: string
	coreId: string
	o18y?: boolean | null
	o21y?: boolean | null
	kyc?: boolean | null
	kycDoc?: string | null
	providedTill?: number | null
}

export type CorePassStore = {
	upsertIdentity(identity: { coreId: string; userId: string; refId?: string | null }, ctx?: CorePassTxContext): Promise<void>
	getIdentityByCoreId(params: { coreId: string }, ctx?: CorePassTxContext): Promise<CorePassUserIdentity | null>
	getIdentityByUserId?(params: { userId: string }, ctx?: CorePassTxContext): Promise<CorePassUserIdentity | null>
	upsertProfile(
		profile: {
			userId: string
			coreId: string
			o18y?: boolean | null
			o21y?: boolean | null
			kyc?: boolean | null
			kycDoc?: string | null
			providedTill?: number | null
		},
		ctx?: CorePassTxContext
	): Promise<void>
	getProfile?(params: { userId: string }, ctx?: CorePassTxContext): Promise<CorePassProfile | null>
	setPending?(
		params: { key: string; payload: unknown; expiresAt: Date },
		ctx?: CorePassTxContext
	): Promise<void>
	consumePending?(params: { key: string }, ctx?: CorePassTxContext): Promise<unknown | null>
}

export type CorePassAdapter = Adapter & CorePassStore & CorePassTx
