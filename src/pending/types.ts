import type { CorePassTxContext } from "../types.js"

export type PendingSetResult = void | { pendingToken: string }

export interface PendingBackend {
	set(key: string, payload: unknown, expiresAt: Date, ctx?: CorePassTxContext): Promise<PendingSetResult>
	consume(key: string, ctx?: CorePassTxContext): Promise<unknown | null>
}

export interface PendingBackendWithToken extends PendingBackend {
	consumeWithToken(key: string, token: string, ctx?: CorePassTxContext): Promise<unknown | null>
}

export function isPendingBackendWithToken(b: PendingBackend): b is PendingBackendWithToken {
	return typeof (b as PendingBackendWithToken).consumeWithToken === "function"
}
