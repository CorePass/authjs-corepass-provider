import type { CorePassAdapter } from "../types.js"
import type { CorePassTxContext } from "../types.js"
import type { PendingBackend } from "./types.js"

export function pendingDbCorePass(adapter: CorePassAdapter): PendingBackend {
	if (typeof adapter.setPending !== "function" || typeof adapter.consumePending !== "function") {
		throw new Error(
			"pendingDbCorePass: adapter must implement setPending and consumePending. Use an adapter that supports CorePass pending table or use pending.strategy cookie / VerificationToken fallback."
		)
	}
	return {
		async set(key, payload, expiresAt, ctx) {
			await adapter.setPending!({ key, payload, expiresAt }, ctx)
		},
		async consume(key, ctx) {
			return await adapter.consumePending!({ key }, ctx)
		},
	}
}
