import type { CorePassAdapter } from "../types.js"
import type { ResolvedPending } from "../config.js"
import type { ResolvedTimeConfig } from "../time.js"
import { pendingDbCorePass } from "./db-corepass.js"
import { pendingDbVerificationToken } from "./db-verification-token.js"
import { pendingCookie } from "./cookie.js"
import type { PendingBackend } from "./types.js"
import { isPendingBackendWithToken } from "./types.js"

export type { PendingBackend, PendingBackendWithToken } from "./types.js"
export { isPendingBackendWithToken } from "./types.js"
export type { CookieAccess } from "./cookie.js"

export type MakePendingBackendResult = {
	backend: PendingBackend
	mode: "db" | "cookie"
	requiresToken: boolean
}

export function makePendingBackend(params: {
	adapter: CorePassAdapter
	pendingConfig: ResolvedPending
	secret: string
	time?: ResolvedTimeConfig
}): MakePendingBackendResult {
	const { adapter, pendingConfig, secret, time } = params
	if (pendingConfig.strategy === "cookie") {
		const maxAgeSeconds = time?.flowLifetimeSeconds ?? pendingConfig.maxAgeSeconds
		const backend = pendingCookie({
			secret,
			cookieName: pendingConfig.cookieName,
			maxAgeSeconds,
		})
		return { backend, mode: "cookie", requiresToken: false }
	}
	// strategy === "db"
	if (typeof adapter.setPending === "function" && typeof adapter.consumePending === "function") {
		const backend = pendingDbCorePass(adapter)
		return { backend, mode: "db", requiresToken: false }
	}
	if (typeof adapter.createVerificationToken === "function" && typeof adapter.useVerificationToken === "function") {
		const backend = pendingDbVerificationToken(adapter, { secret })
		return { backend, mode: "db", requiresToken: true }
	}
	throw new Error(
		"CorePass pending.strategy is 'db' but adapter has neither setPending/consumePending nor createVerificationToken/useVerificationToken. Implement setPending/consumePending on your adapter, use an Auth.js adapter that supports verification tokens, or set pending.strategy to 'cookie'."
	)
}
