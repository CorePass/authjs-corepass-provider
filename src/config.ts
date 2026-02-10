export type PendingStrategy =
	| { strategy: "db" }
	| { strategy: "cookie"; cookieName?: string; maxAgeSeconds?: number }

export type FinalizeStrategy =
	| { strategy: "after" }
	| { strategy: "immediate"; maxAgeSeconds?: number }

export type ResolvedPending = { strategy: "db" } | { strategy: "cookie"; cookieName: string; maxAgeSeconds: number }
export type ResolvedFinalize = { strategy: "after" } | { strategy: "immediate"; maxAgeSeconds: number }

const DEFAULT_COOKIE_MAX_AGE = 120
const DEFAULT_PENDING_COOKIE_NAME = "__corepass_pending"

export type ResolvedConfig = {
	pending: ResolvedPending
	finalize: ResolvedFinalize
}

export function resolveConfig(input: {
	pending?: PendingStrategy
	finalize?: FinalizeStrategy
	cookieName?: string
}): ResolvedConfig {
	const finalize = input.finalize ?? { strategy: "after" }
	const finalizeImmediate = finalize.strategy === "immediate"
	const maxAgeFromFinalize = finalizeImmediate && "maxAgeSeconds" in finalize ? finalize.maxAgeSeconds : undefined

	let pending: ResolvedPending
	if (finalizeImmediate) {
		// Rule: finalize.immediate forces pending.cookie
		const cookieOpts = input.pending?.strategy === "cookie" ? input.pending : { strategy: "cookie" as const }
		const maxAgeSeconds = maxAgeFromFinalize ?? cookieOpts.maxAgeSeconds ?? DEFAULT_COOKIE_MAX_AGE
		pending = {
			strategy: "cookie",
			cookieName: input.cookieName ?? cookieOpts.cookieName ?? DEFAULT_PENDING_COOKIE_NAME,
			maxAgeSeconds,
		}
	} else if (input.pending?.strategy === "cookie") {
		pending = {
			strategy: "cookie",
			cookieName: input.cookieName ?? input.pending.cookieName ?? DEFAULT_PENDING_COOKIE_NAME,
			maxAgeSeconds: input.pending.maxAgeSeconds ?? DEFAULT_COOKIE_MAX_AGE,
		}
	} else {
		pending = { strategy: "db" }
	}

	const resolvedFinalize: ResolvedFinalize =
		finalize.strategy === "immediate"
			? { strategy: "immediate", maxAgeSeconds: pending.strategy === "cookie" ? pending.maxAgeSeconds : DEFAULT_COOKIE_MAX_AGE }
			: { strategy: "after" }

	return { pending, finalize: resolvedFinalize }
}
