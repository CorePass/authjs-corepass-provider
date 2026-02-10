export type TimeConfigInput = {
	flowLifetimeSeconds?: number
	registrationTimeoutMs?: number
	timestampWindowMs?: number
}

export type ResolvedTimeConfig = {
	flowLifetimeSeconds: number
	registrationTimeoutMs: number
	timestampWindowMs: number
	flowExpiresInMs: number
}

export function resolveTimeConfig(input?: TimeConfigInput): ResolvedTimeConfig {
	const flowLifetimeSeconds = input?.flowLifetimeSeconds ?? 600
	if (flowLifetimeSeconds <= 0) {
		throw new Error("flowLifetimeSeconds must be > 0")
	}
	const flowExpiresInMs = flowLifetimeSeconds * 1000

	let registrationTimeoutMs = input?.registrationTimeoutMs ?? 60_000
	registrationTimeoutMs = Math.min(registrationTimeoutMs, flowExpiresInMs)
	if (registrationTimeoutMs <= 0) {
		throw new Error("registrationTimeoutMs must be > 0")
	}

	let timestampWindowMs = input?.timestampWindowMs ?? flowExpiresInMs
	timestampWindowMs = Math.max(timestampWindowMs, registrationTimeoutMs)
	timestampWindowMs = Math.min(timestampWindowMs, flowExpiresInMs)

	return {
		flowLifetimeSeconds,
		registrationTimeoutMs,
		timestampWindowMs,
		flowExpiresInMs,
	}
}
