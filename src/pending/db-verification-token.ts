import type { Adapter } from "@auth/core/adapters"
import { encryptJson, decryptJson } from "./crypto.js"
import type { PendingBackendWithToken } from "./types.js"

const MAX_TOKEN_LENGTH = 2048
const PREFIX = "corepass:"

export function pendingDbVerificationToken(
	adapter: Adapter,
	opts: { secret: string }
): PendingBackendWithToken {
	const createVT = adapter.createVerificationToken
	const useVT = adapter.useVerificationToken
	if (typeof createVT !== "function" || typeof useVT !== "function") {
		throw new Error(
			"pendingDbVerificationToken: adapter must implement createVerificationToken and useVerificationToken (Auth.js VerificationToken methods). Use an adapter that supports verification tokens or use setPending/consumePending / cookie strategy."
		)
	}
	const secret = opts.secret
	return {
		async set(key, payload, expiresAt, _ctx) {
			const identifier = PREFIX + key
			const encrypted = await encryptJson(secret, payload)
			const token = encrypted
			if (token.length > MAX_TOKEN_LENGTH) {
				throw new Error(
					`pendingDbVerificationToken: encrypted token too long (${token.length} chars). Use adapter.setPending/consumePending (CorePass pending table) or pending.strategy cookie.`
				)
			}
			await createVT({
				identifier,
				token,
				expires: expiresAt,
			})
			return { pendingToken: token }
		},
		async consume(key, _ctx) {
			// Without token we cannot call useVerificationToken (Auth.js requires token to match).
			return null
		},
		async consumeWithToken(key, token, _ctx) {
			const identifier = PREFIX + key
			const used = await useVT({ identifier, token })
			if (!used) return null
			try {
				return await decryptJson(secret, token)
			} catch {
				return null
			}
		},
	}
}
