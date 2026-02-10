import type { CorePassTxContext } from "../types.js"
import { encryptJson, decryptJson } from "./crypto.js"
import type { PendingBackend } from "./types.js"

export type CookieAccess = {
	getCookie(name: string): string | undefined
	setCookieHeader(name: string, value: string, opts?: { maxAge: number; path?: string }): void
	deleteCookieHeader(name: string): void
}

type CookiePayload = { k: string; p: unknown; exp: number }

export function pendingCookie(opts: {
	secret: string
	cookieName: string
	maxAgeSeconds: number
}): PendingBackend {
	const { secret, cookieName, maxAgeSeconds } = opts
	return {
		async set(key, payload, expiresAt, ctx) {
			const access = (ctx as { cookieAccess?: CookieAccess })?.cookieAccess
			if (!access) throw new Error("pendingCookie.set: ctx.cookieAccess is required")
			const value = await encryptJson(secret, { k: key, p: payload, exp: expiresAt.getTime() } as CookiePayload)
			access.setCookieHeader(cookieName, value, { maxAge: maxAgeSeconds, path: "/" })
		},
		async consume(key, ctx) {
			const access = (ctx as { cookieAccess?: CookieAccess })?.cookieAccess
			if (!access) return null
			const raw = access.getCookie(cookieName)
			if (!raw) return null
			try {
				const decoded = (await decryptJson(secret, raw)) as CookiePayload
				if (decoded.k !== key || typeof decoded.exp !== "number") return null
				if (Date.now() > decoded.exp) return null
				access.deleteCookieHeader(cookieName)
				return decoded.p
			} catch {
				return null
			}
		},
	}
}
