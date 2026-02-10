/**
 * Framework-agnostic cookie helpers. Accept headers as Record<string, string | string[] | undefined>
 * or similar (getCookie reads single string; setCookieHeader/deleteCookieHeader return header value).
 */

export function getCookie(headers: Record<string, string | string[] | undefined>, name: string): string | undefined {
	const raw = headers["cookie"] ?? headers["Cookie"]
	if (typeof raw !== "string") return undefined
	for (const part of raw.split(";")) {
		const [k, ...rest] = part.trim().split("=")
		if (k?.trim() === name) return decodeURIComponent(rest.join("=").trim() || "")
	}
	return undefined
}

export type SetCookieOptions = {
	maxAge?: number
	path?: string
	httpOnly?: boolean
	secure?: boolean
	sameSite?: "Lax" | "Strict" | "None"
}

export function setCookieHeader(name: string, value: string, opts: SetCookieOptions = {}): string {
	const attrs: string[] = [`${name}=${encodeURIComponent(value)}`]
	if (opts.maxAge !== undefined) attrs.push(`Max-Age=${Math.floor(opts.maxAge)}`)
	attrs.push(`Path=${opts.path ?? "/"}`)
	attrs.push(`HttpOnly`)
	attrs.push(`Secure`)
	if (opts.sameSite) attrs.push(`SameSite=${opts.sameSite}`)
	return attrs.join("; ")
}

export function deleteCookieHeader(name: string, path = "/"): string {
	return `${name}=; Path=${path}; Max-Age=0; HttpOnly; Secure`
}
