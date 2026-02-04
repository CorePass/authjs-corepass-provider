export function parseCookies(header: string | null): Record<string, string> {
    const out: Record<string, string> = {}
    if (!header) return out
    for (const part of header.split(";")) {
        const [k, ...rest] = part.trim().split("=")
        if (!k) continue
        out[k] = decodeURIComponent(rest.join("=") || "")
    }
    return out
}

export type CookieOptions = {
    httpOnly?: boolean
    secure?: boolean
    sameSite?: "Lax" | "Strict" | "None"
    path?: string
    maxAge?: number
}

export function serializeCookie(name: string, value: string, options: CookieOptions = {}): string {
    const attrs: string[] = [`${name}=${encodeURIComponent(value)}`]
    if (options.maxAge !== undefined) attrs.push(`Max-Age=${Math.floor(options.maxAge)}`)
    attrs.push(`Path=${options.path ?? "/"}`)
    if (options.httpOnly !== false) attrs.push("HttpOnly")
    if (options.secure !== false) attrs.push("Secure")
    if (options.sameSite) attrs.push(`SameSite=${options.sameSite}`)
    return attrs.join("; ")
}

