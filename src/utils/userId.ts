import { base64ToBytes, bytesToBase64 } from "../server/base64.js"

export type UserIdResolution = {
	userIdBytes: Uint8Array
	userIdStringB64UrlPad: string
	byteLength: 32 | 64
}

const ALLOWED_B64_CHARS = /^[A-Za-z0-9\-_+/=]+$/

/**
 * Normalize base64/base64url input to standard base64 for decoding.
 * Trims, validates allowed chars, converts url-safe to standard, adds padding.
 */
export function normalizeBase64Input(s: string): string {
	const t = s.trim()
	if (!t) return t
	if (!ALLOWED_B64_CHARS.test(t) || /\s/.test(t)) {
		throw new Error("Invalid userId: invalid characters")
	}
	const standard = t.replace(/-/g, "+").replace(/_/g, "/")
	const padLen = (4 - (standard.length % 4)) % 4
	return standard + "=".repeat(padLen)
}

/**
 * Decode base64 string to bytes (after normalizing with normalizeBase64Input).
 */
export function decodeBase64ToBytes(b64: string): Uint8Array {
	return base64ToBytes(b64)
}

/**
 * Encode bytes to base64url WITH padding (canonical form for 32 => 44 chars, 64 => 88 chars).
 */
export function bytesToBase64UrlPad(bytes: Uint8Array): string {
	const b64 = bytesToBase64(bytes)
	return b64.replace(/\+/g, "-").replace(/\//g, "_")
}

/**
 * Validate byte length is 32 or 64 and passes simple strength checks.
 * @throws Error if invalid
 */
export function validateUserIdBytes(bytes: Uint8Array): asserts bytes is Uint8Array & { length: 32 | 64 } {
	const len = bytes.length
	if (len !== 32 && len !== 64) {
		throw new Error("Invalid userId: must decode to 32 or 64 bytes")
	}
	const hist = new Map<number, number>()
	for (let i = 0; i < len; i++) {
		const b = bytes[i]!
		hist.set(b, (hist.get(b) ?? 0) + 1)
	}
	const counts = [...hist.values()]
	const maxFreq = Math.max(...counts)
	const uniqueCount = hist.size
	if (maxFreq === len) {
		throw new Error("Invalid userId: all bytes identical")
	}
	if (uniqueCount < len / 2) {
		throw new Error("Invalid userId: too few unique bytes")
	}
	if (maxFreq > Math.floor(len * 0.6)) {
		throw new Error("Invalid userId: too repetitive")
	}
}

function randomBytes(n: number): Uint8Array {
	const a = new Uint8Array(n)
	crypto.getRandomValues(a)
	return a
}

/**
 * Resolve passkey userId from optional request input.
 * If undefined/empty => generate 32 random bytes.
 * If provided => normalize, decode, validate (32 or 64 bytes, strength checks), return canonical form.
 * @throws Error on invalid input (caller should return 400).
 */
export function resolvePasskeyUserId(input: string | undefined | null): UserIdResolution {
	if (input === undefined || input === null) {
		const bytes = randomBytes(32)
		const canonical = bytesToBase64UrlPad(bytes)
		if (canonical.length !== 44) throw new Error("Invalid userId: encoding length mismatch")
		return { userIdBytes: bytes, userIdStringB64UrlPad: canonical, byteLength: 32 }
	}
	const trimmed = input.trim()
	if (!trimmed) {
		const bytes = randomBytes(32)
		const canonical = bytesToBase64UrlPad(bytes)
		if (canonical.length !== 44) throw new Error("Invalid userId: encoding length mismatch")
		return { userIdBytes: bytes, userIdStringB64UrlPad: canonical, byteLength: 32 }
	}
	const normalized = normalizeBase64Input(trimmed)
	const bytes = decodeBase64ToBytes(normalized)
	validateUserIdBytes(bytes)
	const canonical = bytesToBase64UrlPad(bytes)
	const expectedLen = bytes.length === 32 ? 44 : 88
	if (canonical.length !== expectedLen) {
		throw new Error("Invalid userId: encoding length mismatch")
	}
	return {
		userIdBytes: bytes,
		userIdStringB64UrlPad: canonical,
		byteLength: bytes.length as 32 | 64,
	}
}
