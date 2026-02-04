function hasAtobBtoa(): boolean {
	return typeof globalThis.atob === "function" && typeof globalThis.btoa === "function"
}

function bytesToBinaryString(bytes: Uint8Array): string {
	let s = ""
	for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!)
	return s
}

function binaryStringToBytes(bin: string): Uint8Array {
	const bytes = new Uint8Array(bin.length)
	for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
	return bytes
}

export function bytesToBase64(bytes: Uint8Array): string {
	if (hasAtobBtoa()) {
		return globalThis.btoa(bytesToBinaryString(bytes))
	}
	return Buffer.from(bytes).toString("base64")
}

export function base64ToBytes(base64: string): Uint8Array {
	if (hasAtobBtoa()) {
		return binaryStringToBytes(globalThis.atob(base64))
	}
	return new Uint8Array(Buffer.from(base64, "base64"))
}

export function bytesToBase64Url(bytes: Uint8Array): string {
	return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "")
}

export function base64UrlToBytes(base64url: string): Uint8Array {
	const pad = "=".repeat((4 - (base64url.length % 4)) % 4)
	const base64 = (base64url + pad).replace(/-/g, "+").replace(/_/g, "/")
	return base64ToBytes(base64)
}

export function tryDecodeBase64OrBase64Url(input: string): Uint8Array | null {
	try {
		if (!input || typeof input !== "string") return null
		const s = input.trim()
		if (!s) return null

		if (/^[0-9A-Za-z+/]+=*$/.test(s) && s.length % 4 === 0) {
			return base64ToBytes(s)
		}
		if (/^[0-9A-Za-z_-]+$/.test(s)) {
			return base64UrlToBytes(s)
		}
		return null
	} catch {
		return null
	}
}

export function normalizeCredentialId(id: string): {
	bytes: Uint8Array
	base64: string
	base64url: string
} | null {
	const bytes = tryDecodeBase64OrBase64Url(id)
	if (!bytes) return null
	return { bytes, base64: bytesToBase64(bytes), base64url: bytesToBase64Url(bytes) }
}
