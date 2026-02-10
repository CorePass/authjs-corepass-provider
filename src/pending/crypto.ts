import { base64UrlToBytes, bytesToBase64Url } from "../server/base64.js"

const ALG = "AES-GCM"
const KEY_LEN = 256
const IV_LEN = 12
const TAG_LEN = 16

async function deriveKey(secret: string): Promise<CryptoKey> {
	const data = new TextEncoder().encode(secret)
	const hash = await crypto.subtle.digest("SHA-256", data)
	return crypto.subtle.importKey("raw", hash, { name: ALG, length: KEY_LEN }, false, ["encrypt", "decrypt"])
}

/**
 * Encrypt and authenticate data as base64url(iv | ciphertext_with_tag).
 * Uses AES-256-GCM with random IV. Key derived from secret via SHA-256.
 */
export async function encryptJson(secret: string, data: unknown): Promise<string> {
	const key = await deriveKey(secret)
	const iv = crypto.getRandomValues(new Uint8Array(IV_LEN))
	const plain = new TextEncoder().encode(JSON.stringify(data))
	const cipher = await crypto.subtle.encrypt(
		{ name: ALG, iv, tagLength: TAG_LEN * 8 },
		key,
		plain
	)
	const combined = new Uint8Array(iv.length + cipher.byteLength)
	combined.set(iv, 0)
	combined.set(new Uint8Array(cipher), iv.length)
	return bytesToBase64Url(combined)
}

/**
 * Decrypt and verify. Throws on invalid or tampered payload.
 */
export async function decryptJson(secret: string, token: string): Promise<unknown> {
	const key = await deriveKey(secret)
	const combined = base64UrlToBytes(token)
	if (combined.length < IV_LEN + TAG_LEN) throw new Error("Invalid token length")
	const iv = combined.slice(0, IV_LEN)
	const cipher = combined.slice(IV_LEN)
	const plain = await crypto.subtle.decrypt(
		{ name: ALG, iv, tagLength: TAG_LEN * 8 },
		key,
		cipher
	)
	return JSON.parse(new TextDecoder().decode(plain))
}
