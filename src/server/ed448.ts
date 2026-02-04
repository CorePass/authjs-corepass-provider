import { ed448 } from "@noble/curves/ed448.js"
import { tryDecodeBase64OrBase64Url } from "./base64.js"

function isHex(s: string): boolean {
	return /^[0-9a-fA-F]+$/.test(s)
}

function hexToBytes(hex: string): Uint8Array | null {
	if (!hex || (hex.length % 2) !== 0) return null
	if (!isHex(hex)) return null
	const bytes = new Uint8Array(hex.length / 2)
	for (let i = 0; i < hex.length; i += 2) {
		bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16)
	}
	return bytes
}

export function parseEd448Signature(signature: string): Uint8Array | null {
	if (typeof signature !== "string") return null
	const s = signature.trim()
	if (!s) return null

	if (isHex(s)) return hexToBytes(s)
	return tryDecodeBase64OrBase64Url(s)
}

async function verifyWithWebCrypto(
	publicKeyBytes: Uint8Array,
	messageBytes: Uint8Array,
	signatureBytes: Uint8Array
): Promise<boolean> {
	try {
		const toArrayBuffer = (u8: Uint8Array): ArrayBuffer =>
			u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) as ArrayBuffer

		const key = await crypto.subtle.importKey(
			"raw",
			toArrayBuffer(publicKeyBytes),
			{ name: "Ed448" },
			false,
			["verify"]
		)
		return await crypto.subtle.verify(
			{ name: "Ed448" },
			key,
			toArrayBuffer(signatureBytes),
			toArrayBuffer(messageBytes)
		)
	} catch {
		return false
	}
}

export async function verifyEd448Signature(args: {
	publicKeyBytes: Uint8Array
	messageBytes: Uint8Array
	signatureBytes: Uint8Array
}): Promise<boolean> {
	const { publicKeyBytes, messageBytes, signatureBytes } = args
	if (!(publicKeyBytes instanceof Uint8Array) || publicKeyBytes.length !== 57) return false
	if (!(signatureBytes instanceof Uint8Array) || signatureBytes.length !== 114) return false
	if (!(messageBytes instanceof Uint8Array)) return false

	if (crypto?.subtle) {
		const ok = await verifyWithWebCrypto(publicKeyBytes, messageBytes, signatureBytes)
		if (ok) return true
	}

	try {
		return ed448.verify(signatureBytes, messageBytes, publicKeyBytes)
	} catch {
		return false
	}
}
