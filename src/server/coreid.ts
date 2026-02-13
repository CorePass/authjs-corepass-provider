import { validateWalletAddress } from "blockchain-wallet-validator"

function isDigits2(s: string): boolean {
	return /^[0-9]{2}$/.test(s)
}

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

export function validateCoreIdMainnet(coreId: string): boolean {
	try {
		if (typeof coreId !== "string" || !coreId.trim()) return false
		const res = validateWalletAddress(coreId.trim(), { network: ["xcb"], testnet: false })
		return !!(res && (res as any).isValid)
	} catch {
		return false
	}
}

export function parseCoreIdIcan(coreId: string): { prefix: "cb"; checksum: string; bban: string } | null {
	if (typeof coreId !== "string") return null
	const s = coreId.trim()
	if (s.length < 5) return null
	const prefix = s.slice(0, 2).toLowerCase()
	const checksum = s.slice(2, 4)
	const bban = s.slice(4)

	if (prefix !== "cb") return null
	if (!isDigits2(checksum)) return null
	if (!bban) return null
	return { prefix: "cb", checksum, bban }
}

/**
 * Core ICAN (go-core) has two BBAN forms:
 * - Short form: BBAN = 40 hex chars (20 bytes), standard mainnet address. Cannot derive Ed448 public key.
 * - Long form: BBAN = 114 hex chars (57 bytes) = raw Ed448 public key. Required for signature verification.
 * Returns the raw Ed448 public key only when BBAN is 57 bytes; otherwise null (e.g. short-form address).
 */
export function deriveEd448PublicKeyFromCoreId(coreId: string): Uint8Array | null {
	if (!validateCoreIdMainnet(coreId)) return null
	const parts = parseCoreIdIcan(coreId)
	if (!parts) return null

	const pk = hexToBytes(parts.bban)
	if (!pk) return null
	// Only 57-byte BBAN (114 hex) is the raw Ed448 public key; 20-byte BBAN (40 hex) is short form, cannot verify
	if (pk.length !== 57) return null
	return pk
}
