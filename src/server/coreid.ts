import { validateWalletAddress } from "blockchain-wallet-validator"

/** Core ICAN short-form regex: (cb|ce|ab) + 2-digit checksum + 40 hex. */
const CORE_ID_AUTO_REGEX = /^(cb|ce|ab)[0-9]{2}[a-f0-9]{40}$/i

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

type CoreIdMode = "mainnet" | "testnet" | "enterprise"

function validateCoreIdByMode(coreId: string, mode: CoreIdMode): boolean {
	try {
		if (typeof coreId !== "string" || !coreId.trim()) return false
		const addr = coreId.trim()
		// xcb = mainnet, xab = testnet (Devin), xce = enterprise (Koliba); validate only the one that matches mode
		const network = mode === "mainnet" ? ["xcb"] : mode === "testnet" ? ["xab"] : ["xce"]
		const res = validateWalletAddress(addr, {
			network,
			testnet: mode === "testnet",
		})
		return !!(res && (res as { isValid?: boolean }).isValid)
	} catch {
		return false
	}
}

/**
 * Validate Core ID according to setting.
 * - false: skip validation (return true).
 * - true: same as 'auto'.
 * - 'auto': detect by regex ^(cb|ce|ab)[0-9]{2}[a-f0-9]{40}$/i; cb → mainnet (xcb), ab → testnet (xab), ce → enterprise (xce); then validate via blockchain-wallet-validator.
 * @see https://github.com/sergical/blockchain-wallet-validator
 */
export function validateCoreIdWithSettings(
	coreId: string,
	setting: boolean | "auto"
): boolean {
	if (setting === false) return true
	if (typeof coreId !== "string" || !coreId.trim()) return false
	const addr = coreId.trim()
	if (!CORE_ID_AUTO_REGEX.test(addr)) return false
	const prefix = addr.slice(0, 2).toLowerCase()
	if (prefix === "cb") return validateCoreIdByMode(addr, "mainnet")
	if (prefix === "ab") return validateCoreIdByMode(addr, "testnet")
	if (prefix === "ce") return validateCoreIdByMode(addr, "enterprise")
	return false
}

/** @deprecated Use validateCoreIdWithSettings(id, true) or validateCoreIdWithSettings(id, 'auto') with mainnet. Validates mainnet (cb) only. */
export function validateCoreIdMainnet(coreId: string): boolean {
	return validateCoreIdByMode(typeof coreId === "string" ? coreId.trim() : "", "mainnet")
}

export function parseCoreIdIcan(
	coreId: string
): { prefix: "cb" | "ce" | "ab"; checksum: string; bban: string } | null {
	if (typeof coreId !== "string") return null
	const s = coreId.trim()
	if (s.length < 5) return null
	const prefix = s.slice(0, 2).toLowerCase() as "cb" | "ce" | "ab"
	if (prefix !== "cb" && prefix !== "ce" && prefix !== "ab") return null
	const checksum = s.slice(2, 4)
	const bban = s.slice(4)
	if (!isDigits2(checksum)) return null
	if (!bban) return null
	return { prefix, checksum, bban }
}

/**
 * Core ICAN (go-core) has two BBAN forms:
 * - Short form: BBAN = 40 hex chars (20 bytes), standard mainnet address. Cannot derive Ed448 public key.
 * - Long form: BBAN = 114 hex chars (57 bytes) = raw Ed448 public key. Required for signature verification.
 * Returns the raw Ed448 public key only when BBAN is 57 bytes; otherwise null (e.g. short-form address).
 * When validator is provided, uses it instead of mainnet-only check (e.g. from validateCoreIdWithSettings).
 */
export function deriveEd448PublicKeyFromCoreId(
	coreId: string,
	validator?: (id: string) => boolean
): Uint8Array | null {
	const check = validator ?? validateCoreIdMainnet
	if (!check(coreId)) return null
	const parts = parseCoreIdIcan(coreId)
	if (!parts) return null

	const pk = hexToBytes(parts.bban)
	if (!pk) return null
	// Only 57-byte BBAN (114 hex) is the raw Ed448 public key; 20-byte BBAN (40 hex) is short form, cannot verify
	if (pk.length !== 57) return null
	return pk
}
