import { decode as cborDecode } from "cbor-x"
import { base64UrlToBytes } from "./base64.js"

function bytesToHex(bytes: Uint8Array): string {
    return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("")
}

function hexToUuid(hex32: string): string {
    return [
        hex32.slice(0, 8),
        hex32.slice(8, 12),
        hex32.slice(12, 16),
        hex32.slice(16, 20),
        hex32.slice(20),
    ].join("-")
}

function bytes16ToUuid(bytes16: Uint8Array): string {
    return hexToUuid(bytesToHex(bytes16))
}

/**
 * Extract the AAGUID from a WebAuthn attestationObject (base64url).
 */
export function extractAaguidFromAttestationObject(attestationObjectB64Url?: string): string | null {
    if (!attestationObjectB64Url) return null
    try {
        const attestationBytes = base64UrlToBytes(attestationObjectB64Url)
        const attObj = cborDecode(attestationBytes) as any
        const authData: Uint8Array | undefined = attObj?.authData
        if (!authData || authData.length < 37) return null

        const flags = authData[32] ?? 0
        const AT_FLAG = 0x40
        if ((flags & AT_FLAG) === 0) return null

        const aaguidOffset = 32 + 1 + 4
        const aaguidBytes = authData.slice(aaguidOffset, aaguidOffset + 16)
        if (aaguidBytes.length !== 16) return null

        return bytes16ToUuid(aaguidBytes)
    } catch {
        return null
    }
}

export function validateAaguidAllowlist(
    aaguid: string | null,
    allowedAaguids?: string | false
): boolean {
    if (allowedAaguids === false) return true
    if (!allowedAaguids) return true
    if (!aaguid) return false

    const normalized = aaguid.trim().toLowerCase()
    const allowed = allowedAaguids
        .split(",")
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean)

    return allowed.includes(normalized)
}

