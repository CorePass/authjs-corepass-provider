import type { AdapterAccount, AdapterAuthenticator } from "@auth/core/adapters"
import type { PendingStrategy, FinalizeStrategy } from "../config.js"
import type { CorePassAdapter } from "../types.js"
import type { TimeConfigInput } from "../time.js"

/** @deprecated Use pending backend (cookie or db) via createCorePassServer pending config. */
export type CorePassChallengeStore = {
	put(key: string, value: string, ttlSeconds: number): Promise<void>
	get(key: string): Promise<string | null>
	delete(key: string): Promise<void>
}

/** @deprecated Internal shape for legacy store payloads. */
export type CorePassPendingRegistration = {
	token: string
	credentialId: string
	credentialPublicKey: string
	counter: number
	credentialDeviceType: string
	credentialBackedUp: boolean
	transports: string | null
	email: string | null
	refId: string | null
	aaguid: string | null
	createdAt: number
	expiresAt: number
}

/** @deprecated Use CorePassAdapter from "../types.js". */
export type CorePassUserIdentity = { coreId: string; userId: string; refId: string | null }

/** @deprecated Use CorePassAdapter / profile from "../types.js". */
export type CorePassProfile = {
	userId: string
	coreId: string
	o18y: boolean | null
	o21y: boolean | null
	kyc: boolean | null
	kycDoc: string | null
	providedTill: number | null
}

/** @deprecated Use CorePassAdapter; legacy store interface for stores.ts. */
export type CorePassStore = {
	createPendingRegistration(reg: CorePassPendingRegistration): Promise<void>
	getPendingRegistrationByCredentialId(credentialId: string): Promise<CorePassPendingRegistration | null>
	deletePendingRegistrationByToken(token: string): Promise<void>
	getIdentityByCoreId(coreId: string): Promise<CorePassUserIdentity | null>
	getIdentityByUserId?(userId: string): Promise<CorePassUserIdentity | null>
	upsertIdentity(identity: CorePassUserIdentity): Promise<void>
	upsertProfile(profile: CorePassProfile): Promise<void>
}

/** Payload stored at start and consumed at finish (challenge + optional email/refId). */
export type CorePassStartPayload = {
	challenge: string
	email: string | null
	refId: string | null
}

/** Payload stored after finish for enrich (credential + metadata). */
export type CorePassPendingRegPayload = {
	credentialId: string
	credentialPublicKey: string
	counter: number
	credentialDeviceType: string
	credentialBackedUp: boolean
	transports: string | null
	email: string | null
	refId: string | null
	aaguid: string | null
	createdAt: number
	expiresAt: number
}

export type CreateCorePassServerOptions = {
	/** Unified Auth.js + CorePass adapter. Required. */
	adapter: CorePassAdapter

	/** Pending state strategy: "db" (default) or "cookie". */
	pending?: PendingStrategy

	/** Finalize strategy: "after" (default) or "immediate". */
	finalize?: FinalizeStrategy

	/** Secret for cookie encryption and VT token encryption. Required. */
	secret: string

	/** Cookie name for pending (cookie strategy). Defaults to __corepass_pending. */
	cookieName?: string

	rpID: string
	rpName: string
	expectedOrigin: string

	/** WebAuthn user name fallback order: this value, then email from request, then "CorePass". */
	defaultUserName?: string
	/** WebAuthn user display name fallback order: this value, then email from request, then "CorePass User". */
	defaultUserDisplayName?: string
	/** Default passkey user id (32 or 64 bytes, base64/base64url). If set, used when the request does not send userId. If neither request nor this is set, server generates 32 random bytes. */
	defaultUserId?: string

	signaturePath?: string
	allowedAaguids?: string | string[] | false
	/** COSE algorithm ID(s) for pubKeyCredParams. Single value or array. */
	pubKeyCredAlgs?: number | number[]
	attestationType?: "none" | "indirect" | "direct"
	authenticatorAttachment?: "platform" | "cross-platform"
	residentKey?: "discouraged" | "preferred" | "required"
	userVerification?: "required" | "preferred" | "discouraged"
	transports?: ("usb" | "nfc" | "ble" | "internal" | "hybrid")[]

	emailRequired?: boolean
	requireO18y?: boolean
	requireO21y?: boolean
	requireKyc?: boolean

	/** Unified time config (flow lifetime, registration timeout, timestamp window). */
	time?: TimeConfigInput

	enableRefId?: boolean

	registrationWebhookUrl?: string
	registrationWebhookSecret?: string
	registrationWebhookRetries?: number
	postRegistrationWebhooks?: boolean

	loginWebhookUrl?: string
	loginWebhookSecret?: string
	loginWebhookRetries?: number
	postLoginWebhooks?: boolean

	logoutWebhookUrl?: string
	logoutWebhookSecret?: string
	logoutWebhookRetries?: number
	postLogoutWebhooks?: boolean

	providerId?: string
	timestampFutureSkewMs?: number
}

export type CorePassFinalizeArgs = {
	coreId: string
	credentialId: string
	authenticator: Omit<AdapterAuthenticator, "userId">
	email: string | null
	refId: string | null
	o18y: boolean | null
	o21y: boolean | null
	kyc: boolean | null
	kycDoc: string | null
	dataExpMinutes: number | null
}

export type CorePassFinalizeResult = {
	userId: string
	account: AdapterAccount
}
