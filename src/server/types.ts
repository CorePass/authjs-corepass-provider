import type { Adapter, AdapterAccount, AdapterAuthenticator } from "@auth/core/adapters"

export type CorePassChallengeStore = {
	put(key: string, value: string, ttlSeconds: number): Promise<void>
	get(key: string): Promise<string | null>
	delete(key: string): Promise<void>
}

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

export type CorePassUserIdentity = {
	coreId: string
	userId: string
	refId: string | null
}

export type CorePassProfile = {
	userId: string
	coreId: string
	o18y: boolean | null
	o21y: boolean | null
	kyc: boolean | null
	kycDoc: string | null
	providedTill: number | null
}

export type CorePassStore = {
	createPendingRegistration(reg: CorePassPendingRegistration): Promise<void>
	getPendingRegistrationByCredentialId(
		credentialId: string
	): Promise<CorePassPendingRegistration | null>
	deletePendingRegistrationByToken(token: string): Promise<void>

	getIdentityByCoreId(coreId: string): Promise<CorePassUserIdentity | null>
	upsertIdentity(identity: CorePassUserIdentity): Promise<void>

	upsertProfile(profile: CorePassProfile): Promise<void>
}

export type CreateCorePassServerOptions = {
	/**
   * Auth.js adapter.
   * Used to create users, link the WebAuthn account, and create authenticators.
   */
	adapter: Required<
		Pick<
			Adapter,
			| "createUser"
			| "getUser"
			| "updateUser"
			| "linkAccount"
			| "getUserByAccount"
			| "getAuthenticator"
			| "createAuthenticator"
		>
	>
	/**
   * CorePass extension store (pending registrations + CoreID mapping + profile).
   */
	store: CorePassStore
	/**
   * Store for short-lived WebAuthn challenges (KV/Redis/DB/etc).
   */
	challengeStore: CorePassChallengeStore

	rpID: string
	rpName: string
	expectedOrigin: string

	/**
   * Enrichment signature must be calculated over this path.
   * Defaults to `/passkey/data`.
   */
	signaturePath?: string

	/**
   * AAGUID allowlist.
   *
   * - Default: CorePass AAGUID (`636f7265-7061-7373-6964-656e74696679`)
   * - Set to `false` to disable AAGUID checks (allow any authenticator).
   */
	allowedAaguids?: string | false

	/**
   * WebAuthn algorithm preferences (COSE `alg` ids).
   *
   * Default: `[-257, -7, -8]` (RS256, ES256, Ed25519) like the injector.
   */
	pubKeyCredAlgs?: number[]

	/**
   * If true, finalization fails if the resulting email is missing.
   * Defaults to false.
   */
	emailRequired?: boolean

	/**
   * Policy flags enforced during the enrich (pending) finalization path only.
   * Not enforced for immediate-finalize.
   *
   * Defaults: false
   */
	requireO18y?: boolean
	requireO21y?: boolean
	requireKyc?: boolean

	/**
   * TTL for pending registrations (seconds). Defaults to 600 (10 minutes).
   */
	pendingTtlSeconds?: number

	/**
   * Enable `refId` support (capture it in start/finish/enrich and store it).
   *
   * Defaults to `false`.
   */
	enableRefId?: boolean

	/**
   * Webhook URL to POST after successful finalization.
   *
   * Payload: `{ coreId, refId? }`
   */
	webhookUrl?: string

	/**
	 * Webhook secret for HMAC signing. If set, webhook requests will include:
	 * - `X-Webhook-Timestamp` (unix seconds)
	 * - `X-Webhook-Signature` (`sha256=<hex>`)
	 *
	 * Signature input:
	 * `timestamp + "\\n" + requestBody`
	 *
	 * If unset, webhooks are not signed.
	 */
	webhookSecret?: string

	/**
   * Number of webhook delivery attempts for a single finalization.
   *
   * Retries happen when:
   * - fetch throws (network error), or
   * - response is non-2xx
   *
   * Allowed range: 1-10
   * Default: 3
   */
	webhookRetries?: number

	/**
   * If enabled, POST a webhook after finalization:
   * - always sends `coreId`
   * - includes `refId` only if present
   *
   * Defaults to `false`.
   */
	postWebhooks?: boolean

	/**
   * If enabled, `finishRegistration` may finalize immediately when `coreId` is provided.
   * Defaults to false.
   *
   * Security note: immediate finalization shifts trust to whatever provides `coreId` to the server.
   * The default flow requires an Ed448-signed enrichment request to prove CoreID ownership.
   */
	allowImmediateFinalize?: boolean

	/**
   * The provider id to use when linking accounts. Defaults to `corepass`.
   */
	providerId?: string

	/**
   * Acceptable timestamp window for enrichment requests.
   */
	timestampWindowMs?: number

	/**
   * Allowed future skew for enrichment requests.
   */
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
