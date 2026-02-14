import WebAuthn from "@auth/core/providers/webauthn"
import type { AdapterAccount, AdapterAuthenticator, AdapterUser } from "@auth/core/adapters"

import { resolveConfig } from "../config.js"
import { resolveTimeConfig } from "../time.js"
import { makePendingBackend, isPendingBackendWithToken } from "../pending/index.js"
import { getCookie, setCookieHeader, deleteCookieHeader } from "../http/cookies.js"
import { base64UrlToBytes, bytesToBase64, bytesToBase64Url, normalizeCredentialId } from "./base64.js"
import { canonicalizeForSignature, canonicalizeJSON } from "./canonical-json.js"
import { deriveEd448PublicKeyFromCoreId, validateCoreIdMainnet } from "./coreid.js"
import { parseEd448PublicKey, parseEd448Signature, verifyEd448Signature } from "./ed448.js"
import { extractAaguidFromAttestationObject, validateAaguidAllowlist } from "./aaguid.js"

import { resolvePasskeyUserId } from "../utils/userId.js"
import type {
	CorePassFinalizeArgs,
	CorePassFinalizeResult,
	CorePassStartPayload,
	CorePassPendingRegPayload,
	CreateCorePassServerOptions,
} from "./types.js"

const COREPASS_DEFAULT_AAGUID = "636f7265-7061-7373-6964-656e74696679"

function nowMs(): number {
	return Date.now()
}

function nowSec(): number {
	return Math.floor(nowMs() / 1000)
}

function nowUs(): number {
	return nowMs() * 1000
}

function json(status: number, body: unknown, headers?: HeadersInit): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "content-type": "application/json", ...(headers ?? {}) },
	})
}

function randomBytes(n: number): Uint8Array {
	const a = new Uint8Array(n)
	crypto.getRandomValues(a)
	return a
}

function randomChallenge(): string {
	return bytesToBase64Url(randomBytes(32))
}

function parseEmail(input: unknown): string | null {
	if (typeof input !== "string") return null
	const email = input.trim()
	if (!email) return null
	if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return null
	return email
}

function parseBool(input: unknown): boolean | null {
	if (input === undefined || input === null) return null
	if (typeof input === "boolean") return input
	if (typeof input === "number") return input === 1 ? true : input === 0 ? false : null
	if (typeof input === "string") {
		const v = input.trim().toLowerCase()
		if (v === "true" || v === "1" || v === "yes") return true
		if (v === "false" || v === "0" || v === "no") return false
	}
	return null
}

function parseDataExpMinutes(input: unknown): number | null {
	if (input === undefined || input === null) return null
	const n = typeof input === "number" ? input : parseInt(String(input), 10)
	if (!Number.isFinite(n)) return null
	if (n <= 0) return null
	return Math.floor(n)
}

function computeProvidedTillFromDataExp(dataExpMinutes: number | null): number | null {
	if (dataExpMinutes === null) return null
	return nowSec() + dataExpMinutes * 60
}

function transportsToString(transports: unknown): string | null {
	if (!Array.isArray(transports)) return null
	const items = transports.filter((t) => typeof t === "string") as string[]
	return items.length ? items.join(",") : null
}

async function finalizeToAuthJs(
	adapter: CreateCorePassServerOptions["adapter"],
	runInTx: <T>(fn: (ctx: { tx?: unknown }) => Promise<T>) => Promise<T>,
	options: CreateCorePassServerOptions,
	args: CorePassFinalizeArgs
): Promise<CorePassFinalizeResult> {
	const providerId = options.providerId ?? "corepass"
	const enableRefId = options.enableRefId ?? false

	return runInTx(async (ctx) => {
		let identity = await adapter.getIdentityByCoreId({ coreId: args.coreId }, ctx)
		let user: AdapterUser | null = identity ? await adapter.getUser!(identity.userId) : null

		if (!identity || !user) {
			const emailRequired = options.emailRequired ?? false
			if (emailRequired && !args.email) throw new Error("Missing email")

			user = await adapter.createUser!({
				email: args.email ?? undefined,
				emailVerified: null,
				name: args.coreId.toUpperCase(),
				image: null,
			} as Parameters<NonNullable<typeof adapter.createUser>>[0])

			const refId = enableRefId ? args.refId ?? crypto.randomUUID() : null
			identity = { coreId: args.coreId, userId: user.id, refId }
			await adapter.upsertIdentity({ coreId: args.coreId, userId: user.id, refId }, ctx)
		} else {
			if (enableRefId && args.refId && !identity.refId) {
				await adapter.upsertIdentity({ ...identity, refId: args.refId }, ctx)
			} else if (enableRefId && !identity.refId) {
				await adapter.upsertIdentity({ ...identity, refId: crypto.randomUUID() }, ctx)
			}
		}

		if (args.email && user!.email !== args.email && adapter.updateUser) {
			user = await adapter.updateUser({ id: user!.id, email: args.email } as Parameters<NonNullable<typeof adapter.updateUser>>[0])
		}

		const providerAccountId = args.credentialId
		const existingUserByAccount = await adapter.getUserByAccount!({
			provider: providerId,
			providerAccountId,
		})
		if (existingUserByAccount && existingUserByAccount.id !== user!.id) {
			throw new Error("Credential already linked to a different user")
		}

		const account: AdapterAccount = {
			userId: user!.id,
			provider: providerId,
			providerAccountId,
			type: "webauthn",
		}
		if (!existingUserByAccount && adapter.linkAccount) {
			await adapter.linkAccount(account)
		}

		const existingAuthenticator = await adapter.getAuthenticator?.(providerAccountId)
		if (!existingAuthenticator && adapter.createAuthenticator) {
			await adapter.createAuthenticator({
				...args.authenticator,
				userId: user!.id,
			} as AdapterAuthenticator)
		}

		await adapter.upsertProfile(
			{
				userId: user!.id,
				coreId: args.coreId,
				o18y: args.o18y,
				o21y: args.o21y,
				kyc: args.kyc,
				kycDoc: args.kycDoc,
				providedTill: computeProvidedTillFromDataExp(args.dataExpMinutes),
			},
			ctx
		)

		return { userId: user!.id, account }
	})
}

export function createCorePassServer(options: CreateCorePassServerOptions) {
	const adapter = options.adapter
	if (!adapter || typeof adapter.upsertIdentity !== "function" || typeof adapter.getIdentityByCoreId !== "function" || typeof adapter.upsertProfile !== "function") {
		throw new Error("createCorePassServer: adapter must implement upsertIdentity, getIdentityByCoreId, and upsertProfile (CorePassStore)")
	}
	if (!options.secret || typeof options.secret !== "string") {
		throw new Error("createCorePassServer: secret (string) is required")
	}

	const resolved = resolveConfig({
		...(options.pending !== undefined && { pending: options.pending }),
		...(options.finalize !== undefined && { finalize: options.finalize }),
		...(options.cookieName !== undefined && { cookieName: options.cookieName }),
	})
	const finalizeImmediate = resolved.finalize.strategy === "immediate"
	const defaultFlowLifetimeSeconds = finalizeImmediate && options.time?.flowLifetimeSeconds === undefined ? 120 : 600
	const time = resolveTimeConfig({
		...options.time,
		flowLifetimeSeconds: options.time?.flowLifetimeSeconds ?? defaultFlowLifetimeSeconds,
	})
	const { backend, requiresToken } = makePendingBackend({
		adapter,
		pendingConfig: resolved.pending,
		secret: options.secret,
		time,
	})
	const runInTx = adapter.withTransaction
		? (async <T>(fn: (ctx: import("../types.js").CorePassTxContext) => Promise<T>) => adapter.withTransaction!(fn) as Promise<T>)
		: async <T>(fn: (ctx: { tx?: unknown }) => Promise<T>) => fn({})

	const emailRequired = options.emailRequired ?? false
	const requireO18y = options.requireO18y ?? false
	const requireO21y = options.requireO21y ?? false
	const requireKyc = options.requireKyc ?? false
	const enableRefId = options.enableRefId ?? false
	const postRegistrationWebhooks = options.postRegistrationWebhooks ?? false
	const registrationWebhookUrl = options.registrationWebhookUrl
	const registrationWebhookSecret = options.registrationWebhookSecret
	const registrationWebhookRetriesRaw = options.registrationWebhookRetries ?? 3

	const postLoginWebhooks = options.postLoginWebhooks ?? false
	const loginWebhookUrl = options.loginWebhookUrl
	const loginWebhookSecret = options.loginWebhookSecret
	const loginWebhookRetriesRaw = options.loginWebhookRetries ?? 3

	const postLogoutWebhooks = options.postLogoutWebhooks ?? false
	const logoutWebhookUrl = options.logoutWebhookUrl
	const logoutWebhookSecret = options.logoutWebhookSecret
	const logoutWebhookRetriesRaw = options.logoutWebhookRetries ?? 3
	const signaturePath = options.signaturePath ?? "/passkey/data"
	const timestampFutureSkewMs = options.timestampFutureSkewMs ?? 2 * 60 * 1000
	const allowedAaguids = options.allowedAaguids ?? COREPASS_DEFAULT_AAGUID
	const pubKeyCredAlgs = options.pubKeyCredAlgs ?? [-257, -7, -8]
	const pendingCookieName = resolved.pending.strategy === "cookie" ? resolved.pending.cookieName : "__corepass_pending"

	const sw = WebAuthn({}).simpleWebAuthn

	if (postRegistrationWebhooks && !registrationWebhookUrl) {
		throw new Error(
			"createCorePassServer: postRegistrationWebhooks=true requires registrationWebhookUrl"
		)
	}
	if (postLoginWebhooks && !loginWebhookUrl) {
		throw new Error("createCorePassServer: postLoginWebhooks=true requires loginWebhookUrl")
	}
	if (postLoginWebhooks && typeof adapter.getIdentityByUserId !== "function") {
		throw new Error(
			"createCorePassServer: postLoginWebhooks=true requires adapter.getIdentityByUserId"
		)
	}
	if (postLogoutWebhooks && !logoutWebhookUrl) {
		throw new Error("createCorePassServer: postLogoutWebhooks=true requires logoutWebhookUrl")
	}
	if (postLogoutWebhooks && typeof adapter.getIdentityByUserId !== "function") {
		throw new Error(
			"createCorePassServer: postLogoutWebhooks=true requires adapter.getIdentityByUserId"
		)
	}

	if (
		!Number.isInteger(registrationWebhookRetriesRaw) ||
		registrationWebhookRetriesRaw < 1 ||
		registrationWebhookRetriesRaw > 10
	) {
		throw new Error(
			"createCorePassServer: registrationWebhookRetries must be an integer between 1 and 10"
		)
	}
	if (!Number.isInteger(loginWebhookRetriesRaw) || loginWebhookRetriesRaw < 1 || loginWebhookRetriesRaw > 10) {
		throw new Error("createCorePassServer: loginWebhookRetries must be an integer between 1 and 10")
	}
	if (
		!Number.isInteger(logoutWebhookRetriesRaw) ||
		logoutWebhookRetriesRaw < 1 ||
		logoutWebhookRetriesRaw > 10
	) {
		throw new Error("createCorePassServer: logoutWebhookRetries must be an integer between 1 and 10")
	}
	const registrationWebhookRetries = registrationWebhookRetriesRaw
	const loginWebhookRetries = loginWebhookRetriesRaw
	const logoutWebhookRetries = logoutWebhookRetriesRaw

	const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms))
	const retryDelayMs = (attempt: number) => Math.min(2000, 200 * 2 ** (attempt - 1))

	const hmacSha256Hex = async (secret: string, message: string): Promise<string> => {
		const key = await crypto.subtle.importKey(
			"raw",
			new TextEncoder().encode(secret),
			{ name: "HMAC", hash: "SHA-256" },
			false,
			["sign"]
		)
		const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message))
		return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("")
	}

	function withPendingCookieHeaders(res: Response, cookieHeaders: string[]): Response {
		if (cookieHeaders.length === 0) return res
		const headers = new Headers(res.headers)
		for (const h of cookieHeaders) headers.append("set-cookie", h)
		return new Response(res.body, { status: res.status, headers })
	}

	async function postWebhook(args: {
		url: string
		secret?: string
		retries: number
		payload: Record<string, unknown>
	}): Promise<void> {
		const { url, secret, retries, payload } = args
		const body = JSON.stringify(payload)

		for (let attempt = 1; attempt <= retries; attempt++) {
			try {
				const headers: Record<string, string> = { "content-type": "application/json" }
				if (secret) {
					const ts = String(nowSec())
					const signatureInput = `${ts}\n${body}`
					const sigHex = await hmacSha256Hex(secret, signatureInput)
					headers["X-Webhook-Timestamp"] = ts
					headers["X-Webhook-Signature"] = `sha256=${sigHex}`
				}

				const res = await fetch(url, {
					method: "POST",
					headers,
					body,
				})
				if (res.ok) return
			} catch {
				// retry below
			}

			if (attempt < retries) {
				await sleep(retryDelayMs(attempt))
			}
		}
	}

	async function maybePostRegistrationWebhook(args: { coreId: string; refId: string | null }): Promise<void> {
		if (!postRegistrationWebhooks || !registrationWebhookUrl) return
		const payload: Record<string, unknown> = { coreId: args.coreId }
		if (args.refId) payload.refId = args.refId
		await postWebhook({
			url: registrationWebhookUrl,
			retries: registrationWebhookRetries,
			payload,
			...(registrationWebhookSecret ? { secret: registrationWebhookSecret } : {}),
		})
	}

	async function postLoginWebhook(args: { userId: string }): Promise<void> {
		if (!postLoginWebhooks || !loginWebhookUrl) return
		const identity = await adapter.getIdentityByUserId?.({ userId: args.userId })
		if (!identity) return
		const payload: Record<string, unknown> = { coreId: identity.coreId }
		if (identity.refId) payload.refId = identity.refId
		await postWebhook({
			url: loginWebhookUrl,
			retries: loginWebhookRetries,
			payload,
			...(loginWebhookSecret ? { secret: loginWebhookSecret } : {}),
		})
	}

	async function postLogoutWebhook(args: { userId: string }): Promise<void> {
		if (!postLogoutWebhooks || !logoutWebhookUrl) return
		const identity = await adapter.getIdentityByUserId?.({ userId: args.userId })
		if (!identity) return
		const payload: Record<string, unknown> = { coreId: identity.coreId }
		if (identity.refId) payload.refId = identity.refId
		await postWebhook({
			url: logoutWebhookUrl,
			retries: logoutWebhookRetries,
			payload,
			...(logoutWebhookSecret ? { secret: logoutWebhookSecret } : {}),
		})
	}

	async function startRegistration(req: Request): Promise<Response> {
		const body = (await req.json().catch(() => null)) as Record<string, unknown>
		const email = parseEmail(body?.email)
		const refId =
			enableRefId && typeof body?.refId === "string" ? body.refId.trim() || null : null

		if (body?.email !== undefined && body?.email !== null && !email) {
			return json(400, { ok: false, error: "Invalid email" })
		}

		const userIdInput =
			typeof body?.userId === "string" ? body.userId : options.defaultUserId
		let userIdResolution: import("../utils/userId.js").UserIdResolution
		try {
			userIdResolution = resolvePasskeyUserId(userIdInput)
		} catch (err) {
			const message = err instanceof Error ? err.message : "Invalid userId"
			return json(400, { ok: false, error: message })
		}

		const challenge = randomChallenge()
		const payload: CorePassStartPayload = { challenge, email, refId }
		const expiresAt = new Date(Date.now() + time.flowExpiresInMs)
		const useCookie = resolved.pending.strategy === "cookie"
		const pendingKey = useCookie ? "reg" : bytesToBase64Url(randomBytes(16))

		const cookieHeaders: string[] = []
		const headerRecord = Object.fromEntries(req.headers.entries()) as Record<string, string | string[] | undefined>
		const cookieAccess = {
			getCookie: (name: string) => getCookie(headerRecord, name),
			setCookieHeader: (name: string, value: string, opts?: { maxAge: number; path?: string }) => {
				cookieHeaders.push(setCookieHeader(name, value, { ...opts, path: opts?.path ?? "/" }))
			},
			deleteCookieHeader: (name: string) => {
				cookieHeaders.push(deleteCookieHeader(name, "/"))
			},
		}
		const ctx = useCookie ? ({ cookieAccess } as import("../types.js").CorePassTxContext) : undefined
		const setResult = await backend.set(pendingKey, payload, expiresAt, ctx)
		const pendingToken = setResult && typeof setResult === "object" && "pendingToken" in setResult ? (setResult as { pendingToken: string }).pendingToken : undefined

		const attestationType = options.attestationType ?? "none"
		const authenticatorAttachment = options.authenticatorAttachment ?? "cross-platform"
		const residentKey = options.residentKey ?? "preferred"
		const userVerification = options.userVerification ?? "required"
		const transports = options.transports && options.transports.length > 0 ? options.transports : undefined

		const authenticatorSelection: {
			authenticatorAttachment: "platform" | "cross-platform"
			residentKey: "discouraged" | "preferred" | "required"
			userVerification: "required" | "preferred" | "discouraged"
			transports?: ("usb" | "nfc" | "ble" | "internal" | "hybrid")[]
		} = {
			authenticatorAttachment,
			residentKey,
			userVerification,
		}
		if (transports) authenticatorSelection.transports = transports

		const creationOptions = await sw.generateRegistrationOptions({
			rpID: options.rpID,
			rpName: options.rpName,
			userID: userIdResolution.userIdBytes,
			userName: options.defaultUserName ?? email ?? "CorePass",
			userDisplayName: options.defaultUserDisplayName ?? email ?? "CorePass User",
			// Pass raw bytes so SimpleWebAuthn v13 does not double base64url-encode (string is treated as UTF-8 and re-encoded)
			challenge: base64UrlToBytes(challenge),
			pubKeyCredParams: pubKeyCredAlgs.map((alg) => ({ alg, type: "public-key" })),
			authenticatorSelection,
			attestationType,
			timeout: time.registrationTimeoutMs,
			excludeCredentials: [],
		})

		const responseBody: Record<string, unknown> = { options: creationOptions }
		if (!useCookie) {
			responseBody.pendingKey = pendingKey
			if (requiresToken && pendingToken) responseBody.pendingToken = pendingToken
		}
		const res = json(200, responseBody)
		return withPendingCookieHeaders(res, cookieHeaders)
	}

	async function finishRegistration(req: Request): Promise<Response> {
		const body = (await req.json().catch(() => null)) as Record<string, unknown>
		const attestation = body?.attestation
		if (!attestation) return json(400, { ok: false, error: "Bad request" })

		const useCookie = resolved.pending.strategy === "cookie"
		const pendingKey = useCookie ? "reg" : (typeof body?.pendingKey === "string" ? body.pendingKey.trim() : null)
		const pendingToken = typeof body?.pendingToken === "string" ? body.pendingToken : undefined

		if (!pendingKey) {
			return json(400, { ok: false, error: useCookie ? "No pending cookie" : "Missing pendingKey" })
		}
		if (requiresToken && !pendingToken) {
			return json(400, { ok: false, error: "Missing pendingToken (required for this pending backend)" })
		}

		const cookieHeaders: string[] = []
		const headerRecordFinish = Object.fromEntries(req.headers.entries()) as Record<string, string | string[] | undefined>
		const cookieAccess = {
			getCookie: (name: string) => getCookie(headerRecordFinish, name),
			setCookieHeader: () => {},
			deleteCookieHeader: (name: string) => {
				cookieHeaders.push(deleteCookieHeader(name, "/"))
			},
		}
		const ctx = useCookie ? ({ cookieAccess } as import("../types.js").CorePassTxContext) : undefined
		let saved: CorePassStartPayload | null
		if (isPendingBackendWithToken(backend)) {
			const token = typeof pendingToken === "string" ? pendingToken : ""
			saved = (await backend.consumeWithToken(pendingKey, token, ctx)) as CorePassStartPayload | null
		} else {
			saved = (await backend.consume(pendingKey, ctx)) as CorePassStartPayload | null
		}
		if (!saved || typeof saved.challenge !== "string") {
			return withPendingCookieHeaders(json(400, { ok: false, error: "Challenge expired or invalid" }), cookieHeaders)
		}
		const expectedChallenge = saved.challenge

		// Validate AAGUID allowlist (CorePass app gate)
		const aaguid = extractAaguidFromAttestationObject((attestation as { response?: { attestationObject?: string } })?.response?.attestationObject)
		if (!validateAaguidAllowlist(aaguid, allowedAaguids)) {
			return withPendingCookieHeaders(json(400, {
				ok: false,
				error: "AAGUID not allowed",
				aaguid,
				allowedAaguids: allowedAaguids ?? null,
			}), cookieHeaders)
		}

		const requireUserVerification = options.userVerification !== "discouraged"
		let verification: Awaited<ReturnType<(typeof sw)["verifyRegistrationResponse"]>>
		try {
			verification = await sw.verifyRegistrationResponse({
				response: attestation,
				expectedChallenge,
				expectedOrigin: options.expectedOrigin,
				expectedRPID: options.rpID,
				requireUserVerification,
			})
		} catch (err) {
			const detail = err instanceof Error ? err.message : String(err)
			return withPendingCookieHeaders(
				json(400, { ok: false, error: "Invalid registration response", detail }),
				cookieHeaders
			)
		}

		if (!verification.verified || !verification.registrationInfo) {
			return withPendingCookieHeaders(json(400, { ok: false, error: "Registration not verified" }), cookieHeaders)
		}

		const credentialIdBase64 = bytesToBase64(verification.registrationInfo.credentialID)
		const credentialPublicKeyBase64 = bytesToBase64(verification.registrationInfo.credentialPublicKey)
		const transports = transportsToString((attestation as any)?.response?.transports)

		const authenticator: Omit<AdapterAuthenticator, "userId"> = {
			providerAccountId: credentialIdBase64,
			credentialID: credentialIdBase64,
			credentialPublicKey: credentialPublicKeyBase64,
			counter: verification.registrationInfo.counter,
			credentialDeviceType: verification.registrationInfo.credentialDeviceType,
			credentialBackedUp: verification.registrationInfo.credentialBackedUp,
			transports,
		}

		const coreIdFromBody = typeof body?.coreId === "string" ? body.coreId.trim() : null

		if (finalizeImmediate && coreIdFromBody) {
			if (!validateCoreIdMainnet(coreIdFromBody)) {
				return withPendingCookieHeaders(json(400, { ok: false, error: "Invalid Core ID (mainnet)" }), cookieHeaders)
			}

			const emailFromBody = parseEmail(body?.email)
			if (body?.email !== undefined && body?.email !== null && !emailFromBody) {
				return withPendingCookieHeaders(json(400, { ok: false, error: "Invalid email" }), cookieHeaders)
			}
			const finalEmail = emailFromBody || saved.email || null
			if (emailRequired && !finalEmail) {
				return withPendingCookieHeaders(json(400, { ok: false, error: "Missing email" }), cookieHeaders)
			}

			const result = await finalizeToAuthJs(adapter, runInTx, options, {
				coreId: coreIdFromBody,
				credentialId: credentialIdBase64,
				authenticator,
				email: finalEmail,
				refId: enableRefId ? saved.refId ?? null : null,
				o18y: parseBool(body?.o18y),
				o21y: parseBool(body?.o21y),
				kyc: parseBool(body?.kyc),
				kycDoc: typeof body?.kycDoc === "string" ? body.kycDoc.trim() || null : null,
				dataExpMinutes: parseDataExpMinutes(body?.dataExp),
			})

			const storedIdentity = await adapter.getIdentityByCoreId({ coreId: coreIdFromBody })
			await maybePostRegistrationWebhook({
				coreId: coreIdFromBody,
				refId: enableRefId ? storedIdentity?.refId ?? null : null,
			})

			return withPendingCookieHeaders(json(200, { ok: true, finalized: true, userId: result.userId, coreId: coreIdFromBody }), cookieHeaders)
		}

		// After strategy: store pending for enrich
		const createdAt = nowSec()
		const expiresAtSec = createdAt + time.flowLifetimeSeconds
		const pendingPayload: CorePassPendingRegPayload = {
			credentialId: credentialIdBase64,
			credentialPublicKey: credentialPublicKeyBase64,
			counter: authenticator.counter,
			credentialDeviceType: authenticator.credentialDeviceType,
			credentialBackedUp: authenticator.credentialBackedUp,
			transports: authenticator.transports ?? null,
			email: saved.email,
			refId: enableRefId ? saved.refId ?? null : null,
			aaguid,
			createdAt,
			expiresAt: expiresAtSec,
		}
		const enrichExpiresAt = new Date(Date.now() + time.flowExpiresInMs)
		const setEnrichResult = await backend.set(credentialIdBase64, pendingPayload, enrichExpiresAt)
		const enrichToken = setEnrichResult && typeof setEnrichResult === "object" && "pendingToken" in setEnrichResult
			? (setEnrichResult as { pendingToken: string }).pendingToken
			: undefined

		const out: Record<string, unknown> = { ok: true, pending: true, credentialId: credentialIdBase64 }
		if (enrichToken) out.enrichToken = enrichToken
		return withPendingCookieHeaders(json(200, out), cookieHeaders)
	}

	async function enrichRegistration(req: Request): Promise<Response> {
		const rawBody = await req.text()
		let body: Record<string, unknown>
		try {
			body = JSON.parse(rawBody) as Record<string, unknown>
		} catch {
			return json(400, { ok: false, error: "Invalid JSON" })
		}

		const coreId = typeof body?.coreId === "string" ? body.coreId.trim() : null
		const credentialIdRaw = typeof body?.credentialId === "string" ? body.credentialId.trim() : null
		const enrichTokenRaw: string | undefined = typeof body?.enrichToken === "string" ? (body.enrichToken as string) : undefined
		const timestamp = body?.timestamp as unknown
		const userData = (body?.userData ?? {}) as Record<string, unknown>

		if (!coreId || !credentialIdRaw || typeof timestamp !== "number") {
			return json(400, { ok: false, error: "Missing required fields: coreId, credentialId, timestamp" })
		}
		if (requiresToken && !enrichTokenRaw) {
			return json(400, { ok: false, error: "Missing enrichToken (required for this pending backend)" })
		}

		if (!validateCoreIdMainnet(coreId)) {
			return json(400, { ok: false, error: "Invalid Core ID (mainnet)" })
		}

		const credentialIdNormalized = normalizeCredentialId(credentialIdRaw)
		if (!credentialIdNormalized) return json(400, { ok: false, error: "Invalid credentialId encoding" })
		const credentialIdBase64 = credentialIdNormalized.base64

		if (!Number.isSafeInteger(timestamp) || timestamp <= 0) {
			return json(400, { ok: false, error: "Invalid timestamp (microseconds)" })
		}

		const tNowUs = nowUs()
		const windowUs = time.timestampWindowMs * 1000
		const futureSkewUs = timestampFutureSkewMs * 1000
		if (tNowUs - timestamp > windowUs) return json(400, { ok: false, error: "Timestamp too old" })
		if (timestamp - tNowUs > futureSkewUs) return json(400, { ok: false, error: "Timestamp too far in future" })

		const signatureHeader = req.headers.get("X-Signature")
		if (!signatureHeader) return json(400, { ok: false, error: "Missing X-Signature header" })

		const signatureBytes = parseEd448Signature(signatureHeader)
		if (!signatureBytes) return json(400, { ok: false, error: "Invalid signature format" })
		if (signatureBytes.length !== 114) return json(400, { ok: false, error: "Invalid signature length" })

		const publicKeyHeader = req.headers.get("X-Public-Key")
		let publicKeyBytes: Uint8Array | null =
			publicKeyHeader !== null && publicKeyHeader !== "" ? parseEd448PublicKey(publicKeyHeader) : null
		if (!publicKeyBytes) publicKeyBytes = deriveEd448PublicKeyFromCoreId(coreId)
		if (!publicKeyBytes) {
			return json(400, {
				ok: false,
				error:
					"Ed448 public key required for signature verification: provide X-Public-Key header (57 bytes, 114 hex or base64) or use long-form Core ID (BBAN = 114 hex chars).",
			})
		}

		const canonicalBody = canonicalizeJSON(body)
		const signatureInput = canonicalizeForSignature("POST", signaturePath, canonicalBody)
		const messageBytes = new TextEncoder().encode(signatureInput)
		const valid = await verifyEd448Signature({ publicKeyBytes, messageBytes, signatureBytes })
		if (!valid) return json(400, { ok: false, error: "Invalid signature" })

		let pending: CorePassPendingRegPayload | null
		if (isPendingBackendWithToken(backend)) {
			const token = requiresToken ? (enrichTokenRaw ?? "") : ""
			pending = (await backend.consumeWithToken(credentialIdBase64, token, undefined)) as CorePassPendingRegPayload | null
		} else {
			pending = (await backend.consume(credentialIdBase64, undefined)) as CorePassPendingRegPayload | null
		}
		if (!pending) return json(400, { ok: false, error: "Pending registration not found or already consumed" })

		if (pending.expiresAt < nowSec()) {
			return json(400, { ok: false, error: "Pending registration expired" })
		}

		const emailFromBody = parseEmail(userData?.email)
		const o18yFromBody = parseBool(userData?.o18y)
		const o21yFromBody = parseBool(userData?.o21y)
		const kycFromBody = parseBool(userData?.kyc)
		const kycDocFromBody = typeof userData?.kycDoc === "string" ? userData.kycDoc.trim() || null : null
		const dataExpMinutes = parseDataExpMinutes(userData?.dataExp)
		const refIdFromBody =
			enableRefId && typeof userData?.refId === "string" ? userData.refId.trim() || null : null

		if (userData?.email !== undefined && userData?.email !== null && !emailFromBody) {
			return json(400, { ok: false, error: "Invalid email format" })
		}
		if (userData?.o18y !== undefined && userData?.o18y !== null && o18yFromBody === null) {
			return json(400, { ok: false, error: "Invalid o18y" })
		}
		if (userData?.o21y !== undefined && userData?.o21y !== null && o21yFromBody === null) {
			return json(400, { ok: false, error: "Invalid o21y" })
		}
		if (userData?.kyc !== undefined && userData?.kyc !== null && kycFromBody === null) {
			return json(400, { ok: false, error: "Invalid kyc" })
		}
		if (userData?.dataExp !== undefined && userData?.dataExp !== null && dataExpMinutes === null) {
			return json(400, { ok: false, error: "Invalid dataExp" })
		}

		if (requireO18y && o18yFromBody !== true) return json(403, { ok: false, error: "o18y required" })
		if (requireO21y && o21yFromBody !== true) return json(403, { ok: false, error: "o21y required" })
		if (requireKyc && kycFromBody !== true) return json(403, { ok: false, error: "kyc required" })

		const finalEmail = emailFromBody || pending.email || null
		if (emailRequired && !finalEmail) {
			return json(400, { ok: false, error: "Missing email" })
		}

		const refId = enableRefId ? refIdFromBody || pending.refId || null : null

		const authenticator: Omit<AdapterAuthenticator, "userId"> = {
			providerAccountId: pending.credentialId,
			credentialID: pending.credentialId,
			credentialPublicKey: pending.credentialPublicKey,
			counter: pending.counter,
			credentialDeviceType: pending.credentialDeviceType,
			credentialBackedUp: pending.credentialBackedUp,
			transports: pending.transports,
		}

		const result = await finalizeToAuthJs(adapter, runInTx, options, {
			coreId,
			credentialId: pending.credentialId,
			authenticator,
			email: finalEmail,
			refId,
			o18y: o18yFromBody,
			o21y: o21yFromBody,
			kyc: kycFromBody,
			kycDoc: kycDocFromBody,
			dataExpMinutes,
		})

		const storedIdentity = await adapter.getIdentityByCoreId({ coreId })
		await maybePostRegistrationWebhook({ coreId, refId: storedIdentity?.refId ?? null })

		return json(200, {
			ok: true,
			coreId,
			email: finalEmail,
			userId: result.userId,
		})
	}

	function checkEnrichment(): Response {
		const available = resolved.finalize.strategy === "after"
		return new Response(null, { status: available ? 200 : 404 })
	}

	return { startRegistration, finishRegistration, enrichRegistration, postLoginWebhook, postLogoutWebhook, checkEnrichment }
}
