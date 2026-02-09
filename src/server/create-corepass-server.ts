import WebAuthn from "@auth/core/providers/webauthn"
import type { AdapterAccount, AdapterAuthenticator, AdapterUser } from "@auth/core/adapters"

import { bytesToBase64, bytesToBase64Url, normalizeCredentialId } from "./base64.js"
import { canonicalizeForSignature, canonicalizeJSON } from "./canonical-json.js"
import { parseCookies, serializeCookie } from "./cookies.js"
import { deriveEd448PublicKeyFromCoreId, validateCoreIdMainnet } from "./coreid.js"
import { parseEd448Signature, verifyEd448Signature } from "./ed448.js"
import { extractAaguidFromAttestationObject, validateAaguidAllowlist } from "./aaguid.js"

import type {
	CorePassFinalizeArgs,
	CorePassFinalizeResult,
	CorePassPendingRegistration,
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
	options: CreateCorePassServerOptions,
	args: CorePassFinalizeArgs
): Promise<CorePassFinalizeResult> {
	const providerId = options.providerId ?? "corepass"
	const { adapter, store } = options
	const enableRefId = options.enableRefId ?? false

	// 1) Find or create user by CoreID mapping
	let identity = await store.getIdentityByCoreId(args.coreId)
	let user: AdapterUser | null = identity ? await adapter.getUser(identity.userId) : null

	if (!identity || !user) {
		const emailRequired = options.emailRequired ?? false
		if (emailRequired && !args.email) throw new Error("Missing email")

		user = await adapter.createUser({
			// Most adapters will ignore provided id and generate their own.
			// CoreID is stored in corepass_identities instead.
			email: args.email ?? undefined,
			emailVerified: null,
			name: args.coreId.toUpperCase(),
			image: null,
		} as any)

		const refId = enableRefId ? args.refId ?? crypto.randomUUID() : null
		identity = { coreId: args.coreId, userId: user.id, refId }
		await store.upsertIdentity(identity)
	} else {
		// Keep refId if newly available
		if (enableRefId && args.refId && !identity.refId) {
			identity = { ...identity, refId: args.refId }
			await store.upsertIdentity(identity)
		}
		if (enableRefId && !identity.refId) {
			identity = { ...identity, refId: crypto.randomUUID() }
			await store.upsertIdentity(identity)
		}
	}

	// 2) Update user email if we have it and it differs
	if (args.email && user.email !== args.email) {
		user = await adapter.updateUser({ id: user.id, email: args.email } as any)
	}

	// 3) Link the WebAuthn account (providerAccountId = credentialId base64)
	const providerAccountId = args.credentialId
	const existingUserByAccount = await adapter.getUserByAccount({
		provider: providerId,
		providerAccountId,
	})
	if (existingUserByAccount && existingUserByAccount.id !== user.id) {
		throw new Error("Credential already linked to a different user")
	}

	const account: AdapterAccount = {
		userId: user.id,
		provider: providerId,
		providerAccountId,
		type: "webauthn",
	}
	if (!existingUserByAccount) {
		await adapter.linkAccount(account)
	}

	// 4) Create authenticator (idempotent best-effort; adapter may enforce uniqueness)
	const existingAuthenticator = await adapter.getAuthenticator(providerAccountId)
	if (!existingAuthenticator) {
		await adapter.createAuthenticator({
			...args.authenticator,
			userId: user.id,
		} as AdapterAuthenticator)
	}

	// 5) Store CorePass profile metadata (optional)
	await store.upsertProfile({
		userId: user.id,
		coreId: args.coreId,
		o18y: args.o18y,
		o21y: args.o21y,
		kyc: args.kyc,
		kycDoc: args.kycDoc,
		providedTill: computeProvidedTillFromDataExp(args.dataExpMinutes),
	})

	return { userId: user.id, account }
}

export function createCorePassServer(options: CreateCorePassServerOptions) {
	const cookieName = "corepass.sid"

	const pendingTtlSeconds = options.pendingTtlSeconds ?? 600
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
	const timestampWindowMs = options.timestampWindowMs ?? 10 * 60 * 1000
	const timestampFutureSkewMs = options.timestampFutureSkewMs ?? 2 * 60 * 1000
	const allowedAaguids = options.allowedAaguids ?? COREPASS_DEFAULT_AAGUID
	const pubKeyCredAlgs = options.pubKeyCredAlgs ?? [-257, -7, -8]

	const sw = WebAuthn({}).simpleWebAuthn

	if (postRegistrationWebhooks && !registrationWebhookUrl) {
		throw new Error(
			"createCorePassServer: postRegistrationWebhooks=true requires registrationWebhookUrl"
		)
	}
	if (postLoginWebhooks && !loginWebhookUrl) {
		throw new Error("createCorePassServer: postLoginWebhooks=true requires loginWebhookUrl")
	}
	if (postLoginWebhooks && typeof options.store.getIdentityByUserId !== "function") {
		throw new Error(
			"createCorePassServer: postLoginWebhooks=true requires store.getIdentityByUserId(userId)"
		)
	}
	if (postLogoutWebhooks && !logoutWebhookUrl) {
		throw new Error("createCorePassServer: postLogoutWebhooks=true requires logoutWebhookUrl")
	}
	if (postLogoutWebhooks && typeof options.store.getIdentityByUserId !== "function") {
		throw new Error(
			"createCorePassServer: postLogoutWebhooks=true requires store.getIdentityByUserId(userId)"
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
		const identity = await options.store.getIdentityByUserId?.(args.userId)
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
		const identity = await options.store.getIdentityByUserId?.(args.userId)
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
		const body = (await req.json().catch(() => null)) as any
		const email = parseEmail(body?.email)
		const refId =
			enableRefId && typeof body?.refId === "string" ? body.refId.trim() || null : null

		if (body?.email !== undefined && body?.email !== null && !email) {
			return json(400, { ok: false, error: "Invalid email" })
		}

		const challenge = randomChallenge()
		const sid = crypto.randomUUID()

		await options.challengeStore.put(
			`reg:${sid}`,
			JSON.stringify({ challenge, email, refId }),
			pendingTtlSeconds
		)

		const attestationType = options.attestationType ?? "none"
		const authenticatorAttachment = options.authenticatorAttachment ?? "cross-platform"
		const residentKey = options.residentKey ?? "preferred"
		const userVerification = options.userVerification ?? "required"
		const registrationTimeout = options.registrationTimeout ?? 60_000

		const creationOptions = await sw.generateRegistrationOptions({
			rpID: options.rpID,
			rpName: options.rpName,
			userID: randomBytes(32),
			userName: email ?? "CorePass",
			userDisplayName: email ?? "CorePass User",
			challenge,
			pubKeyCredParams: pubKeyCredAlgs.map((alg) => ({ alg, type: "public-key" })),
			authenticatorSelection: {
				authenticatorAttachment,
				residentKey,
				userVerification,
			},
			attestationType,
			timeout: registrationTimeout,
			excludeCredentials: [],
		})

		return json(
			200,
			creationOptions,
			{
				"set-cookie": serializeCookie(cookieName, sid, {
					httpOnly: true,
					secure: true,
					sameSite: "Lax",
					path: "/",
					maxAge: pendingTtlSeconds,
				}),
			}
		)
	}

	async function finishRegistration(req: Request): Promise<Response> {
		const body = (await req.json().catch(() => null)) as any
		const attestation = body?.attestation as any
		if (!attestation) return json(400, { ok: false, error: "Bad request" })

		const cookies = parseCookies(req.headers.get("cookie"))
		const sid = cookies[cookieName]
		if (!sid) return json(400, { ok: false, error: "No session" })

		const raw = await options.challengeStore.get(`reg:${sid}`)
		if (!raw) return json(400, { ok: false, error: "Challenge expired" })
		await options.challengeStore.delete(`reg:${sid}`)

		const saved = JSON.parse(raw) as {
			challenge: string
			email: string | null
			refId: string | null
		}
		const expectedChallenge = saved.challenge

		// Validate AAGUID allowlist (CorePass app gate)
		const aaguid = extractAaguidFromAttestationObject((attestation as any)?.response?.attestationObject)
		if (!validateAaguidAllowlist(aaguid, allowedAaguids)) {
			return json(400, {
				ok: false,
				error: "AAGUID not allowed",
				aaguid,
				allowedAaguids: allowedAaguids ?? null,
			})
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
		} catch {
			return json(400, { ok: false, error: "Invalid registration response" })
		}

		if (!verification.verified || !verification.registrationInfo) {
			return json(400, { ok: false, error: "Registration not verified" })
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
		const allowImmediateFinalize = options.allowImmediateFinalize ?? false

		if (allowImmediateFinalize && coreIdFromBody) {
			if (!validateCoreIdMainnet(coreIdFromBody)) {
				return json(400, { ok: false, error: "Invalid Core ID (mainnet)" })
			}

			const emailFromBody = parseEmail(body?.email)
			if (body?.email !== undefined && body?.email !== null && !emailFromBody) {
				return json(400, { ok: false, error: "Invalid email" })
			}
			const finalEmail = emailFromBody || saved.email || null
			if (emailRequired && !finalEmail) return json(400, { ok: false, error: "Missing email" })

			const result = await finalizeToAuthJs(options, {
				coreId: coreIdFromBody,
				credentialId: credentialIdBase64,
				authenticator,
				email: finalEmail,
				refId: enableRefId ? saved.refId : null,
				o18y: parseBool(body?.o18y),
				o21y: parseBool(body?.o21y),
				kyc: parseBool(body?.kyc),
				kycDoc: typeof body?.kycDoc === "string" ? body.kycDoc.trim() || null : null,
				dataExpMinutes: parseDataExpMinutes(body?.dataExp),
			})

			const storedIdentity = await options.store.getIdentityByCoreId(coreIdFromBody)
			await maybePostRegistrationWebhook({
				coreId: coreIdFromBody,
				refId: enableRefId ? storedIdentity?.refId ?? null : null,
			})

			return json(200, { ok: true, finalized: true, userId: result.userId, coreId: coreIdFromBody })
		}

		const token = crypto.randomUUID()
		const createdAt = nowSec()
		const expiresAt = createdAt + pendingTtlSeconds
		const pending: CorePassPendingRegistration = {
			token,
			credentialId: credentialIdBase64,
			credentialPublicKey: credentialPublicKeyBase64,
			counter: authenticator.counter,
			credentialDeviceType: authenticator.credentialDeviceType,
			credentialBackedUp: authenticator.credentialBackedUp,
			transports: authenticator.transports ?? null,
			email: saved.email,
			refId: enableRefId ? saved.refId : null,
			aaguid,
			createdAt,
			expiresAt,
		}
		await options.store.createPendingRegistration(pending)

		return json(200, {
			ok: true,
			pending: true,
			enrichToken: token,
			credentialId: credentialIdBase64,
		})
	}

	async function enrichRegistration(req: Request): Promise<Response> {
		const rawBody = await req.text()
		let body: any
		try {
			body = JSON.parse(rawBody)
		} catch {
			return json(400, { ok: false, error: "Invalid JSON" })
		}

		const coreId = typeof body?.coreId === "string" ? body.coreId.trim() : null
		const credentialIdRaw = typeof body?.credentialId === "string" ? body.credentialId.trim() : null
		const timestamp = body?.timestamp as unknown
		const userData = body?.userData ?? {}

		if (!coreId || !credentialIdRaw || typeof timestamp !== "number") {
			return json(400, { ok: false, error: "Missing required fields: coreId, credentialId, timestamp" })
		}

		if (!validateCoreIdMainnet(coreId)) {
			return json(400, { ok: false, error: "Invalid Core ID (mainnet)" })
		}

		const credentialIdNormalized = normalizeCredentialId(credentialIdRaw)
		if (!credentialIdNormalized) return json(400, { ok: false, error: "Invalid credentialId encoding" })
		const credentialIdBase64 = credentialIdNormalized.base64

		// Timestamp must be integer microseconds since Unix epoch
		if (!Number.isSafeInteger(timestamp) || timestamp <= 0) {
			return json(400, { ok: false, error: "Invalid timestamp (microseconds)" })
		}

		const tNowUs = nowUs()
		const windowUs = timestampWindowMs * 1000
		const futureSkewUs = timestampFutureSkewMs * 1000
		if (tNowUs - timestamp > windowUs) return json(400, { ok: false, error: "Timestamp too old" })
		if (timestamp - tNowUs > futureSkewUs) return json(400, { ok: false, error: "Timestamp too far in future" })

		const signatureHeader = req.headers.get("X-Signature")
		if (!signatureHeader) return json(400, { ok: false, error: "Missing X-Signature header" })

		const signatureBytes = parseEd448Signature(signatureHeader)
		if (!signatureBytes) return json(400, { ok: false, error: "Invalid signature format" })
		if (signatureBytes.length !== 114) return json(400, { ok: false, error: "Invalid signature length" })

		const publicKeyBytes = deriveEd448PublicKeyFromCoreId(coreId)
		if (!publicKeyBytes) return json(400, { ok: false, error: "Failed to derive public key from CoreID" })

		const canonicalBody = canonicalizeJSON(body)
		const signatureInput = canonicalizeForSignature("POST", signaturePath, canonicalBody)
		const messageBytes = new TextEncoder().encode(signatureInput)
		const valid = await verifyEd448Signature({ publicKeyBytes, messageBytes, signatureBytes })
		if (!valid) return json(400, { ok: false, error: "Invalid signature" })

		const pending = await options.store.getPendingRegistrationByCredentialId(credentialIdBase64)
		if (!pending) return json(400, { ok: false, error: "Pending registration not found" })

		if (pending.expiresAt < nowSec()) {
			await options.store.deletePendingRegistrationByToken(pending.token)
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

		const failAndCleanup = async (status: number, error: string): Promise<Response> => {
			await options.store.deletePendingRegistrationByToken(pending.token)
			return json(status, { ok: false, error })
		}

		// Validate parsed fields (and cleanup pending on failure)
		if (userData?.email !== undefined && userData?.email !== null && !emailFromBody) {
			return await failAndCleanup(400, "Invalid email format")
		}
		if (userData?.o18y !== undefined && userData?.o18y !== null && o18yFromBody === null) {
			return await failAndCleanup(400, "Invalid o18y")
		}
		if (userData?.o21y !== undefined && userData?.o21y !== null && o21yFromBody === null) {
			return await failAndCleanup(400, "Invalid o21y")
		}
		if (userData?.kyc !== undefined && userData?.kyc !== null && kycFromBody === null) {
			return await failAndCleanup(400, "Invalid kyc")
		}
		if (userData?.dataExp !== undefined && userData?.dataExp !== null && dataExpMinutes === null) {
			return await failAndCleanup(400, "Invalid dataExp")
		}

		// Policy gates (enrich/pending path only; not enforced for immediate-finalize)
		if (requireO18y && o18yFromBody !== true) {
			return await failAndCleanup(403, "o18y required")
		}
		if (requireO21y && o21yFromBody !== true) {
			return await failAndCleanup(403, "o21y required")
		}
		if (requireKyc && kycFromBody !== true) {
			return await failAndCleanup(403, "kyc required")
		}

		const finalEmail = emailFromBody || pending.email || null
		if (emailRequired && !finalEmail) {
			await options.store.deletePendingRegistrationByToken(pending.token)
			return json(400, { ok: false, error: "Missing email" })
		}

		const refId = enableRefId ? refIdFromBody || pending.refId || null : null

		await options.store.deletePendingRegistrationByToken(pending.token)

		const authenticator: Omit<AdapterAuthenticator, "userId"> = {
			providerAccountId: pending.credentialId,
			credentialID: pending.credentialId,
			credentialPublicKey: pending.credentialPublicKey,
			counter: pending.counter,
			credentialDeviceType: pending.credentialDeviceType,
			credentialBackedUp: pending.credentialBackedUp,
			transports: pending.transports,
		}

		const result = await finalizeToAuthJs(options, {
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

		const storedIdentity = await options.store.getIdentityByCoreId(coreId)
		await maybePostRegistrationWebhook({ coreId, refId: storedIdentity?.refId ?? null })

		return json(200, {
			ok: true,
			coreId,
			email: finalEmail,
			userId: result.userId,
		})
	}

	function checkEnrichment(): Response {
		const available = !(options.allowImmediateFinalize ?? false)
		return new Response(null, { status: available ? 200 : 404 })
	}

	return { startRegistration, finishRegistration, enrichRegistration, postLoginWebhook, postLogoutWebhook, checkEnrichment }
}
