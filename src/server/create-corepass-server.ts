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

async function syntheticEmailFromCoreId(coreId: string): Promise<string> {
  const bytes = new TextEncoder().encode(coreId)
  const digest = await crypto.subtle.digest("SHA-256", bytes)
  const hash = [...new Uint8Array(digest)]
    .slice(0, 16)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
  // Keep local-part short (<64 chars) and deterministic
  return `corepass+${hash}@corepass.invalid`
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

    const emailForUser = args.email ?? (await syntheticEmailFromCoreId(args.coreId))

    user = await adapter.createUser({
      // Most adapters will ignore provided id and generate their own.
      // CoreID is stored in corepass_identities instead.
      email: emailForUser,
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

  const pendingTtlSeconds = options.pendingTtlSeconds ?? 300
  const emailRequired = options.emailRequired ?? false
  const enableRefId = options.enableRefId ?? false
  const postWebhooks = options.postWebhooks ?? false
  const webhookUrl = options.webhookUrl
  const webhookRetriesRaw = options.webhookRetries ?? 3
  const signaturePath = options.signaturePath ?? "/passkey/data"
  const timestampWindowMs = options.timestampWindowMs ?? 10 * 60 * 1000
  const timestampFutureSkewMs = options.timestampFutureSkewMs ?? 2 * 60 * 1000
  const allowedAaguids = options.allowedAaguids ?? COREPASS_DEFAULT_AAGUID
  const pubKeyCredAlgs = options.pubKeyCredAlgs ?? [-257, -7, -8]

  const sw = WebAuthn({}).simpleWebAuthn

  if (postWebhooks && !webhookUrl) {
    throw new Error("createCorePassServer: postWebhooks=true requires webhookUrl")
  }

  if (!Number.isInteger(webhookRetriesRaw) || webhookRetriesRaw < 1 || webhookRetriesRaw > 10) {
    throw new Error("createCorePassServer: webhookRetries must be an integer between 1 and 10")
  }
  const webhookRetries = webhookRetriesRaw

  const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms))
  const retryDelayMs = (attempt: number) => Math.min(2000, 200 * 2 ** (attempt - 1))

  async function maybePostWebhook(args: { coreId: string; refId: string | null }) {
    if (!postWebhooks || !webhookUrl) return
    const payload: Record<string, unknown> = { coreId: args.coreId }
    if (args.refId) payload.refId = args.refId

    for (let attempt = 1; attempt <= webhookRetries; attempt++) {
      try {
        const res = await fetch(webhookUrl, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(payload),
        })
        if (res.ok) return
      } catch {
        // retry below
      }

      if (attempt < webhookRetries) {
        await sleep(retryDelayMs(attempt))
      }
    }
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

    const creationOptions = await sw.generateRegistrationOptions({
      rpID: options.rpID,
      rpName: options.rpName,
      userID: bytesToBase64Url(randomBytes(32)),
      userName: email ?? "CorePass",
      userDisplayName: email ?? "CorePass User",
      challenge,
      pubKeyCredParams: pubKeyCredAlgs.map((alg) => ({ alg, type: "public-key" })),
      authenticatorSelection: {
        authenticatorAttachment: "cross-platform",
        residentKey: "preferred",
        userVerification: "required",
      },
      attestationType: "none",
      timeout: 60_000,
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

    let verification: Awaited<ReturnType<(typeof sw)["verifyRegistrationResponse"]>>
    try {
      verification = await sw.verifyRegistrationResponse({
        response: attestation,
        expectedChallenge,
        expectedOrigin: options.expectedOrigin,
        expectedRPID: options.rpID,
        requireUserVerification: true,
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
      await maybePostWebhook({
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

    if (!Number.isSafeInteger(timestamp) || timestamp <= 0) {
      return json(400, { ok: false, error: "Invalid timestamp" })
    }

    const tNow = nowMs()
    if (tNow - timestamp > timestampWindowMs) return json(400, { ok: false, error: "Timestamp too old" })
    if (timestamp - tNow > timestampFutureSkewMs) return json(400, { ok: false, error: "Timestamp too far in future" })

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

    if (userData?.email !== undefined && userData?.email !== null && !emailFromBody) {
      return json(400, { ok: false, error: "Invalid email format" })
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
    await maybePostWebhook({ coreId, refId: storedIdentity?.refId ?? null })

    return json(200, {
      ok: true,
      coreId,
      email: finalEmail,
      userId: result.userId,
    })
  }

  return { startRegistration, finishRegistration, enrichRegistration }
}
