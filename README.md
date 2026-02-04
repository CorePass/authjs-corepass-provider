# authjs-corepass-provider

CorePass provider + server helpers for Auth.js (`@auth/core`) implementing the **pending-by-default** registration flow:

- Browser completes WebAuthn attestation (registration)
- Server stores a **pending registration** (no Auth.js user/account/authenticator yet)
- CorePass mobile app finalizes the account by calling **`POST /passkey/data`** with an **Ed448-signed** payload

This design is based on the existing Cloudflare Worker implementation in `wall-func-injector`.

## What you get

- **Provider**: `CorePass()` (wraps Auth.js WebAuthn with passkey-friendly defaults)
- **Server helpers**: `createCorePassServer()` exposing handlers:
  - `startRegistration(req)`
  - `finishRegistration(req)`
  - `enrichRegistration(req)` (your `/passkey/data`)
- **DB extension schema**: `db/corepass-schema.sql`

## Flows

### Registration flow (pending-by-default)

```mermaid
sequenceDiagram
  autonumber
  actor B as Browser
  participant S as Your backend
  participant KV as Challenge store
  participant DB as CorePass store
  actor A as CorePass app

  B->>S: POST /webauthn/start { email? }
  Note over B,S: Pending TTL default is 10 minutes (pendingTtlSeconds=600)
  S->>KV: put reg:sid {challenge,email} ttl
  S-->>B: 200 CreationOptions + Set-Cookie corepass.sid
  B->>B: navigator.credentials.create()
  B->>S: POST /webauthn/finish { attestation, email? }
  S->>KV: get+delete reg:sid
  S->>S: verifyRegistrationResponse()
  S->>DB: createPendingRegistration(credentialId, publicKey, counter, aaguid, email?)
  S-->>B: 200 { pending:true, enrichToken, credentialId }

  A->>S: POST /passkey/data {coreId, credentialId, timestamp, userData} + X-Signature (Ed448)
  S->>S: validateCoreIdMainnet + timestamp window
  S->>S: verify Ed448 signature over canonical JSON
  S->>DB: load+delete pending by credentialId
  S->>S: create/link Auth.js user+account+authenticator
  S->>DB: upsert CorePass identity/profile (provided_till, flags)
  S->>S: (optional) POST registration webhook { coreId, refId? } (registrationWebhookRetries, default 3)
  Note over S: If registrationWebhookSecret is set, include HMAC headers:\nX-Webhook-Timestamp + X-Webhook-Signature
  S-->>A: 200 ok
```

### Login flow (standard Auth.js WebAuthn authenticate)

CorePass login is normal WebAuthn: it uses the Auth.js WebAuthn callback path (`action=authenticate`), and resolves the user by stored authenticators.

```mermaid
sequenceDiagram
  autonumber
  actor B as Browser
  participant Auth as Auth.js (@auth/core)
  participant DB as Adapter DB

  B->>Auth: GET /auth/webauthn-options?action=authenticate (provider=corepass)
  Auth->>DB: listAuthenticatorsByUserId (optional) / challenge cookie
  Auth-->>B: 200 RequestOptions + challenge cookie
  B->>B: navigator.credentials.get()
  B->>Auth: POST /auth/callback/corepass { action:"authenticate", data }
  Auth->>DB: getAuthenticator(credentialId) + verifyAuthenticationResponse()
  Auth->>DB: updateAuthenticatorCounter()
  Auth-->>B: session established
  Note over Auth: (optional) POST login webhook { coreId, refId? } (loginWebhookRetries, default 3)
```

## Install

```bash
npm install authjs-corepass-provider
```

You also need:

- `@auth/core` (peer dependency)
- `@simplewebauthn/browser` in your frontend

## Auth.js configuration

```ts
import { Auth } from "@auth/core"
import CorePass from "authjs-corepass-provider/provider"

export const auth = (req: Request) =>
  Auth(req, {
    providers: [CorePass()],
    adapter: /* your Auth.js adapter */,
  })
```

## CorePass endpoints

You mount these where you want in your app (framework-specific). The handlers are plain Web API `Request -> Response`.

```ts
import { createCorePassServer } from "authjs-corepass-provider"

const corepass = createCorePassServer({
  adapter: /* Auth.js adapter (must implement WebAuthn + user methods) */,
  store: /* CorePassStore implementation (pending regs + coreId mapping + profile) */,
  challengeStore: /* CorePassChallengeStore implementation (KV/Redis/etc) */,
  rpID: "example.com",
  rpName: "Example",
  expectedOrigin: "https://example.com",

  // default: pending registrations are required
  allowImmediateFinalize: false,
})

// Optional: login webhook (call from Auth.js events.signIn)
// events: {
//   async signIn({ user, account }) {
//     if (account?.provider === "corepass" && account?.type === "webauthn" && user?.id) {
//       await corepass.postLoginWebhook({ userId: user.id })
//     }
//   }
// }

export async function POST(req: Request) {
  const url = new URL(req.url)
  if (url.pathname === "/webauthn/start") return corepass.startRegistration(req)
  if (url.pathname === "/webauthn/finish") return corepass.finishRegistration(req)
  if (url.pathname === "/passkey/data") return corepass.enrichRegistration(req)
  return new Response("Not found", { status: 404 })
}
```

## Database

Apply your adapter’s default Auth.js schema, then apply:

- `db/corepass-schema.sql`

This adds:

- `corepass_pending_registrations`
- `corepass_identities` (CoreID → Auth.js `userId` mapping)
- `corepass_profiles` (CorePass metadata like `o18y`, `kyc`, `provided_till`)

## Options

- **`allowedAaguids`**: defaults to CorePass AAGUID `636f7265-7061-7373-6964-656e74696679`. Set to `false` to allow any authenticator.
- **`pubKeyCredAlgs`**: defaults to `[-257, -7, -8]` (RS256, ES256, Ed25519).
- **`allowImmediateFinalize`**: if enabled, `finishRegistration` may finalize immediately if `coreId` is provided in the browser payload. This is **disabled by default** because it weakens the CoreID ownership guarantee (the default flow requires the Ed448-signed `/passkey/data` request).
- **`emailRequired`**: defaults to `false` (email can arrive later via `/passkey/data`). If no email is ever provided, the library creates the Auth.js user with a deterministic synthetic email and updates it once a real email is received.
- **`requireO18y`**: defaults to `false`. If enabled, `/passkey/data` must include `userData.o18y=true` or finalization is rejected. Not enforced for immediate-finalize.
- **`requireO21y`**: defaults to `false`. If enabled, `/passkey/data` must include `userData.o21y=true` or finalization is rejected. Not enforced for immediate-finalize.
- **`requireKyc`**: defaults to `false`. If enabled, `/passkey/data` must include `userData.kyc=true` or finalization is rejected. Not enforced for immediate-finalize.
- **`enableRefId`**: defaults to `false`. When enabled, the server generates and stores a `refId` (UUIDv4) for the CoreID identity and can include it in webhooks. When disabled, no `refId` is generated or stored.
- **Registration webhook options**:
  - **`postRegistrationWebhooks`**: defaults to `false`.
  - **`registrationWebhookUrl`**: required if `postRegistrationWebhooks: true`.
  - **`registrationWebhookSecret`**: optional. If set, requests are HMAC-signed (SHA-256) using `timestamp + "\\n" + body` and include `X-Webhook-Timestamp` (unix seconds) and `X-Webhook-Signature` (`sha256=<hex>`).
  - **`registrationWebhookRetries`**: defaults to `3` (range `1-10`). Retries happen on non-2xx responses or network errors.
- **Login webhook options**:
  - **`postLoginWebhooks`**: defaults to `false`.
  - **`loginWebhookUrl`**: required if `postLoginWebhooks: true`.
  - **`loginWebhookSecret`**: optional. Same signing format/headers as registration.
  - **`loginWebhookRetries`**: defaults to `3` (range `1-10`). Retries happen on non-2xx responses or network errors.
- **`pendingTtlSeconds`**: defaults to `600` (10 minutes). Pending registrations expire after this and are dropped.
- **`timestampWindowMs`**: defaults to `600000` (10 minutes). Enrichment `timestamp` must be within this window.

## Enrichment payload (`/passkey/data`)

The CorePass app sends:

- **Body**: `{ coreId, credentialId, timestamp, userData }`
- **Header**: `X-Signature` (Ed448 signature)

### Canonical payload + signature input

For signature verification, the server **does not** use the raw request body bytes. Instead it:

- **Canonicalizes JSON**: recursively sorts object keys alphabetically and serializes with `JSON.stringify(...)` (so it is **minified**, no whitespace).
- **Builds signature input** as:

```text
signatureInput = "POST\n" + signaturePath + "\n" + canonicalJsonBody
```

Then it verifies `X-Signature` (Ed448) over `UTF-8(signatureInput)`.

This means the CorePass signer must sign the **same canonical JSON string** (alphabetically ordered + minified) and the same `signaturePath` (defaults to `/passkey/data`, configurable via `signaturePath`).

### Timestamp units

`timestamp` is required and must be a **Unix timestamp in microseconds**.

`userData` fields:

| Field | Type | Example | Notes |
| - | - | - | - |
| `email` | `string` | `user@example.com` | Optional. If provided later, Auth.js user email is updated. |
| `o18y` | `boolean (or 0/1)` | `true` | Stored in `corepass_profiles.o18y`. |
| `o21y` | `boolean (or 0/1)` | `false` | Stored in `corepass_profiles.o21y`. |
| `kyc` | `boolean (or 0/1)` | `true` | Stored in `corepass_profiles.kyc`. |
| `kycDoc` | `string` | `PASSPORT` | Stored in `corepass_profiles.kyc_doc`. |
| `dataExp` | `number` | `43829` | Minutes. Converted to `provided_till`. |

`refId` is **not part of CorePass `/passkey/data`**. If you need an external correlation id, enable `enableRefId` and deliver it via your webhooks.

### `provided_till` calculation

`provided_till` is stored as a **Unix timestamp in seconds**:

```text
provided_till = floor(now_sec) + dataExpMinutes * 60
```

## Notes on Auth.js internals

Auth.js’ built-in WebAuthn flow normally creates the user/account/authenticator during the WebAuthn callback. CorePass intentionally delays this until enrichment, so it uses custom endpoints instead of Auth.js’ built-in “register” callback path.

## Upstream references

- Auth.js contributing guide: `https://raw.githubusercontent.com/nextauthjs/.github/main/CONTRIBUTING.md`
- Auth.js built-in Passkey provider: `https://raw.githubusercontent.com/nextauthjs/next-auth/main/packages/core/src/providers/passkey.ts`
