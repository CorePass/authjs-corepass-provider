import WebAuthn, {
	DEFAULT_WEBAUTHN_TIMEOUT,
	type WebAuthnConfig,
} from "@auth/core/providers/webauthn"

/** Convert binary credential ID to base64url string (SimpleWebAuthn expects string, Auth.js may pass Uint8Array). */
function toBase64URL(value: Uint8Array | Buffer): string {
	const b = value instanceof Uint8Array ? value : new Uint8Array(value)
	const base64 =
		typeof Buffer !== "undefined" ? Buffer.from(b).toString("base64") : btoa(String.fromCharCode(...b))
	return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "")
}

/**
 * CorePass Auth.js provider.
 *
 * This provider is a thin wrapper around Auth.js' built-in WebAuthn provider with
 * Passkey-friendly defaults. CorePass' pending-registration + enrichment flow is
 * implemented via the server helpers exported from this package (see `createCorePassServer`).
 *
 * SimpleWebAuthn v13 expects the option key `credential` in verifyAuthenticationResponse;
 * Auth.js passes `authenticator`. We wrap verifyAuthenticationResponse so both work.
 * generateAuthenticationOptions expects allowCredentials[].id as base64url string;
 * Auth.js passes Uint8Array from fromBase64(credentialID). We normalize id to string.
 */
export default function CorePass(
	config: Partial<WebAuthnConfig> = {}
): WebAuthnConfig {
	const base = WebAuthn({
		id: "corepass",
		name: "CorePass",
		authenticationOptions: {
			timeout: DEFAULT_WEBAUTHN_TIMEOUT,
			userVerification: "required",
		},
		registrationOptions: {
			timeout: DEFAULT_WEBAUTHN_TIMEOUT,
			authenticatorSelection: {
				residentKey: "required",
				userVerification: "required",
			},
		},
		verifyAuthenticationOptions: {
			requireUserVerification: true,
		},
		verifyRegistrationOptions: {
			requireUserVerification: true,
		},
		...config,
	})
	const sw = base.simpleWebAuthn
	if (!sw) return base
	const wrappers: Partial<typeof sw> = {}
	if (typeof sw.verifyAuthenticationResponse === "function") {
		const original = sw.verifyAuthenticationResponse
		wrappers.verifyAuthenticationResponse = (opts: Parameters<typeof original>[0] & { authenticator?: unknown }) => {
			const raw = opts.credential ?? opts.authenticator
			// Auth.js fromAdapterAuthenticator uses credentialPublicKey; SimpleWebAuthn v13 expects credential.publicKey
			const credential =
				raw && typeof raw === "object" && "credentialPublicKey" in raw && !(raw as { publicKey?: unknown }).publicKey
					? { ...raw, publicKey: (raw as { credentialPublicKey: unknown }).credentialPublicKey }
					: raw
			return original({ ...opts, credential: credential as Parameters<typeof original>[0]["credential"] })
		}
	}
	if (typeof sw.generateAuthenticationOptions === "function") {
		const original = sw.generateAuthenticationOptions
		wrappers.generateAuthenticationOptions = async (opts: Parameters<typeof original>[0]) => {
			const allowCredentials = opts.allowCredentials?.map((cred) => {
				const id = cred.id as string | Uint8Array | Buffer
				const idString =
					typeof id === "string"
						? id
						: (id as unknown) instanceof Uint8Array || (typeof Buffer !== "undefined" && Buffer.isBuffer(id as Buffer))
							? toBase64URL(id as Uint8Array | Buffer)
							: String(id)
				return { ...cred, id: idString }
			})
			return original({
				...opts,
				...(allowCredentials !== undefined && { allowCredentials }),
			})
		}
	}
	if (Object.keys(wrappers).length > 0) {
		base.simpleWebAuthn = { ...sw, ...wrappers }
	}
	return base
}
