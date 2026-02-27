import WebAuthn, {
	DEFAULT_WEBAUTHN_TIMEOUT,
	type WebAuthnConfig,
} from "@auth/core/providers/webauthn"

/**
 * CorePass Auth.js provider.
 *
 * This provider is a thin wrapper around Auth.js' built-in WebAuthn provider with
 * Passkey-friendly defaults. CorePass' pending-registration + enrichment flow is
 * implemented via the server helpers exported from this package (see `createCorePassServer`).
 *
 * SimpleWebAuthn v13 expects the option key `credential` in verifyAuthenticationResponse;
 * Auth.js passes `authenticator`. We wrap verifyAuthenticationResponse so both work.
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
	if (sw && typeof sw.verifyAuthenticationResponse === "function") {
		const original = sw.verifyAuthenticationResponse
		base.simpleWebAuthn = {
			...sw,
			verifyAuthenticationResponse: (opts: Parameters<typeof original>[0] & { authenticator?: unknown }) => {
				const raw = opts.credential ?? opts.authenticator
				// Auth.js fromAdapterAuthenticator uses credentialPublicKey; SimpleWebAuthn v13 expects credential.publicKey
				const credential =
					raw && typeof raw === "object" && "credentialPublicKey" in raw && !(raw as { publicKey?: unknown }).publicKey
						? { ...raw, publicKey: (raw as { credentialPublicKey: unknown }).credentialPublicKey }
						: raw
				return original({ ...opts, credential: credential as Parameters<typeof original>[0]["credential"] })
			},
		}
	}
	return base
}
