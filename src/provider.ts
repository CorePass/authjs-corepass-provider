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
 */
export default function CorePass(
  config: Partial<WebAuthnConfig> = {}
): WebAuthnConfig {
  return WebAuthn({
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
}
