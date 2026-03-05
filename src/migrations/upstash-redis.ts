/**
 * Upstash Redis: key pattern and value shape for WebAuthn Authenticator (passkey).
 * Key = "corepass_authenticator:" + credential_id. Value = JSON. listAuthenticatorsByUserId uses keys("corepass_authenticator:*") then filter by user_id.
 * No runtime migration in this package.
 *
 * @see https://authjs.dev/getting-started/providers/passkey
 */

/** Key prefix and value shape for Auth.js Authenticator. */
export const AUTHENTICATORS_KEY_UPSTASH_REDIS = {
	keyPrefix: "corepass_authenticator:",
	keyPattern: "corepass_authenticator:*",
	valueShape: {
		credential_id: "string",
		user_id: "string",
		provider_account_id: "string",
		credential_public_key: "string",
		counter: "number",
		credential_device_type: "string",
		credential_backed_up: "number (0 | 1)",
		transports: "string | null",
	},
	listByUserId: "keys('corepass_authenticator:*'), then get each and filter by user_id.",
} as const
