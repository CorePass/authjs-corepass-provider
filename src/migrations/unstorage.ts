/**
 * Unstorage: key prefix and value shape for WebAuthn Authenticator (passkey).
 * Key = "corepass_authenticator:" + credential_id. Value = JSON with credential_id, user_id, provider_account_id, credential_public_key, counter, credential_device_type, credential_backed_up, transports.
 * For listAuthenticatorsByUserId implement getItems("corepass_authenticator:") and filter by user_id.
 * No runtime migration in this package.
 *
 * @see https://authjs.dev/getting-started/providers/passkey
 */

/** Key prefix and value shape for Auth.js Authenticator. */
export const AUTHENTICATORS_KEY_UNSTORAGE = {
	keyPrefix: "corepass_authenticator:",
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
	listByUserId: "Implement getItems('corepass_authenticator:') and filter results by user_id.",
} as const
