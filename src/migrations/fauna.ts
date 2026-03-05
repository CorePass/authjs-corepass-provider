/**
 * Fauna: collection layout for WebAuthn Authenticator (passkey).
 * Create the collection in Fauna (e.g. Dashboard or FQL) and implement getAuthenticator, createAuthenticator, updateAuthenticatorCounter, listAuthenticatorsByUserId on your FaunaCorePassLike client.
 * No runtime migration in this package.
 *
 * @see https://authjs.dev/getting-started/providers/passkey
 */

/** Collection and field layout for Auth.js Authenticator. Create collection in Fauna and add an index on user_id for listAuthenticatorsByUserId. */
export const AUTHENTICATORS_COLLECTION_FAUNA = {
	collectionName: "corepass_authenticators",
	fields: {
		credential_id: "string (unique / document id)",
		user_id: "string",
		provider_account_id: "string",
		credential_public_key: "string",
		counter: "number",
		credential_device_type: "string",
		credential_backed_up: "number (0 | 1)",
		transports: "string | null",
	},
	indexForListByUserId: "authenticators_by_user_id (terms: [\"data\", \"user_id\"])",
} as const
