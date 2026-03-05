/**
 * MongoDB: collection layout for WebAuthn Authenticator (passkey).
 * Create the collection (created automatically on first insert). Add an index on user_id for listAuthenticatorsByUserId. Optional unique index on credential_id.
 * No runtime migration in this package.
 *
 * @see https://authjs.dev/getting-started/providers/passkey
 */

/** Collection and field layout for Auth.js Authenticator. Index user_id for list by user. */
export const AUTHENTICATORS_COLLECTION_MONGODB = {
	collectionName: "corepass_authenticators",
	fields: {
		credential_id: "string (unique)",
		user_id: "string",
		provider_account_id: "string",
		credential_public_key: "string",
		counter: "number",
		credential_device_type: "string",
		credential_backed_up: "number (0 | 1)",
		transports: "string | null",
	},
	indexForListByUserId: "db.corepass_authenticators.createIndex({ user_id: 1 })",
	indexUniqueCredentialId: "db.corepass_authenticators.createIndex({ credential_id: 1 }, { unique: true })",
} as const
