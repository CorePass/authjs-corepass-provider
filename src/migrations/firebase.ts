/**
 * Firebase Firestore: collection layout for WebAuthn Authenticator (passkey).
 * Create the collection in Firestore; documents use credential_id as document ID. For listAuthenticatorsByUserId, query where user_id == userId (create a composite index on user_id if prompted).
 * No runtime migration in this package.
 *
 * @see https://authjs.dev/getting-started/providers/passkey
 */

/** Collection and field layout for Auth.js Authenticator. Document ID = credential_id. */
export const AUTHENTICATORS_COLLECTION_FIREBASE = {
	collectionName: "corepass_authenticators",
	documentId: "credential_id",
	fields: {
		credential_id: "string",
		user_id: "string",
		provider_account_id: "string",
		credential_public_key: "string",
		counter: "number",
		credential_device_type: "string",
		credential_backed_up: "number (0 | 1)",
		transports: "string | null",
	},
	indexForListByUserId: "Single-field or composite index on user_id for .where('user_id', '==', userId) queries.",
} as const
