/**
 * PouchDB: document _id prefix and properties for WebAuthn Authenticator (passkey).
 * Documents are created on first put. _id = "corepass_authenticator:" + credential_id. For listAuthenticatorsByUserId implement find({ selector: { user_id } }); create a Mango index on user_id.
 * No runtime migration in this package.
 *
 * @see https://authjs.dev/getting-started/providers/passkey
 */

/** Document _id prefix and properties for Auth.js Authenticator. */
export const AUTHENTICATORS_DOC_POUCHDB = {
	idPrefix: "corepass_authenticator:",
	properties: {
		credential_id: "string",
		user_id: "string",
		provider_account_id: "string",
		credential_public_key: "string",
		counter: "number",
		credential_device_type: "string",
		credential_backed_up: "number (0 | 1)",
		transports: "string | null",
	},
	indexForListByUserId: "Create a Mango index on user_id so find({ selector: { user_id } }) is supported.",
} as const
