/**
 * Xata: table and column layout for WebAuthn Authenticator (passkey).
 * Create the table in your Xata workspace (dashboard or schema). Record id = credential_id. For listAuthenticatorsByUserId implement getAuthenticatorsByUserId (e.g. filter by user_id).
 * No runtime migration in this package.
 *
 * @see https://authjs.dev/getting-started/providers/passkey
 */

/** Table name and columns for Auth.js Authenticator. Use credential_id as record id. */
export const AUTHENTICATORS_TABLE_XATA = {
	tableName: "corepass_authenticators",
	idColumn: "credential_id",
	columns: {
		credential_id: "string (record id)",
		user_id: "string",
		provider_account_id: "string",
		credential_public_key: "string",
		counter: "int",
		credential_device_type: "string",
		credential_backed_up: "int (0 | 1)",
		transports: "string | null",
	},
	listByUserId: "Implement getAuthenticatorsByUserId(userId) on your XataLike client (e.g. query/filter by user_id).",
} as const
