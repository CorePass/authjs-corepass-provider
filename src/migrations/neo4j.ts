/**
 * Neo4j: node label and properties for WebAuthn Authenticator (passkey).
 * Nodes are created on first MERGE/CREATE. Add a constraint or index on CorePassAuthenticator(credential_id) for uniqueness; index on user_id for list by user.
 * No runtime migration in this package.
 *
 * @see https://authjs.dev/getting-started/providers/passkey
 */

/** Node label and properties for Auth.js Authenticator. */
export const AUTHENTICATORS_NODE_NEO4J = {
	label: "CorePassAuthenticator",
	properties: {
		credential_id: "string (unique)",
		user_id: "string",
		provider_account_id: "string",
		credential_public_key: "string",
		counter: "integer",
		credential_device_type: "string",
		credential_backed_up: "integer (0 | 1)",
		transports: "string | null",
	},
	constraintCredentialId: "CREATE CONSTRAINT corepass_authenticator_credential_id IF NOT EXISTS FOR (a:CorePassAuthenticator) REQUIRE a.credential_id IS UNIQUE",
	indexUserId: "CREATE INDEX corepass_authenticator_user_id IF NOT EXISTS FOR (a:CorePassAuthenticator) ON (a.user_id)",
} as const
