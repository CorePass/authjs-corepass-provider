/**
 * SurrealDB: table definition for WebAuthn Authenticator (passkey).
 * Add to your SurrealDB schema or run in your namespace/database. Also in db/corepass-schema.surrealdb.surql.
 *
 * @see https://authjs.dev/getting-started/providers/passkey
 */

/** SurrealQL DEFINE statements for corepass_authenticators table. */
export const AUTHENTICATORS_TABLE_SURQL_SURREALDB = `
DEFINE TABLE corepass_authenticators SCHEMAFULL;
DEFINE FIELD credential_id ON TABLE corepass_authenticators TYPE string;
DEFINE FIELD user_id ON TABLE corepass_authenticators TYPE string;
DEFINE FIELD provider_account_id ON TABLE corepass_authenticators TYPE string;
DEFINE FIELD credential_public_key ON TABLE corepass_authenticators TYPE string;
DEFINE FIELD counter ON TABLE corepass_authenticators TYPE int;
DEFINE FIELD credential_device_type ON TABLE corepass_authenticators TYPE string;
DEFINE FIELD credential_backed_up ON TABLE corepass_authenticators TYPE int;
DEFINE FIELD transports ON TABLE corepass_authenticators TYPE option<string>;
DEFINE INDEX corepass_authenticators_credential_id_unique ON TABLE corepass_authenticators COLUMNS credential_id UNIQUE;
DEFINE INDEX corepass_authenticators_user_id ON TABLE corepass_authenticators COLUMNS user_id;
`
