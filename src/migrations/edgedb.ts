/**
 * EdgeDB schema for WebAuthn Authenticator (passkey).
 * Add this type to your corepass module in dbschema (e.g. db/corepass-schema.edgedb.esdl) and run: edgedb migration create && edgedb migrate.
 *
 * @see https://authjs.dev/getting-started/providers/passkey
 */

/** EdgeDB SDL fragment for corepass::Authenticator. Add to your corepass module. */
export const AUTHENTICATORS_SCHEMA_EDGEDB = `
  type Authenticator {
    required property credential_id -> str {
      constraint exclusive;
    };
    required property user_id -> str;
    required property provider_account_id -> str;
    required property credential_public_key -> str;
    required property counter -> int64;
    required property credential_device_type -> str;
    required property credential_backed_up -> int64;
    property transports -> str;
  }
`
