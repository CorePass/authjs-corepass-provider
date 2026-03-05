/**
 * Dgraph schema for WebAuthn Authenticator (passkey).
 * Dgraph has no runtime migration API in this package; apply this type to your Dgraph schema (GraphQL or DQL) yourself.
 * Then implement getAuthenticator, createAuthenticator, updateAuthenticatorCounter, listAuthenticatorsByUserId on your DgraphCorePassLike client.
 *
 * @see https://authjs.dev/getting-started/providers/passkey
 */

/** GraphQL type definition for Auth.js Authenticator. Add to your Dgraph schema. */
export const AUTHENTICATORS_SCHEMA_DGRAPH = `
# WebAuthn Authenticator (passkey) - Auth.js adapter optional type
type Authenticator {
  credentialID: string!
  userId: string!
  providerAccountId: string!
  credentialPublicKey: string!
  counter: int!
  credentialDeviceType: string!
  credentialBackedUp: bool!
  transports: string
}
# Index by credentialID (unique) and userId (for listAuthenticatorsByUserId)
# In Dgraph: add appropriate indexes for your queries.
`
