/**
 * Prisma (Postgres): re-exports the canonical authenticators table SQL from postgres; adds schema.prisma model snippet.
 * Add the model to your schema.prisma and run prisma migrate, or run the SQL manually.
 *
 * @see https://authjs.dev/getting-started/providers/passkey
 */

export { AUTHENTICATORS_TABLE_SQL_POSTGRES as AUTHENTICATORS_TABLE_SQL_PRISMA } from "./postgres.js"

/** Prisma schema model snippet. Add to your schema.prisma (adjust provider and schema if needed). */
export const AUTHENTICATORS_MODEL_PRISMA = `
model Authenticator {
  credential_id    String   @id
  user_id          String
  provider_account_id String
  credential_public_key String
  counter          Int      @default(0)
  credential_device_type String
  credential_backed_up Int   @default(0)
  transports       String?

  @@map("authenticators")
}
`
