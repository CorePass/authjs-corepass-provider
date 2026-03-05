/**
 * PostgreSQL: canonical SQL for the WebAuthn Authenticator table.
 * Use this for Postgres, Drizzle, Neon, Hasura, Kysely, MikroORM, Prisma (or run the SQL from their migrations that re-export it).
 * Replace "public" with your schema if you use a non-default schema.
 *
 * @see https://authjs.dev/getting-started/providers/passkey
 */

/** PostgreSQL: create authenticators table. Replace "public" with your schema if needed. */
export const AUTHENTICATORS_TABLE_SQL_POSTGRES = `
CREATE TABLE IF NOT EXISTS public.authenticators (
  credential_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  provider_account_id TEXT NOT NULL,
  credential_public_key TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  credential_device_type TEXT NOT NULL,
  credential_backed_up INTEGER NOT NULL DEFAULT 0,
  transports TEXT
);
CREATE INDEX IF NOT EXISTS idx_authenticators_user_id ON public.authenticators(user_id);
`
