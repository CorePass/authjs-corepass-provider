export { default as CorePass } from "./provider.js"
export { default } from "./provider.js"

export type {
	CorePassAdapter,
	CorePassStore,
	CorePassTx,
	CorePassTxContext,
	CorePassUserIdentity,
	CorePassProfile,
} from "./types.js"

export type { CreateCorePassServerOptions } from "./server/types.js"

export type { PendingStrategy, FinalizeStrategy, ResolvedConfig } from "./config.js"
export { resolveConfig } from "./config.js"

export type { TimeConfigInput, ResolvedTimeConfig } from "./time.js"
export { resolveTimeConfig } from "./time.js"

export {
	makePendingBackend,
	isPendingBackendWithToken,
	type MakePendingBackendResult,
	type PendingBackend,
	type PendingBackendWithToken,
	type CookieAccess,
} from "./pending/index.js"

export { createCorePassServer } from "./server/create-corepass-server.js"
export { validateCoreIdMainnet, deriveEd448PublicKeyFromCoreId } from "./server/coreid.js"

export { corepassPostgresAdapter } from "./adapters/postgres.js"
export { corepassD1Adapter } from "./adapters/d1.js"
export { corepassSupabaseAdapter } from "./adapters/supabase.js"
export type { PgLike } from "./adapters/postgres.js"
export type { D1Like } from "./adapters/d1.js"
export type { SupabaseLike } from "./adapters/supabase.js"
