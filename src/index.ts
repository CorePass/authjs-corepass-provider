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
export { corepassXataAdapter } from "./adapters/xata.js"
export { corepassDynamoAdapter } from "./adapters/dynamodb.js"
export { corepassAzureTablesAdapter } from "./adapters/azure-tables.js"
export { corepassMongoAdapter } from "./adapters/mongodb.js"
export { corepassPouchAdapter } from "./adapters/pouchdb.js"
export { corepassNeonAdapter } from "./adapters/neon.js"
export { corepassPrismaAdapter } from "./adapters/prisma.js"
export { corepassDrizzleAdapter } from "./adapters/drizzle.js"
export { corepassKyselyAdapter } from "./adapters/kysely.js"
export { corepassFirebaseAdapter } from "./adapters/firebase.js"
export { corepassUpstashRedisAdapter } from "./adapters/upstash-redis.js"
export { corepassUnstorageAdapter } from "./adapters/unstorage.js"
export { corepassFaunaAdapter } from "./adapters/fauna.js"
export { corepassSequelizeAdapter } from "./adapters/sequelize.js"
export { corepassSurrealDBAdapter } from "./adapters/surrealdb.js"
export { corepassEdgeDBAdapter } from "./adapters/edgedb.js"
export { corepassTypeORMAdapter } from "./adapters/typeorm.js"
export { corepassNeo4jAdapter } from "./adapters/neo4j.js"
export { corepassDgraphAdapter } from "./adapters/dgraph.js"
export { corepassHasuraAdapter } from "./adapters/hasura.js"
export { corepassMikroORMAdapter } from "./adapters/mikro-orm.js"
export type { PgLike } from "./adapters/postgres.js"
export type { D1Like } from "./adapters/d1.js"
export type { SupabaseLike } from "./adapters/supabase.js"
export type { XataLike } from "./adapters/xata.js"
export type { DynamoLike, CorePassDynamoAdapterOptions } from "./adapters/dynamodb.js"
export type { AzureTablesLike, CorePassAzureTablesAdapterOptions } from "./adapters/azure-tables.js"
export type { MongoLike, MongoCollectionLike, CorePassMongoAdapterOptions } from "./adapters/mongodb.js"
export type { PouchDBLike } from "./adapters/pouchdb.js"
export type { PrismaLike, CorePassPrismaAdapterOptions } from "./adapters/prisma.js"
export type { DrizzleLike, CorePassDrizzleAdapterOptions } from "./adapters/drizzle.js"
export type { KyselyLike, CorePassKyselyAdapterOptions } from "./adapters/kysely.js"
export type { FirestoreLike, CorePassFirebaseAdapterOptions } from "./adapters/firebase.js"
export type { UpstashRedisLike } from "./adapters/upstash-redis.js"
export type { UnstorageLike } from "./adapters/unstorage.js"
export type { FaunaCorePassLike } from "./adapters/fauna.js"
export type { SequelizeLike, CorePassSequelizeAdapterOptions } from "./adapters/sequelize.js"
export type { SurrealDBLike, CorePassSurrealDBAdapterOptions } from "./adapters/surrealdb.js"
export type { EdgeDBLike } from "./adapters/edgedb.js"
export type { TypeORMLike, CorePassTypeORMAdapterOptions } from "./adapters/typeorm.js"
export type { Neo4jLike } from "./adapters/neo4j.js"
export type { DgraphCorePassLike } from "./adapters/dgraph.js"
export type { HasuraLike, CorePassHasuraAdapterOptions } from "./adapters/hasura.js"
export type { MikroORMLike, CorePassMikroORMAdapterOptions } from "./adapters/mikro-orm.js"
