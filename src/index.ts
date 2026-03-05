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
export {
	validateCoreIdMainnet,
	validateCoreIdWithSettings,
	deriveEd448PublicKeyFromCoreId,
} from "./server/coreid.js"

// Migration runners and types
export { migrateD1 } from "./migrations/d1.js"
export { migrateAzureTables } from "./migrations/azure-tables.js"
export type { AzureTablesMigrationClient } from "./migrations/azure-tables.js"

// Authenticators schema/table/collection constants (AUTHENTICATORS_*), alphabetically by adapter
export { AUTHENTICATORS_TABLE_AZURE_TABLES } from "./migrations/azure-tables.js"
export { AUTHENTICATORS_TABLE_SQL_D1 } from "./migrations/d1.js"
export { AUTHENTICATORS_TABLE_KEY_SCHEMA_DYNAMODB } from "./migrations/dynamodb.js"
export { AUTHENTICATORS_SCHEMA_DGRAPH } from "./migrations/dgraph.js"
export { AUTHENTICATORS_SCHEMA_EDGEDB } from "./migrations/edgedb.js"
export { AUTHENTICATORS_COLLECTION_FAUNA } from "./migrations/fauna.js"
export { AUTHENTICATORS_COLLECTION_FIREBASE } from "./migrations/firebase.js"
export { AUTHENTICATORS_TABLE_SQL_HASURA } from "./migrations/hasura.js"
export { AUTHENTICATORS_TABLE_SQL_KYSELY } from "./migrations/kysely.js"
export { AUTHENTICATORS_TABLE_SQL_MIKRO_ORM } from "./migrations/mikro-orm.js"
export { AUTHENTICATORS_COLLECTION_MONGODB } from "./migrations/mongodb.js"
export { AUTHENTICATORS_NODE_NEO4J } from "./migrations/neo4j.js"
export { AUTHENTICATORS_TABLE_SQL_NEON } from "./migrations/neon.js"
export { AUTHENTICATORS_TABLE_SQL_POSTGRES } from "./migrations/postgres.js"
export { AUTHENTICATORS_DOC_POUCHDB } from "./migrations/pouchdb.js"
export { AUTHENTICATORS_TABLE_SQL_PRISMA, AUTHENTICATORS_MODEL_PRISMA } from "./migrations/prisma.js"
export { AUTHENTICATORS_TABLE_SQL_SEQUELIZE } from "./migrations/sequelize.js"
export { AUTHENTICATORS_TABLE_SQL_SUPABASE } from "./migrations/supabase.js"
export { AUTHENTICATORS_TABLE_SURQL_SURREALDB } from "./migrations/surrealdb.js"
export { AUTHENTICATORS_TABLE_SQL_TYPEORM } from "./migrations/typeorm.js"
export { AUTHENTICATORS_KEY_UNSTORAGE } from "./migrations/unstorage.js"
export { AUTHENTICATORS_KEY_UPSTASH_REDIS } from "./migrations/upstash-redis.js"
export { AUTHENTICATORS_TABLE_XATA } from "./migrations/xata.js"

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
