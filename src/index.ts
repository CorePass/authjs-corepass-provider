export { default as CorePass } from "./provider.js"
export { default } from "./provider.js"

export type {
	CorePassChallengeStore,
	CorePassPendingRegistration,
	CorePassProfile,
	CorePassStore,
	CorePassUserIdentity,
	CreateCorePassServerOptions,
} from "./server/types.js"

export { createCorePassServer } from "./server/create-corepass-server.js"
export { validateCoreIdMainnet, deriveEd448PublicKeyFromCoreId } from "./server/coreid.js"
export {
	memoryChallengeStore,
	redisChallengeStore,
	kvChallengeStore,
	vercelKvChallengeStore,
	upstashRedisChallengeStore,
	durableObjectChallengeStore,
	dynamoChallengeStore,
	type RedisLike,
	type KvLike,
	type VercelKvLike,
	type UpstashRedisLike,
	type DurableObjectStubLike,
	type DynamoLike,
} from "./server/challenge-stores.js"
