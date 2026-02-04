import { createCorePassServer } from "./create-corepass-server.js"
import { d1CorePassStore, postgresCorePassStore, supabaseCorePassStore } from "./stores.js"
import type { CreateCorePassServerOptions } from "./types.js"
import type { D1Like, PgLike, SupabaseLike } from "./stores.js"
import {
	kvChallengeStore,
	redisChallengeStore,
	upstashRedisChallengeStore,
	vercelKvChallengeStore,
	type KvLike,
	type RedisLike,
	type UpstashRedisLike,
	type VercelKvLike,
} from "./challenge-stores.js"

type WithoutStore<T> = Omit<T, "store">
type WithoutStoreAndChallengeStore<T> = Omit<T, "store" | "challengeStore">

export function createCorePassServerD1(
	options: WithoutStore<CreateCorePassServerOptions> & { db: D1Like }
) {
	const { db, ...rest } = options
	return createCorePassServer({ ...rest, store: d1CorePassStore(db) })
}

export function createCorePassServerPostgres(
	options: WithoutStore<CreateCorePassServerOptions> & { pg: PgLike }
) {
	const { pg, ...rest } = options
	return createCorePassServer({ ...rest, store: postgresCorePassStore(pg) })
}

export function createCorePassServerSupabase(
	options: WithoutStore<CreateCorePassServerOptions> & { supabase: SupabaseLike }
) {
	const { supabase, ...rest } = options
	return createCorePassServer({ ...rest, store: supabaseCorePassStore(supabase) })
}

/**
 * Popular stack factory: Cloudflare Workers (D1 + KV)
 */
export function createCorePassServerCloudflareD1Kv(
	options: WithoutStoreAndChallengeStore<CreateCorePassServerOptions> & { db: D1Like; kv: KvLike }
) {
	const { db, kv, ...rest } = options
	return createCorePassServer({
		...rest,
		store: d1CorePassStore(db),
		challengeStore: kvChallengeStore(kv),
	})
}

/**
 * Popular stack factory: Postgres + Redis
 */
export function createCorePassServerPostgresRedis(
	options: WithoutStoreAndChallengeStore<CreateCorePassServerOptions> & { pg: PgLike; redis: RedisLike }
) {
	const { pg, redis, ...rest } = options
	return createCorePassServer({
		...rest,
		store: postgresCorePassStore(pg),
		challengeStore: redisChallengeStore(redis),
	})
}

/**
 * Popular stack factory: Supabase (Postgres) + Upstash Redis REST
 */
export function createCorePassServerSupabaseUpstash(
	options: WithoutStoreAndChallengeStore<CreateCorePassServerOptions> & {
		supabase: SupabaseLike
		redis: UpstashRedisLike
	}
) {
	const { supabase, redis, ...rest } = options
	return createCorePassServer({
		...rest,
		store: supabaseCorePassStore(supabase),
		challengeStore: upstashRedisChallengeStore(redis),
	})
}

/**
 * Popular stack factory: Supabase (Postgres) + Vercel KV
 */
export function createCorePassServerSupabaseVercelKv(
	options: WithoutStoreAndChallengeStore<CreateCorePassServerOptions> & {
		supabase: SupabaseLike
		kv: VercelKvLike
	}
) {
	const { supabase, kv, ...rest } = options
	return createCorePassServer({
		...rest,
		store: supabaseCorePassStore(supabase),
		challengeStore: vercelKvChallengeStore(kv),
	})
}
