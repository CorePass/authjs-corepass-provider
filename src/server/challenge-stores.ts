import type { CorePassChallengeStore } from "./types.js"

export function memoryChallengeStore(): CorePassChallengeStore {
	const m = new Map<string, { value: string; expiresAtMs: number }>()

	return {
		async put(key, value, ttlSeconds) {
			m.set(key, { value, expiresAtMs: Date.now() + ttlSeconds * 1000 })
		},
		async get(key) {
			const row = m.get(key)
			if (!row) return null
			if (Date.now() > row.expiresAtMs) {
				m.delete(key)
				return null
			}
			return row.value
		},
		async delete(key) {
			m.delete(key)
		},
	}
}

export type RedisLike = {
	set: (key: string, value: string, opts: { ex: number }) => Promise<unknown>
	get: (key: string) => Promise<string | null>
	del: (key: string) => Promise<unknown>
}

export function redisChallengeStore(redis: RedisLike): CorePassChallengeStore {
	return {
		async put(key, value, ttlSeconds) {
			await redis.set(key, value, { ex: ttlSeconds })
		},
		async get(key) {
			return await redis.get(key)
		},
		async delete(key) {
			await redis.del(key)
		},
	}
}

export type KvLike = {
	put: (key: string, value: string, opts: { expirationTtl: number }) => Promise<unknown>
	get: (key: string) => Promise<string | null>
	delete: (key: string) => Promise<unknown>
}

export function kvChallengeStore(kv: KvLike): CorePassChallengeStore {
	return {
		async put(key, value, ttlSeconds) {
			await kv.put(key, value, { expirationTtl: ttlSeconds })
		},
		async get(key) {
			return await kv.get(key)
		},
		async delete(key) {
			await kv.delete(key)
		},
	}
}

/**
 * Vercel KV client shape (based on `@vercel/kv`).
 * We intentionally don't import `@vercel/kv` to avoid a hard dependency.
 */
export type VercelKvLike = {
	set: (key: string, value: string, opts: { ex: number }) => Promise<unknown>
	get: <T = string>(key: string) => Promise<T | null>
	del: (key: string) => Promise<unknown>
}

export function vercelKvChallengeStore(kv: VercelKvLike): CorePassChallengeStore {
	return {
		async put(key, value, ttlSeconds) {
			await kv.set(key, value, { ex: ttlSeconds })
		},
		async get(key) {
			const v = await kv.get<string>(key)
			return typeof v === "string" ? v : v === null ? null : String(v)
		},
		async delete(key) {
			await kv.del(key)
		},
	}
}

/**
 * Upstash Redis REST client shape (based on `@upstash/redis`).
 * We intentionally don't import `@upstash/redis` to avoid a hard dependency.
 */
export type UpstashRedisLike = {
	set: (key: string, value: string, opts: { ex: number }) => Promise<unknown>
	get: <T = string>(key: string) => Promise<T | null>
	del: (key: string) => Promise<unknown>
}

export function upstashRedisChallengeStore(redis: UpstashRedisLike): CorePassChallengeStore {
	return {
		async put(key, value, ttlSeconds) {
			await redis.set(key, value, { ex: ttlSeconds })
		},
		async get(key) {
			const v = await redis.get<string>(key)
			return typeof v === "string" ? v : v === null ? null : String(v)
		},
		async delete(key) {
			await redis.del(key)
		},
	}
}

/**
 * Durable Object stub shape (Cloudflare).
 * Your Durable Object must implement these routes:
 * - POST /challenge/put { key, value, ttlSeconds }
 * - GET  /challenge/get?key=...
 * - POST /challenge/delete { key }
 */
export type DurableObjectStubLike = {
	fetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
}

export function durableObjectChallengeStore(stub: DurableObjectStubLike): CorePassChallengeStore {
	return {
		async put(key, value, ttlSeconds) {
			const res = await stub.fetch("https://do/challenge/put", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ key, value, ttlSeconds }),
			})
			if (!res.ok) throw new Error("durableObjectChallengeStore: put failed")
		},
		async get(key) {
			const res = await stub.fetch(
				`https://do/challenge/get?key=${encodeURIComponent(key)}`
			)
			if (!res.ok) return null
			const data = (await res.json()) as { value: string | null }
			return data.value
		},
		async delete(key) {
			await stub.fetch("https://do/challenge/delete", {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ key }),
			})
		},
	}
}

/**
 * DynamoDB-style store (pluggable).
 * This avoids hard-depending on AWS SDK packages while still making wiring easy.
 */
export type DynamoLike = {
	put: (args: { key: string; value: string; expiresAt: number }) => Promise<unknown>
	get: (key: string) => Promise<{ value: string; expiresAt: number } | null>
	delete: (key: string) => Promise<unknown>
}

export function dynamoChallengeStore(dynamo: DynamoLike): CorePassChallengeStore {
	const nowSec = () => Math.floor(Date.now() / 1000)
	return {
		async put(key, value, ttlSeconds) {
			await dynamo.put({ key, value, expiresAt: nowSec() + ttlSeconds })
		},
		async get(key) {
			const row = await dynamo.get(key)
			if (!row) return null
			if (row.expiresAt < nowSec()) return null
			return row.value
		},
		async delete(key) {
			await dynamo.delete(key)
		},
	}
}
