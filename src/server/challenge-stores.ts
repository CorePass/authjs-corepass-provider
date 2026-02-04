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
