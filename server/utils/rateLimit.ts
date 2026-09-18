// Sliding window rate limiter for sensitive API endpoints (auth and assistant).
// Tracks timestamps per client identifier (e.g. rule:IP) within a moving time window.
//
// When the number of requests in the window hits the limit, requests are rejected
// with HTTP 429 and Retry-After / X-RateLimit-* headers are provided.

export interface RateLimitResult {
  allowed: boolean
  limit: number
  remaining: number
  retryAfterSeconds: number
  resetSeconds: number
}

export interface RateLimitRule {
  name: string
  limit: number
  windowMs: number
}

export class SlidingWindowRateLimiter {
  private store = new Map<string, number[]>()
  private lastCleanup = Date.now()
  private cleanupIntervalMs = 60_000

  check(key: string, limit: number, windowMs: number, now: number = Date.now()): RateLimitResult {
    this.maybeCleanup(now, windowMs)

    const timestamps = this.store.get(key) || []
    const windowStart = now - windowMs

    // Keep only timestamps within the current sliding window
    const valid = timestamps.filter((t) => t > windowStart)

    if (valid.length >= limit) {
      const oldest = valid[0] ?? now
      const retryAfterMs = Math.max(0, oldest + windowMs - now)
      const retryAfterSeconds = Math.max(1, Math.ceil(retryAfterMs / 1000))
      this.store.set(key, valid)
      return {
        allowed: false,
        limit,
        remaining: 0,
        retryAfterSeconds,
        resetSeconds: retryAfterSeconds
      }
    }

    valid.push(now)
    this.store.set(key, valid)

    const oldest = valid[0] ?? now
    const resetMs = Math.max(0, oldest + windowMs - now)
    const resetSeconds = Math.max(1, Math.ceil(resetMs / 1000))

    return {
      allowed: true,
      limit,
      remaining: Math.max(0, limit - valid.length),
      retryAfterSeconds: 0,
      resetSeconds
    }
  }

  reset(): void {
    this.store.clear()
  }

  size(): number {
    return this.store.size
  }

  cleanup(now: number = Date.now(), maxWindowMs: number = 60_000): void {
    const cutoff = now - maxWindowMs
    for (const [key, timestamps] of this.store.entries()) {
      const valid = timestamps.filter((t) => t > cutoff)
      if (valid.length === 0) {
        this.store.delete(key)
      } else {
        this.store.set(key, valid)
      }
    }
  }

  private maybeCleanup(now: number, windowMs: number): void {
    if (now - this.lastCleanup > this.cleanupIntervalMs || this.store.size > 2000) {
      this.cleanup(now, windowMs)
      this.lastCleanup = now
    }
  }
}

// Global shared instance for the server runtime
export const globalRateLimiter = new SlidingWindowRateLimiter()

export function isRateLimitEnabled(): boolean {
  return process.env.CHOHLE_RATE_LIMIT !== 'false' && process.env.CHOHLE_RATE_LIMIT !== '0'
}

export function getRateLimitRule(path: string): RateLimitRule | null {
  const cleanPath = (path || '').split('?')[0]!

  if (cleanPath === '/api/auth' || cleanPath.startsWith('/api/auth/')) {
    const limit = Number(process.env.RATE_LIMIT_AUTH_MAX) || 10
    const windowSec = Number(process.env.RATE_LIMIT_AUTH_WINDOW_SEC) || 60
    return {
      name: 'auth',
      limit,
      windowMs: windowSec * 1000
    }
  }

  if (cleanPath === '/api/assistant' || cleanPath.startsWith('/api/assistant/')) {
    const limit = Number(process.env.RATE_LIMIT_ASSISTANT_MAX) || 30
    const windowSec = Number(process.env.RATE_LIMIT_ASSISTANT_WINDOW_SEC) || 60
    return {
      name: 'assistant',
      limit,
      windowMs: windowSec * 1000
    }
  }

  return null
}
