import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  SlidingWindowRateLimiter,
  getRateLimitRule,
  globalRateLimiter,
  isRateLimitEnabled
} from '../server/utils/rateLimit'

describe('SlidingWindowRateLimiter', () => {
  let limiter: SlidingWindowRateLimiter

  beforeEach(() => {
    limiter = new SlidingWindowRateLimiter()
  })

  it('allows requests within limit and decrements remaining', () => {
    const key = 'test:client-1'
    const limit = 3
    const windowMs = 60_000
    const t0 = 1_000_000

    const r1 = limiter.check(key, limit, windowMs, t0)
    expect(r1.allowed).toBe(true)
    expect(r1.limit).toBe(3)
    expect(r1.remaining).toBe(2)
    expect(r1.retryAfterSeconds).toBe(0)

    const r2 = limiter.check(key, limit, windowMs, t0 + 1000)
    expect(r2.allowed).toBe(true)
    expect(r2.remaining).toBe(1)

    const r3 = limiter.check(key, limit, windowMs, t0 + 2000)
    expect(r3.allowed).toBe(true)
    expect(r3.remaining).toBe(0)

    // Exceeds limit
    const r4 = limiter.check(key, limit, windowMs, t0 + 3000)
    expect(r4.allowed).toBe(false)
    expect(r4.remaining).toBe(0)
    expect(r4.retryAfterSeconds).toBe(57) // (1_000_000 + 60_000 - 1_003_000) / 1000 = 57s
    expect(r4.resetSeconds).toBe(57)
  })

  it('slides the window when older requests expire', () => {
    const key = 'test:client-2'
    const limit = 2
    const windowMs = 10_000
    const t0 = 100_000

    // Two requests at t0
    limiter.check(key, limit, windowMs, t0)
    limiter.check(key, limit, windowMs, t0 + 1000)

    // Third request at t0 + 2000 fails
    const blocked = limiter.check(key, limit, windowMs, t0 + 2000)
    expect(blocked.allowed).toBe(false)

    // Advance time past the first request (t0 + 10_001 > t0 + windowMs)
    const allowedAfterSlide = limiter.check(key, limit, windowMs, t0 + 10_001)
    expect(allowedAfterSlide.allowed).toBe(true)
    expect(allowedAfterSlide.remaining).toBe(0) // now holds [t0+1000, t0+10_001]
  })

  it('keeps track of different keys independently', () => {
    const limit = 2
    const windowMs = 60_000
    const now = 10_000

    limiter.check('auth:ip1', limit, windowMs, now)
    limiter.check('auth:ip1', limit, windowMs, now)
    expect(limiter.check('auth:ip1', limit, windowMs, now).allowed).toBe(false)

    // ip2 should still have full quota
    const resIp2 = limiter.check('auth:ip2', limit, windowMs, now)
    expect(resIp2.allowed).toBe(true)
    expect(resIp2.remaining).toBe(1)

    // assistant rule for ip1 should also have independent quota
    const resAssistant = limiter.check('assistant:ip1', limit, windowMs, now)
    expect(resAssistant.allowed).toBe(true)
  })

  it('cleans up expired entries', () => {
    const now = 100_000
    limiter.check('k1', 5, 10_000, now)
    limiter.check('k2', 5, 10_000, now)
    expect(limiter.size()).toBe(2)

    // Clean up with time advanced past 10s
    limiter.cleanup(now + 15_000, 10_000)
    expect(limiter.size()).toBe(0)
  })

  it('resets all entries on reset()', () => {
    limiter.check('k1', 5, 60_000, 1000)
    expect(limiter.size()).toBe(1)
    limiter.reset()
    expect(limiter.size()).toBe(0)
  })
})

describe('getRateLimitRule', () => {
  const env = process.env

  beforeEach(() => {
    process.env = { ...env }
  })

  afterEach(() => {
    process.env = env
  })

  it('matches /api/auth routes with default auth rules', () => {
    const rule1 = getRateLimitRule('/api/auth/login')
    expect(rule1).not.toBeNull()
    expect(rule1?.name).toBe('auth')
    expect(rule1?.limit).toBe(10)
    expect(rule1?.windowMs).toBe(60_000)

    const rule2 = getRateLimitRule('/api/auth/change-password?ref=1')
    expect(rule2?.name).toBe('auth')
  })

  it('matches /api/assistant routes with default assistant rules', () => {
    const rule1 = getRateLimitRule('/api/assistant/chat')
    expect(rule1).not.toBeNull()
    expect(rule1?.name).toBe('assistant')
    expect(rule1?.limit).toBe(30)
    expect(rule1?.windowMs).toBe(60_000)

    const rule2 = getRateLimitRule('/api/assistant/commit')
    expect(rule2?.name).toBe('assistant')
  })

  it('returns null for non-rate-limited routes', () => {
    expect(getRateLimitRule('/api/invoices')).toBeNull()
    expect(getRateLimitRule('/api/customers/1')).toBeNull()
    expect(getRateLimitRule('/api/search')).toBeNull()
  })

  it('respects environment overrides for limits and window sizes', () => {
    process.env.RATE_LIMIT_AUTH_MAX = '5'
    process.env.RATE_LIMIT_AUTH_WINDOW_SEC = '30'
    process.env.RATE_LIMIT_ASSISTANT_MAX = '50'
    process.env.RATE_LIMIT_ASSISTANT_WINDOW_SEC = '120'

    const authRule = getRateLimitRule('/api/auth/login')
    expect(authRule?.limit).toBe(5)
    expect(authRule?.windowMs).toBe(30_000)

    const assistantRule = getRateLimitRule('/api/assistant/chat')
    expect(assistantRule?.limit).toBe(50)
    expect(assistantRule?.windowMs).toBe(120_000)
  })
})

describe('isRateLimitEnabled', () => {
  const env = process.env

  beforeEach(() => {
    process.env = { ...env }
  })

  afterEach(() => {
    process.env = env
  })

  it('is enabled by default', () => {
    delete process.env.CHOHLE_RATE_LIMIT
    expect(isRateLimitEnabled()).toBe(true)
  })

  it('can be disabled with CHOHLE_RATE_LIMIT=false or 0', () => {
    process.env.CHOHLE_RATE_LIMIT = 'false'
    expect(isRateLimitEnabled()).toBe(false)

    process.env.CHOHLE_RATE_LIMIT = '0'
    expect(isRateLimitEnabled()).toBe(false)

    process.env.CHOHLE_RATE_LIMIT = 'true'
    expect(isRateLimitEnabled()).toBe(true)
  })
})

import rateLimitMiddleware from '../server/middleware/01.rate-limit'
import { createApp, toNodeListener, eventHandler } from 'h3'
import { createServer } from 'node:http'

describe('rate-limit middleware', () => {
  let server: ReturnType<typeof createServer>
  let baseUrl: string
  const originalEnv = process.env

  beforeEach(async () => {
    process.env = { ...originalEnv }
    globalRateLimiter.reset()
    const app = createApp()
    app.use(rateLimitMiddleware)
    app.use(
      eventHandler(() => {
        return { ok: true }
      })
    )
    server = createServer(toNodeListener(app))
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address() as { port: number }
        baseUrl = `http://127.0.0.1:${addr.port}`
        resolve()
      })
    })
  })

  afterEach(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()))
    globalRateLimiter.reset()
    process.env = originalEnv
  })

  it('sets X-RateLimit headers and passes through requests', async () => {
    const res = await fetch(`${baseUrl}/api/auth/login`, {
      headers: { 'x-forwarded-for': '10.0.0.1' }
    })
    expect(res.status).toBe(200)
    expect(res.headers.get('x-ratelimit-limit')).toBe('10')
    expect(res.headers.get('x-ratelimit-remaining')).toBe('9')
    expect(res.headers.get('x-ratelimit-reset')).toBeDefined()
  })

  it('blocks requests and returns 429 + Retry-After when limit is exceeded', async () => {
    process.env.RATE_LIMIT_AUTH_MAX = '2'

    // First request
    const r1 = await fetch(`${baseUrl}/api/auth/login`, {
      headers: { 'x-forwarded-for': '10.0.0.2' }
    })
    expect(r1.status).toBe(200)

    // Second request
    const r2 = await fetch(`${baseUrl}/api/auth/login`, {
      headers: { 'x-forwarded-for': '10.0.0.2' }
    })
    expect(r2.status).toBe(200)

    // Third request (exceeds limit)
    const r3 = await fetch(`${baseUrl}/api/auth/login`, {
      headers: { 'x-forwarded-for': '10.0.0.2' }
    })
    expect(r3.status).toBe(429)
    expect(r3.headers.get('retry-after')).toBeDefined()
    expect(Number(r3.headers.get('retry-after'))).toBeGreaterThan(0)
    expect(r3.headers.get('x-ratelimit-remaining')).toBe('0')
  })

  it('bypasses non-rate-limited routes', async () => {
    const res = await fetch(`${baseUrl}/api/invoices`)
    expect(res.status).toBe(200)
    expect(res.headers.get('x-ratelimit-limit')).toBeNull()
  })
})
