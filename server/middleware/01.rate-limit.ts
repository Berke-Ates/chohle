import { defineEventHandler, getRequestIP, setHeader, createError } from 'h3'
import { globalRateLimiter, getRateLimitRule, isRateLimitEnabled } from '../utils/rateLimit'

export default defineEventHandler((event) => {
  if (!isRateLimitEnabled()) return

  const path = (event.path || '').split('?')[0]!
  const rule = getRateLimitRule(path)
  if (!rule) return

  const ip = getRequestIP(event, { xForwardedFor: true }) || '127.0.0.1'
  const key = `${rule.name}:${ip}`
  const result = globalRateLimiter.check(key, rule.limit, rule.windowMs)

  setHeader(event, 'X-RateLimit-Limit', String(result.limit))
  setHeader(event, 'X-RateLimit-Remaining', String(result.remaining))
  setHeader(event, 'X-RateLimit-Reset', String(result.resetSeconds))

  if (!result.allowed) {
    setHeader(event, 'Retry-After', result.retryAfterSeconds)
    throw createError({
      statusCode: 429,
      statusMessage: 'Too Many Requests',
      message: 'Too many requests. Please try again later.'
    })
  }
})
