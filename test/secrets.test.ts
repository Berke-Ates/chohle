import { afterEach, describe, expect, it, vi } from 'vitest'
import { decryptSecret, encryptSecret, secretIsAvailable } from '../server/utils/secrets'

describe('secrets', () => {
  const originalSecret = process.env.CHOHLE_SECRET

  afterEach(() => {
    if (originalSecret === undefined) delete process.env.CHOHLE_SECRET
    else process.env.CHOHLE_SECRET = originalSecret
  })

  it('round-trips a plaintext through encrypt + decrypt', () => {
    const plain = 'eyJ0b2tlbiI6IkV3QmdBOFhxV3YifQ==.refresh-token'
    const stored = encryptSecret(plain)
    expect(stored).not.toContain(plain)
    expect(stored.split(':')).toHaveLength(4) // v1:iv:authTag:ciphertext
    expect(stored.startsWith('v1:')).toBe(true)
    expect(decryptSecret(stored)).toBe(plain)
  })

  it('produces a different ciphertext each call (fresh IV)', () => {
    const a = encryptSecret('same-input')
    const b = encryptSecret('same-input')
    expect(a).not.toBe(b)
    expect(decryptSecret(a)).toBe('same-input')
  })

  it('throws when tampered with', () => {
    const stored = encryptSecret('original')
    // Changing the last character corrupts the ciphertext
    expect(() => decryptSecret(stored.slice(0, -1) + (stored.endsWith('a') ? 'b' : 'a'))).toThrow()
  })

  it('rejects malformed or unsupported stored values', () => {
    expect(() => decryptSecret('not-four-parts-or-even-three')).toThrow(/malformed or unsupported/)
    expect(() => decryptSecret('iv:tag:data')).toThrow(/malformed or unsupported/)
    expect(() => decryptSecret('v2:iv:tag:data')).toThrow(/malformed or unsupported/)
  })

  it('refuses to encrypt without CHOHLE_SECRET (or too short)', async () => {
    delete process.env.CHOHLE_SECRET
    vi.resetModules()
    const mod = await import('../server/utils/secrets')
    expect(mod.secretIsAvailable()).toBe(false)
    expect(() => mod.encryptSecret('x')).toThrow(/CHOHLE_SECRET/)
  })
})
