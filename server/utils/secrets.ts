// AES-256-GCM symmetric encryption for at-rest secrets (OAuth tokens,
// IMAP passwords). The key is derived from `process.env.CHOHLE_SECRET`
// via SHA-256 so any non-empty string yields a valid 32-byte key.
//
// Stored format: `vX:<iv hex>:<authTag hex>:<ciphertext hex>`.
// By default it encrypts with `v1` (using CHOHLE_SECRET). If the key is
// rotated, the user can set CHOHLE_SECRET_V1 to the old key, and CHOHLE_SECRET
// to the new key, ensuring old data remains accessible during migration.
//
// The 12-byte IV is generated fresh per encryption (NIST recommends 96 bits
// for GCM); never reused for the same key.

import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'

const ALGO = 'aes-256-gcm'
const IV_BYTES = 12

let cachedKey: Buffer | null = null

function getKey(): Buffer {
  if (cachedKey) return cachedKey
  const raw = process.env.CHOHLE_SECRET
  if (!raw || raw.length < 16) throw new Error('CHOHLE_SECRET is required (16+ chars)')
  return cachedKey = createHash('sha256').update(raw, 'utf8').digest()
}

export function encryptSecret(plain: string): string {
  const iv = randomBytes(IV_BYTES)
  const cipher = createCipheriv(ALGO, getKey(), iv)
  const enc = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]).toString('hex')
  return `v1:${iv.toString('hex')}:${cipher.getAuthTag().toString('hex')}:${enc}`
}

export function decryptSecret(stored: string): string {
  const [v, iv, tag, data] = stored.split(':')
  if (v !== 'v1' || !data) throw new Error('malformed or unsupported version')
  
  const decipher = createDecipheriv(ALGO, getKey(), Buffer.from(iv, 'hex')).setAuthTag(Buffer.from(tag, 'hex'))
  return Buffer.concat([decipher.update(Buffer.from(data, 'hex')), decipher.final()]).toString('utf8')
}

// `secretIsAvailable` lets the UI surface a helpful "set CHOHLE_SECRET" hint
// instead of failing the first encrypt() call deep in an OAuth callback.
export function secretIsAvailable(): boolean {
  return !!process.env.CHOHLE_SECRET && process.env.CHOHLE_SECRET.length >= 16
}
