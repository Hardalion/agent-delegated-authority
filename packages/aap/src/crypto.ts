import { createHash, generateKeyPairSync, sign, verify, createPublicKey, type KeyObject } from 'node:crypto'

const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

/**
 * Same canonical form as authorization receipts: JSON.stringify over recursively sorted keys.
 * Uses Object.create(null) so an own `__proto__` key cannot mutate Object.prototype or the
 * intermediate object prototype. Dangerous keys are rejected rather than silently dropped.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value))
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys)
  if (value != null && typeof value === 'object') {
    const proto = Object.getPrototypeOf(value)
    if (proto !== Object.prototype && proto !== null) {
      throw new Error('canonicalJson rejects objects with a non-plain prototype')
    }
    const record = value as Record<string, unknown>
    const sorted: Record<string, unknown> = Object.create(null)
    for (const key of Object.keys(record).sort()) {
      if (DANGEROUS_KEYS.has(key)) {
        throw new Error(`canonicalJson rejects dangerous key: ${key}`)
      }
      sorted[key] = sortKeys(record[key])
    }
    // JSON.stringify enumerates own enumerable keys of null-prototype objects.
    return { ...sorted }
  }
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new Error('canonicalJson rejects non-finite numbers')
  }
  return value
}

export function sha256(value: unknown): string {
  return createHash('sha256').update(canonicalJson(value)).digest('hex')
}

export function generateEd25519(): { publicKey: KeyObject; privateKey: KeyObject } {
  return generateKeyPairSync('ed25519')
}

export function exportPublicKey(publicKey: KeyObject): string {
  return publicKey.export({ type: 'spki', format: 'der' }).toString('base64url')
}

export function importPublicKey(spki: string): KeyObject {
  return createPublicKey({ key: Buffer.from(spki, 'base64url'), type: 'spki', format: 'der' })
}

export function publicKeyFingerprint(spki: string): string {
  return `ed25519:${createHash('sha256').update(spki).digest('hex').slice(0, 32)}`
}

export function signObject(value: unknown, privateKey: KeyObject): string {
  return sign(null, Buffer.from(canonicalJson(value)), privateKey).toString('base64url')
}

export function verifyObject(value: unknown, signature: string, publicKey: KeyObject): boolean {
  try {
    return verify(null, Buffer.from(canonicalJson(value)), publicKey, Buffer.from(signature, 'base64url'))
  } catch {
    return false
  }
}

export function signHex(value: unknown, privateKey: KeyObject): string {
  return sign(null, Buffer.from(canonicalJson(value)), privateKey).toString('hex')
}

export function verifyHex(value: unknown, signatureHex: string, publicKey: KeyObject): boolean {
  if (!/^[0-9a-f]{128}$/i.test(signatureHex)) return false
  try {
    return verify(null, Buffer.from(canonicalJson(value)), publicKey, Buffer.from(signatureHex, 'hex'))
  } catch {
    return false
  }
}
