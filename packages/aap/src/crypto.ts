import { createHash, generateKeyPairSync, sign, verify, createPublicKey, type KeyObject } from 'node:crypto'

/** Same canonical form as authorization receipts: JSON.stringify over recursively sorted keys. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value))
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys)
  if (value != null && typeof value === 'object') {
    const record = value as Record<string, unknown>
    const sorted: Record<string, unknown> = {}
    for (const key of Object.keys(record).sort()) {
      sorted[key] = sortKeys(record[key])
    }
    return sorted
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
  return verify(null, Buffer.from(canonicalJson(value)), publicKey, Buffer.from(signature, 'base64url'))
}

export function signHex(value: unknown, privateKey: KeyObject): string {
  return sign(null, Buffer.from(canonicalJson(value)), privateKey).toString('hex')
}

export function verifyHex(value: unknown, signatureHex: string, publicKey: KeyObject): boolean {
  if (!/^[0-9a-f]{128}$/i.test(signatureHex)) return false
  return verify(null, Buffer.from(canonicalJson(value)), publicKey, Buffer.from(signatureHex, 'hex'))
}
