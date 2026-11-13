import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from 'node:crypto'
import { canonicalJson as canonicalJsonProfile } from 'adap-receipt'

/**
 * Reference-profile canonical JSON. One implementation, shared with receipt hashes and signatures.
 * Dangerous keys and non-plain prototypes are rejected rather than silently dropped.
 */
export function canonicalJson(value: unknown): string {
  return canonicalJsonProfile(value)
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

export function exportPrivateKeyPkcs8(privateKey: KeyObject): Buffer {
  return Buffer.from(privateKey.export({ type: 'pkcs8', format: 'der' }))
}

export function importPrivateKeyPkcs8(pkcs8: Buffer): KeyObject {
  return createPrivateKey({ key: pkcs8, type: 'pkcs8', format: 'der' })
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
