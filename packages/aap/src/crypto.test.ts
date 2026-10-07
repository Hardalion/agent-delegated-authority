import { describe, expect, it } from 'vitest'
import { canonicalReceiptJson } from 'adap-receipt'
import { canonicalJson, generateEd25519, sha256, signObject, verifyObject } from './crypto.js'

describe('canonical signatures', () => {
  it('verifies Ed25519 over canonical JSON', () => {
    const keys = generateEd25519()
    const payload = { b: 2, a: 1 }
    const signature = signObject(payload, keys.privateKey)
    expect(verifyObject({ a: 1, b: 2 }, signature, keys.publicKey)).toBe(true)
    expect(sha256(payload)).toBe(sha256({ a: 1, b: 2 }))
    expect(canonicalJson({ z: { b: 1, a: 2 }, m: 3 })).toBe(canonicalReceiptJson({ m: 3, z: { a: 2, b: 1 } }))
  })
})
