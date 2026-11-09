import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { canonicalJson } from './canonical-json.js'
import { hashToolArgs } from './emit-authorization-receipt.js'
import { canonicalReceiptJson, verifyAuthorizationReceipt } from './authorization-receipt.js'

const here = dirname(fileURLToPath(import.meta.url))
const vectors = JSON.parse(
  readFileSync(join(here, 'canonical-json.vectors.json'), 'utf8'),
) as {
  accept: Array<{ name: string; value: unknown; canonical: string }>
}

describe('RFC 8785 canonical JSON vectors', () => {
  it.each(vectors.accept)('$name matches the shared vector', (vector) => {
    expect(canonicalJson(vector.value)).toBe(vector.canonical)
    expect(canonicalReceiptJson(vector.value)).toBe(vector.canonical)
  })

  it('does not use numeric order for integer-like keys', () => {
    const encoded = canonicalJson({ 9: 2, 10: 1, a: 3 })
    expect(encoded).toBe('{"10":1,"9":2,"a":3}')
    expect(encoded).not.toBe('{"9":2,"10":1,"a":3}')
  })

  it('formats finite numbers the way ECMAScript JSON does, including negative zero', () => {
    expect(canonicalJson({ n: 500.0, e: 1e-7, z: -0 })).toBe('{"e":1e-7,"n":500,"z":0}')
  })

  it('hashes tool arguments with the same serializer', () => {
    const args = { 10: 'b', 2: 'a', label: 'x' }
    expect(hashToolArgs(args)).toBe(
      hashToolArgs(JSON.parse(canonicalJson(args)) as Record<string, unknown>),
    )
    expect(canonicalJson(args)).toBe('{"10":"b","2":"a","label":"x"}')
  })

  it('keeps the published example receipt valid', () => {
    const receipt = JSON.parse(
      readFileSync(join(here, '../../../examples/receipt.json'), 'utf8'),
    ) as { integrity: { contentHash: string } }
    const result = verifyAuthorizationReceipt(receipt)
    expect(result.valid).toBe(true)
    expect(result.contentHash).toBe('35a2f27d1d11b306fbbfa81d0345afe66db6c9087d760eec7f20644744f2511c')
    expect(receipt.integrity.contentHash).toBe(result.contentHash)
  })

  it('rejects dangerous keys, bad prototypes, non-finite numbers, and unsupported values', () => {
    expect(() => canonicalJson(JSON.parse('{"a":1,"__proto__":{"x":1}}'))).toThrow(/dangerous key/)
    expect(() => canonicalJson(JSON.parse('{"constructor":1}'))).toThrow(/dangerous key/)
    expect(() => canonicalJson(JSON.parse('{"prototype":1}'))).toThrow(/dangerous key/)
    const inherited = Object.create({ leaked: 1 }) as Record<string, unknown>
    inherited.a = 1
    expect(() => canonicalJson(inherited)).toThrow(/prototype/)
    expect(() => canonicalJson({ n: Number.NaN })).toThrow(/non-finite/)
    expect(() => canonicalJson({ n: Number.POSITIVE_INFINITY })).toThrow(/non-finite/)
    expect(() => canonicalJson({ n: Number.NEGATIVE_INFINITY })).toThrow(/non-finite/)
    expect(() => canonicalJson({ n: 1n })).toThrow(/BigInt/)
    expect(() => canonicalJson({ f: () => 1 })).toThrow(/function/)
    expect(() => canonicalJson({ s: Symbol('x') })).toThrow(/symbol/)
    expect(() => canonicalJson(['a', undefined])).toThrow(/undefined/)
    expect(() => canonicalJson({ s: '\uD800' })).toThrow(/Unicode/)
    expect(() => canonicalJson({ '\uD800': 1 })).toThrow(/Unicode/)
    expect(canonicalJson({ a: 1, b: undefined })).toBe('{"a":1}')
  })
})
