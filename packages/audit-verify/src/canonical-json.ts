/**
 * Reference-profile canonical JSON.
 *
 * RFC 8785 (JSON Canonicalization Scheme): object members are emitted in
 * ascending UTF-16 code-unit order, with no insignificant whitespace, and
 * finite numbers use ECMAScript Number-to-String (the same conversion as
 * JSON.stringify, including negative zero as 0).
 *
 * The serializer writes text from sorted entries. It does not rebuild a
 * JavaScript object and then rely on property enumeration order. Integer-like
 * keys therefore stay lexicographic.
 *
 * A maintained JCS library was not added. The profile also rejects dangerous
 * keys, non-plain prototypes, non-finite numbers, lone surrogates, BigInt,
 * functions, and symbols. Those restrictions are part of the hash preimage,
 * so the implementation stays in this repository with no extra dependency.
 */

const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

export class CanonicalJsonError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CanonicalJsonError'
  }
}

/** Canonical JSON for receipt hashes, signatures, tool-argument hashes, and other reference-profile digests. */
export function canonicalJson(value: unknown): string {
  return serialize(value)
}

function fail(message: string): never {
  throw new CanonicalJsonError(message)
}

function assertWellFormedUnicode(value: string, where: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index)
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1)
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        fail(`canonical JSON rejects invalid Unicode in ${where}`)
      }
      index += 1
      continue
    }
    if (code >= 0xdc00 && code <= 0xdfff) {
      fail(`canonical JSON rejects invalid Unicode in ${where}`)
    }
  }
}

function serialize(value: unknown): string {
  if (value === null) return 'null'
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false'
    case 'number':
      if (!Number.isFinite(value)) fail('canonical JSON rejects non-finite numbers')
      return JSON.stringify(value)
    case 'string':
      assertWellFormedUnicode(value, 'a string')
      return JSON.stringify(value)
    case 'bigint':
      fail('canonical JSON rejects BigInt')
    case 'undefined':
      fail('canonical JSON rejects undefined')
    case 'function':
      fail('canonical JSON rejects functions')
    case 'symbol':
      fail('canonical JSON rejects symbols')
    case 'object':
      break
    default:
      fail('canonical JSON rejects unsupported values')
  }

  if (Array.isArray(value)) {
    const parts: string[] = []
    for (let index = 0; index < value.length; index += 1) {
      if (!Object.prototype.hasOwnProperty.call(value, index) || value[index] === undefined) {
        fail('canonical JSON rejects undefined')
      }
      parts.push(serialize(value[index]))
    }
    return `[${parts.join(',')}]`
  }

  const proto = Object.getPrototypeOf(value)
  if (proto !== Object.prototype && proto !== null) {
    fail('canonical JSON rejects objects with a non-plain prototype')
  }

  const record = value as Record<string, unknown>
  if (Object.getOwnPropertySymbols(record).length > 0) {
    fail('canonical JSON rejects symbols')
  }
  const names = Object.getOwnPropertyNames(record)
  const keys = Object.keys(record).sort()
  if (names.length !== keys.length || names.some((name) => !Object.prototype.propertyIsEnumerable.call(record, name))) {
    fail('canonical JSON rejects non-enumerable properties')
  }

  const parts: string[] = []
  for (const key of keys) {
    if (DANGEROUS_KEYS.has(key)) {
      fail(`canonical JSON rejects dangerous key: ${key}`)
    }
    assertWellFormedUnicode(key, 'an object key')
    const child = record[key]
    // JSON omits undefined object members. They do not enter the encoding.
    if (child === undefined) continue
    parts.push(`${JSON.stringify(key)}:${serialize(child)}`)
  }
  return `{${parts.join(',')}}`
}
