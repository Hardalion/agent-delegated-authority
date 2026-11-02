/**
 * Data-only object helpers for security-sensitive dictionaries.
 * Rejects prototype-bearing structures and dangerous keys at normalization boundaries.
 */

import { AuthorityError } from './errors.js'

const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

export function isPlainDataObject(value: unknown): value is Record<string, unknown> {
  if (value == null || typeof value !== 'object' || Array.isArray(value)) return false
  const proto = Object.getPrototypeOf(value)
  return proto === Object.prototype || proto === null
}

export function assertSafeKey(key: string, path = 'object'): void {
  if (DANGEROUS_KEYS.has(key)) {
    throw new AuthorityError('schema', `dangerous key rejected at ${path}: ${key}`)
  }
}

/** Copy own enumerable string keys into Object.create(null). Rejects non-plain objects and dangerous keys. */
export function toDataRecord(
  value: unknown,
  path = 'object'
): Record<string, unknown> {
  if (!isPlainDataObject(value)) {
    throw new AuthorityError('schema', `${path} must be a plain data object`)
  }
  const out: Record<string, unknown> = Object.create(null)
  for (const key of Object.keys(value)) {
    assertSafeKey(key, path)
    const desc = Object.getOwnPropertyDescriptor(value, key)
    if (!desc || !desc.enumerable) continue
    out[key] = value[key]
  }
  return out
}

export function ownEntries(value: Record<string, unknown>): Array<[string, unknown]> {
  return Object.keys(value).map((key) => [key, value[key]] as [string, unknown])
}

export function hasOwn(value: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key)
}
