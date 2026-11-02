/**
 * Detach security inputs from caller-owned objects.
 * The clone is the only value used after this returns. Nested objects and arrays
 * are new values. Cycles, accessors' later changes, and prototype objects do not
 * cross this boundary.
 */

import { AuthorityError } from './errors.js'
import { assertSafeKey, isPlainDataObject } from './safe-object.js'
import type { SignedDelegation, SignedIntent } from './protocol.js'

export function deepDataClone(value: unknown, path = 'value'): unknown {
  return cloneValue(value, path, new Set())
}

function cloneValue(value: unknown, path: string, seen: Set<object>): unknown {
  if (value === null) return null
  if (typeof value === 'string' || typeof value === 'boolean' || typeof value === 'number') return value
  if (typeof value !== 'object') {
    throw new AuthorityError('schema', `${path} has an unsupported type`, false)
  }
  const objectValue: object = value
  if (seen.has(objectValue)) {
    throw new AuthorityError('schema', `${path} contains a cycle`, false)
  }
  seen.add(objectValue)
  try {
    if (Array.isArray(objectValue)) {
      return objectValue.map((item, index) => cloneValue(item, `${path}[${index}]`, seen))
    }
    if (!isPlainDataObject(objectValue)) {
      throw new AuthorityError('schema', `${path} must be a plain data object`, false)
    }
    const out: Record<string, unknown> = Object.create(null)
    for (const key of Object.keys(objectValue)) {
      assertSafeKey(key, path)
      out[key] = cloneValue(objectValue[key], `${path}.${key}`, seen)
    }
    return out
  } finally {
    seen.delete(objectValue)
  }
}

export function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value)
    for (const key of Object.keys(value)) {
      deepFreeze((value as Record<string, unknown>)[key])
    }
  }
  return value
}

function requireSignature(record: Record<string, unknown>, path: string): void {
  if (typeof record.signature !== 'string' || record.signature.length === 0 || record.signature.length > 256) {
    throw new AuthorityError('schema', `${path}.signature is required`, false)
  }
}

/** Structural clone only. Amount domain and signature checks happen later. */
export function cloneSignedIntent(raw: unknown): SignedIntent {
  if (!isPlainDataObject(raw)) {
    throw new AuthorityError('schema', 'signed intent must be a plain object', false)
  }
  const clone = deepDataClone(raw, 'intent') as Record<string, unknown>
  requireSignature(clone, 'intent')
  return clone as unknown as SignedIntent
}

/** Structural clone only. Constraint amounts are checked after the signature verifies. */
export function cloneSignedDelegation(raw: unknown, path = 'delegation'): SignedDelegation {
  if (!isPlainDataObject(raw)) {
    throw new AuthorityError('schema', `${path} must be a plain object`, false)
  }
  const clone = deepDataClone(raw, path) as Record<string, unknown>
  requireSignature(clone, path)
  return clone as unknown as SignedDelegation
}
