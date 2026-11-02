const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

/** Canonical JSON for content-addressed policy hashes. Rejects dangerous keys. */
export function canonicalJsonStringify(value: unknown): string {
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
    return { ...sorted }
  }
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new Error('canonicalJson rejects non-finite numbers')
  }
  return value
}
