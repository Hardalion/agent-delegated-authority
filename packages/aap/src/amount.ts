/**
 * Amount domain for ADAP authority limits.
 *
 * Representation: non-negative safe integer minor units (for example cents).
 * Sign: amounts and max_* limits must be >= 0.
 * Precision: integers only; fractional JSON numbers are rejected (no silent coercion).
 * Range: Number.MIN_SAFE_INTEGER..Number.MAX_SAFE_INTEGER, constrained to >= 0.
 * Overflow: values outside the safe-integer range are rejected.
 * Non-finite: NaN, +Infinity, -Infinity are rejected.
 * Zero: allowed (zero-value intents and zero caps).
 * Currency: orthogonal string constraint; see target/currency normalization in the spec.
 */

import { AuthorityError } from './errors.js'

export const AMOUNT_MIN = 0
export const AMOUNT_MAX = Number.MAX_SAFE_INTEGER

export function isCanonicalAmount(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isFinite(value) &&
    Number.isSafeInteger(value) &&
    value >= AMOUNT_MIN &&
    value <= AMOUNT_MAX
  )
}

/** Fail closed on any non-canonical numeric authority limit or spend amount. */
export function assertCanonicalAmount(value: unknown, path: string): number {
  if (typeof value !== 'number') {
    throw new AuthorityError('amount', `${path} must be a number (safe-integer minor units)`, true)
  }
  if (Number.isNaN(value)) {
    throw new AuthorityError('amount', `${path} must not be NaN`, true)
  }
  if (!Number.isFinite(value)) {
    throw new AuthorityError('amount', `${path} must be finite`, true)
  }
  if (!Number.isSafeInteger(value)) {
    throw new AuthorityError('amount', `${path} must be a safe integer (minor units)`, true)
  }
  if (value < AMOUNT_MIN) {
    throw new AuthorityError('amount', `${path} must be >= 0`, true)
  }
  return value
}

export function assertAmountWithinLimit(amount: unknown, limit: unknown, path = 'amount'): void {
  assertWithinCeiling(amount, limit, 'amount', 'max_amount', path)
}

/**
 * `max_<field>` governs `parameters.<field>`.
 * `max_amount` → `amount`, `max_quantity` → `quantity`, `max_records` → `records`.
 * The field name is a letter followed by letters, digits, or underscores.
 */
export function ceilingField(constraintKey: string): string | undefined {
  if (!constraintKey.startsWith('max_')) return undefined
  const field = constraintKey.slice(4)
  if (!/^[A-Za-z][A-Za-z0-9_]*$/.test(field)) return undefined
  return field
}

export function isMaxAmountKey(key: string): boolean {
  return ceilingField(key) !== undefined
}

/** Fail closed when a presented value is above a canonical numeric ceiling. */
export function assertWithinCeiling(
  presented: unknown,
  limit: unknown,
  field: string,
  constraintKey: string,
  presentedPath = `parameters.${field}`,
): void {
  const value = assertCanonicalAmount(presented, presentedPath)
  const bound = assertCanonicalAmount(limit, constraintKey)
  if (value > bound) {
    throw new AuthorityError('constraint', `${field} exceeds delegated ${constraintKey}`, true)
  }
}
