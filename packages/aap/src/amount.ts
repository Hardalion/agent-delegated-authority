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
  const a = assertCanonicalAmount(amount, path)
  const bound = assertCanonicalAmount(limit, 'max_amount')
  if (a > bound) {
    throw new AuthorityError('constraint', 'amount exceeds delegated max_amount', true)
  }
}

export function isMaxAmountKey(key: string): boolean {
  return key === 'max_amount' || (key.startsWith('max_') && key !== 'max_')
}
