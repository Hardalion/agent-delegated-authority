import { AuthorityError } from './errors.js'

/**
 * Trusted runtime clock.
 *
 * Authorization expiry uses this clock and no other timestamp. A `now` field on
 * the authority-path input is rejected. Tests inject `FixedClock`. Production
 * uses `systemClock` (the gateway process clock) unless the operator supplies
 * a clock it controls.
 *
 * Skew: the default is zero. An instant is valid when
 * `issued_at <= now < expires_at`. Operators may set `issuedAtSkewMs` up to
 * `MAX_ISSUED_AT_SKEW_MS`. That tolerance applies only to `issued_at`
 * (`issued_at <= now + skew`). `expires_at` is never extended.
 * A grant or intent whose lifetime is longer than `MAX_AUTHORITY_LIFETIME_MS`
 * is rejected. This package does not read agent request bodies for time.
 */

export const MAX_ISSUED_AT_SKEW_MS = 5 * 60 * 1000
export const MAX_AUTHORITY_LIFETIME_MS = 24 * 60 * 60 * 1000

export interface Clock {
  readonly now: () => Date
}

export const systemClock: Clock = {
  now: () => new Date(),
}

export class FixedClock implements Clock {
  constructor(private readonly instant: Date) {
    if (!(instant instanceof Date) || Number.isNaN(instant.getTime())) {
      throw new Error('FixedClock requires a valid Date')
    }
  }

  now(): Date {
    return new Date(this.instant.getTime())
  }
}

/** Resolve the trusted evaluation instant. Caller-supplied `now` is not a clock. */
export function resolveTrustedNow(input: {
  readonly clock?: Clock
  readonly now?: unknown
}): Date {
  if (input.now != null) {
    throw new AuthorityError(
      'clock',
      'caller-supplied now is rejected; authorization time comes from a trusted Clock',
      false
    )
  }
  const clock = input.clock ?? systemClock
  let instant: Date
  try {
    instant = clock.now()
  } catch {
    throw new AuthorityError('clock', 'trusted clock failed', false)
  }
  if (!(instant instanceof Date) || Number.isNaN(instant.getTime())) {
    throw new AuthorityError('clock', 'trusted clock returned an invalid instant', false)
  }
  return new Date(instant.getTime())
}
