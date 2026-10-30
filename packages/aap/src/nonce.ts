import { AuthorityError } from './errors.js'

/**
 * Nonce state machine for single-use intents.
 *
 * - `pending` — reserved for human approval, or exclusively claimed for execution
 * - `consumed` — terminal success (or a terminal BLOCK that retires the nonce)
 * - `failed` — executor threw; nonce is spent and cannot be retried with the same intent
 *
 * Claiming for execution is synchronous and exclusive. A second caller that sees
 * `pending` (including an in-flight claim) is `BLOCK` with `nonce_in_flight_or_used`.
 * Durable multi-process stores must preserve the same exclusive claim semantics.
 */
export type NonceStatus = 'pending' | 'consumed' | 'failed'

type NonceState = {
  readonly status: NonceStatus
  readonly intentHash: string
  /** True once this nonce is exclusively claimed for the executor. */
  readonly inFlight: boolean
}

export class NonceLedger {
  private readonly states = new Map<string, NonceState>()

  has(nonce: string): boolean {
    return this.states.has(nonce)
  }

  statusOf(nonce: string): NonceStatus | undefined {
    return this.states.get(nonce)?.status
  }

  /**
   * Returns whether the nonce may continue on the authority path.
   * `fresh` — never seen. `pending` — waiting on human (not yet in flight).
   * Throws when the nonce is in flight, consumed, failed, or bound to another intent.
   */
  assertUsable(nonce: string, intentHash: string): 'fresh' | 'pending' {
    const state = this.states.get(nonce)
    if (!state) return 'fresh'
    if (state.intentHash !== intentHash) {
      throw new AuthorityError('replay', 'nonce already used', true)
    }
    if (state.status === 'consumed' || state.status === 'failed') {
      throw new AuthorityError('replay', 'nonce already used', true)
    }
    if (state.inFlight) {
      throw new AuthorityError('replay', 'nonce_in_flight_or_used', true)
    }
    return 'pending'
  }

  /** Reserve while a human decision is open. Does not claim the executor. */
  reserve(nonce: string, intentHash: string): void {
    const state = this.states.get(nonce)
    if (!state) {
      this.states.set(nonce, { status: 'pending', intentHash, inFlight: false })
      return
    }
    if (state.intentHash !== intentHash || state.status !== 'pending' || state.inFlight) {
      throw new AuthorityError('replay', 'nonce_in_flight_or_used', true)
    }
  }

  /**
   * Exclusive claim before `await execution()`.
   * If the nonce is already present and in flight, consumed, or failed → BLOCK.
   * A prior human-wait `pending` with the same intentHash may be claimed once.
   */
  claimForExecution(nonce: string, intentHash: string): void {
    const state = this.states.get(nonce)
    if (!state) {
      this.states.set(nonce, { status: 'pending', intentHash, inFlight: true })
      return
    }
    if (state.intentHash !== intentHash) {
      throw new AuthorityError('replay', 'nonce already used', true)
    }
    if (state.status === 'consumed' || state.status === 'failed' || state.inFlight) {
      throw new AuthorityError('replay', 'nonce_in_flight_or_used', true)
    }
    // Human-wait pending → exclusive execution claim
    this.states.set(nonce, { status: 'pending', intentHash, inFlight: true })
  }

  consume(nonce: string, intentHash: string): void {
    const state = this.states.get(nonce)
    if (state && state.intentHash !== intentHash) {
      throw new AuthorityError('replay', 'nonce already used', true)
    }
    this.states.set(nonce, { status: 'consumed', intentHash, inFlight: false })
  }

  fail(nonce: string, intentHash: string): void {
    const state = this.states.get(nonce)
    if (state && state.intentHash !== intentHash) {
      throw new AuthorityError('replay', 'nonce already used', true)
    }
    this.states.set(nonce, { status: 'failed', intentHash, inFlight: false })
  }
}
