import { AuthorityError } from './errors.js'

type NonceState = { readonly status: 'reserved' | 'consumed'; readonly intentHash: string }

/** Replay ledger. A nonce is reserved while a human decision is open, then consumed on a terminal outcome. */
export class NonceLedger {
  private readonly states = new Map<string, NonceState>()

  assertUsable(nonce: string, intentHash: string): 'fresh' | 'pending' {
    const state = this.states.get(nonce)
    if (!state) return 'fresh'
    if (state.status === 'consumed' || state.intentHash !== intentHash) {
      throw new AuthorityError('replay', 'nonce already used', true)
    }
    return 'pending'
  }

  reserve(nonce: string, intentHash: string): void {
    const state = this.states.get(nonce)
    if (!state) {
      this.states.set(nonce, { status: 'reserved', intentHash })
      return
    }
    if (state.intentHash !== intentHash || state.status === 'consumed') {
      throw new AuthorityError('replay', 'nonce already used', true)
    }
  }

  consume(nonce: string, intentHash: string): void {
    const state = this.states.get(nonce)
    if (state && state.intentHash !== intentHash) {
      throw new AuthorityError('replay', 'nonce already used', true)
    }
    this.states.set(nonce, { status: 'consumed', intentHash })
  }
}
