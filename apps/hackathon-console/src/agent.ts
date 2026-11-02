import { signIntent, type Identity, type SignedIntent } from 'adap'

/**
 * Deterministic treasury agent.
 * Holds a signing key only. It cannot see the simulated rail or the broker capability.
 */
export class TreasuryAgent {
  readonly id: string
  readonly #identity: Identity
  readonly #delegationId: string

  constructor(identity: Identity, delegationId: string) {
    this.id = identity.id
    this.#identity = identity
    this.#delegationId = delegationId
  }

  propose(input: {
    readonly intentId: string
    readonly nonce: string
    readonly action: string
    readonly target: string
    readonly parameters: Readonly<Record<string, string | number | boolean>>
    readonly issuedAt: string
    readonly expiresAt: string
    readonly delegationId?: string
  }): SignedIntent {
    return signIntent(
      {
        intent_id: input.intentId,
        actor: this.id,
        delegation_chain: [input.delegationId ?? this.#delegationId],
        action: input.action,
        target: input.target,
        parameters: input.parameters,
        nonce: input.nonce,
        issued_at: input.issuedAt,
        expires_at: input.expiresAt,
      },
      this.#identity,
    )
  }
}
