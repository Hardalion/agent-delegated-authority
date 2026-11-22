import { assertCanonicalAmount } from './amount.js'
import { AuthorityError } from './errors.js'
import type { Constraints } from './protocol.js'
import { hasOwn } from './safe-object.js'

export const CUMULATIVE_MAX_AMOUNT = 'cumulative_max_amount'

export interface SpendCharge {
  readonly delegationId: string
  readonly intentHash: string
  readonly amount: number
  readonly ceiling: number
}

/**
 * Shared spend for `cumulative_max_amount`. One call applies every charge or none.
 * The same `(delegationId, intentHash)` is idempotent when the amount matches.
 */
export interface SpendLedger {
  spend(charges: readonly SpendCharge[]): void | Promise<void>
}

export class MemorySpendLedger implements SpendLedger {
  private readonly byDelegation = new Map<string, { total: number; byIntent: Map<string, number> }>()

  spend(charges: readonly SpendCharge[]): void {
    const normalized = charges.map((charge) => ({
      delegationId: charge.delegationId,
      intentHash: charge.intentHash,
      amount: assertCanonicalAmount(charge.amount, 'parameters.amount'),
      ceiling: assertCanonicalAmount(charge.ceiling, CUMULATIVE_MAX_AMOUNT),
    }))
    const staged = new Map<string, { total: number; byIntent: Map<string, number> }>()
    for (const [id, row] of this.byDelegation) {
      staged.set(id, { total: row.total, byIntent: new Map(row.byIntent) })
    }
    for (const charge of normalized) {
      const row = staged.get(charge.delegationId) ?? { total: 0, byIntent: new Map<string, number>() }
      const previous = row.byIntent.get(charge.intentHash)
      if (previous != null) {
        if (previous !== charge.amount) {
          throw new AuthorityError('constraint', 'cumulative spend for this intent changed', true)
        }
        staged.set(charge.delegationId, row)
        continue
      }
      if (row.total + charge.amount > charge.ceiling) {
        throw new AuthorityError('constraint', 'cumulative spend exceeds cumulative_max_amount', true)
      }
      row.total += charge.amount
      row.byIntent.set(charge.intentHash, charge.amount)
      staged.set(charge.delegationId, row)
    }
    this.byDelegation.clear()
    for (const [id, row] of staged) this.byDelegation.set(id, row)
  }

  spent(delegationId: string): number {
    return this.byDelegation.get(delegationId)?.total ?? 0
  }
}

export function cumulativeCharges(input: {
  readonly chain: readonly { readonly delegation_id: string; readonly constraints: Constraints }[]
  readonly parameters: Readonly<Record<string, unknown>>
  readonly intentHash: string
}): SpendCharge[] {
  const charges: SpendCharge[] = []
  for (const delegation of input.chain) {
    for (const [key, bound] of Object.entries(delegation.constraints)) {
      const field = cumulativeField(key)
      if (!field) continue
      const raw = hasOwn(input.parameters, field) ? input.parameters[field] : 0
      charges.push({
        delegationId: delegation.delegation_id,
        intentHash: input.intentHash,
        amount: assertCanonicalAmount(raw, `parameters.${field}`),
        ceiling: assertCanonicalAmount(bound, key),
      })
    }
  }
  return charges
}

function cumulativeField(key: string): string | undefined {
  if (key === CUMULATIVE_MAX_AMOUNT) return 'amount'
  if (!key.startsWith('cumulative_')) return undefined
  const field = key.slice('cumulative_'.length)
  if (!/^[A-Za-z][A-Za-z0-9_]*$/.test(field) || field.startsWith('max_')) return undefined
  return field
}

export async function chargeCumulativeSpend(input: {
  readonly chain: readonly { readonly delegation_id: string; readonly constraints: Constraints }[]
  readonly parameters: Readonly<Record<string, unknown>>
  readonly intentHash: string
  readonly ledger?: SpendLedger
}): Promise<void> {
  const charges = cumulativeCharges(input)
  if (charges.length === 0) return
  if (!input.ledger) {
    throw new AuthorityError('constraint', 'cumulative spend ledger is required', false)
  }
  await input.ledger.spend(charges)
}
