import { assertCanonicalAmount } from './amount.js'
import { AuthorityError } from './errors.js'
import type { Constraints } from './protocol.js'
import { assertCanonicalCurrency } from './runtime-validate.js'
import { hasOwn } from './safe-object.js'

export const CUMULATIVE_MAX_AMOUNT = 'cumulative_max_amount'

export interface SpendCharge {
  readonly delegationId: string
  readonly intentHash: string
  readonly amount: number
  readonly ceiling: number
  readonly field: string
  /** Required for monetary `amount` pools. Other fields are not currency-scoped. */
  readonly currency?: string
}

/**
 * Shared spend for `cumulative_max_amount`. One call applies every charge or none.
 * The same `(delegationId, intentHash)` is idempotent when the amount matches.
 */
export interface SpendLedger {
  spend(charges: readonly SpendCharge[]): void | Promise<void>
}

interface SpendPool {
  readonly total: number
  readonly byIntent: Map<string, number>
}

function poolKey(charge: Pick<SpendCharge, 'delegationId' | 'field' | 'ceiling' | 'currency'>): string {
  const currency = charge.field === 'amount' ? (charge.currency ?? '') : ''
  return `${charge.delegationId}\0${charge.field}\0${currency}\0${charge.ceiling}`
}

export class MemorySpendLedger implements SpendLedger {
  private readonly pools = new Map<string, SpendPool>()

  spend(charges: readonly SpendCharge[]): void {
    const normalized = charges.map((charge) => {
      if (charge.field === 'amount' && (charge.currency == null || charge.currency.length === 0)) {
        throw new AuthorityError('constraint', 'currency is required for cumulative amount', true)
      }
      return {
        delegationId: charge.delegationId,
        intentHash: charge.intentHash,
        amount: assertCanonicalAmount(charge.amount, `parameters.${charge.field}`),
        ceiling: assertCanonicalAmount(charge.ceiling, charge.field === 'amount' ? CUMULATIVE_MAX_AMOUNT : `cumulative_${charge.field}`),
        field: charge.field,
        currency: charge.currency,
      }
    })
    const staged = new Map<string, SpendPool>()
    for (const [id, row] of this.pools) {
      staged.set(id, { total: row.total, byIntent: new Map(row.byIntent) })
    }
    for (const charge of normalized) {
      const key = poolKey(charge)
      const row = staged.get(key) ?? { total: 0, byIntent: new Map<string, number>() }
      const previous = row.byIntent.get(charge.intentHash)
      if (previous != null) {
        if (previous !== charge.amount) {
          throw new AuthorityError('constraint', 'cumulative spend for this intent changed', true)
        }
        staged.set(key, row)
        continue
      }
      if (row.total + charge.amount > charge.ceiling) {
        throw new AuthorityError('constraint', 'cumulative spend exceeds cumulative_max_amount', true)
      }
      const next: SpendPool = {
        total: row.total + charge.amount,
        byIntent: new Map(row.byIntent),
      }
      next.byIntent.set(charge.intentHash, charge.amount)
      staged.set(key, next)
    }
    this.pools.clear()
    for (const [id, row] of staged) this.pools.set(id, row)
  }

  spent(delegationId: string): number {
    let total = 0
    for (const [key, row] of this.pools) {
      if (key.startsWith(`${delegationId}\0`)) total += row.total
    }
    return total
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
      const currency = monetaryCurrency(field, delegation.constraints, input.parameters)
      charges.push({
        delegationId: delegation.delegation_id,
        intentHash: input.intentHash,
        amount: assertCanonicalAmount(raw, `parameters.${field}`),
        ceiling: assertCanonicalAmount(bound, key),
        field,
        currency,
      })
    }
  }
  return charges
}

function monetaryCurrency(
  field: string,
  constraints: Constraints,
  parameters: Readonly<Record<string, unknown>>,
): string | undefined {
  if (field !== 'amount') return undefined
  const granted = constraints.currency
  const presented = parameters.currency
  if (granted == null && presented == null) {
    throw new AuthorityError('constraint', 'currency is required for cumulative amount', true)
  }
  if (granted == null || presented == null) {
    throw new AuthorityError('constraint', 'currency is required for cumulative amount', true)
  }
  const expected = assertCanonicalCurrency(granted, 'constraints.currency')
  const actual = assertCanonicalCurrency(presented, 'parameters.currency')
  if (expected !== actual) {
    throw new AuthorityError('constraint', 'cumulative amount currency mismatch', true)
  }
  return expected
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
