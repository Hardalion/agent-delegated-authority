import {
  AuthorityError,
  assertCanonicalAmount,
  assertCanonicalCurrency,
  type SpendCharge,
  type SpendLedger,
} from 'adap'
import type { Pool, PoolClient } from './pool.js'

export interface PostgresSpendLedgerOptions {
  readonly pool: Pool
  /** Tenant namespace for spend pools. Default `default`. */
  readonly tenantId?: string
}

interface NormalizedCharge {
  readonly delegationId: string
  readonly field: string
  readonly currency: string
  readonly ceiling: number
  readonly amount: number
  readonly intentHash: string
}

const FIELD_PATTERN = /^[A-Za-z][A-Za-z0-9_]*$/

/**
 * Durable `SpendLedger` for cumulative constraints.
 *
 * One `spend(charges)` call is one transaction: every charge in the call is
 * applied, or none is. Pools are keyed like `MemorySpendLedger`:
 * `(delegation_id, field, currency, ceiling)`.
 *
 * Concurrency: each pool takes a transaction-scoped advisory lock before the
 * cumulative sum is read. Locks are acquired in sorted order so two calls that
 * touch the same set of pools cannot deadlock. Replicas sharing the database
 * therefore cannot collectively exceed a ceiling.
 *
 * Idempotency: a row is keyed by `(delegation_id, field, currency, intent_hash)`.
 * Replaying an intent inserts nothing. Reusing the same intent with a different
 * amount, or reusing a pool with a different ceiling, is rejected rather than
 * written to a second pool.
 *
 * Failed and unknown downstream outcomes leave the charge recorded. The
 * authority path charges before execution, so accounting is conservative: a
 * retried intent reuses the same charge, and an abandoned intent keeps its
 * budget consumed. A caller that wants to release budget must not do so through
 * this interface; the ledger never deletes rows.
 */
export class PostgresSpendLedger implements SpendLedger {
  private readonly pool: Pool
  private readonly tenantId: string

  constructor(options: PostgresSpendLedgerOptions) {
    this.pool = options.pool
    this.tenantId = options.tenantId ?? 'default'
  }

  async spend(charges: readonly SpendCharge[]): Promise<void> {
    const normalized = charges.map(normalizeCharge)
    if (normalized.length === 0) return

    const client = await this.pool.connect()
    try {
      await client.query('BEGIN')
      await lockPools(client, this.tenantId, normalized)
      for (const charge of normalized) {
        await this.applyCharge(client, charge)
      }
      await client.query('COMMIT')
    } catch (error) {
      try {
        await client.query('ROLLBACK')
      } catch {
        // ignore rollback errors; the original failure is what matters
      }
      throw error
    } finally {
      client.release()
    }
  }

  /** Total recorded spend for a delegation across every field and currency. */
  async spent(delegationId: string): Promise<number> {
    const { rows } = await this.pool.query<{ total: string }>(
      `SELECT COALESCE(SUM(amount), 0)::text AS total
       FROM adap_spend
       WHERE tenant_id = $1 AND delegation_id = $2`,
      [this.tenantId, delegationId],
    )
    return Number(rows[0]?.total ?? '0')
  }

  private async applyCharge(client: PoolClient, charge: NormalizedCharge): Promise<void> {
    const existing = await client.query<{ amount: string; ceiling: string }>(
      `SELECT amount::text AS amount, ceiling::text AS ceiling
       FROM adap_spend
       WHERE tenant_id = $1
         AND delegation_id = $2
         AND field = $3
         AND currency = $4
         AND intent_hash = $5
       FOR UPDATE`,
      [this.tenantId, charge.delegationId, charge.field, charge.currency, charge.intentHash],
    )
    const row = existing.rows[0]
    if (row) {
      if (Number(row.amount) !== charge.amount) {
        throw new AuthorityError('constraint', 'cumulative spend for this intent changed', true)
      }
      if (Number(row.ceiling) !== charge.ceiling) {
        throw new AuthorityError('constraint', 'cumulative spend pool ceiling changed', true)
      }
      return
    }

    const conflicting = await client.query(
      `SELECT 1 FROM adap_spend
       WHERE tenant_id = $1
         AND delegation_id = $2
         AND field = $3
         AND currency = $4
         AND ceiling <> $5
       LIMIT 1`,
      [this.tenantId, charge.delegationId, charge.field, charge.currency, charge.ceiling],
    )
    if ((conflicting.rowCount ?? 0) > 0) {
      throw new AuthorityError('constraint', 'cumulative spend pool ceiling changed', true)
    }

    const { rows } = await client.query<{ total: string }>(
      `SELECT COALESCE(SUM(amount), 0)::text AS total
       FROM adap_spend
       WHERE tenant_id = $1
         AND delegation_id = $2
         AND field = $3
         AND currency = $4
         AND ceiling = $5`,
      [this.tenantId, charge.delegationId, charge.field, charge.currency, charge.ceiling],
    )
    const total = Number(rows[0]?.total ?? '0')
    if (total + charge.amount > charge.ceiling) {
      throw new AuthorityError('constraint', 'cumulative spend exceeds cumulative_max_amount', true)
    }

    const inserted = await client.query(
      `INSERT INTO adap_spend
         (tenant_id, delegation_id, field, currency, ceiling, amount, intent_hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (tenant_id, delegation_id, field, currency, intent_hash) DO NOTHING
       RETURNING intent_hash`,
      [
        this.tenantId,
        charge.delegationId,
        charge.field,
        charge.currency,
        charge.ceiling,
        charge.amount,
        charge.intentHash,
      ],
    )
    if ((inserted.rowCount ?? 0) !== 1) {
      // A concurrent writer inserted the same key inside this transaction's
      // lock scope. Treat it as an unknown outcome and fail closed.
      throw new AuthorityError('constraint', 'cumulative spend write was not applied', true)
    }
  }
}

function normalizeCharge(charge: SpendCharge): NormalizedCharge {
  if (typeof charge.delegationId !== 'string' || charge.delegationId.length === 0) {
    throw new AuthorityError('constraint', 'spend delegation id is required', true)
  }
  if (typeof charge.intentHash !== 'string' || charge.intentHash.length === 0) {
    throw new AuthorityError('constraint', 'spend intent hash is required', true)
  }
  if (!FIELD_PATTERN.test(charge.field)) {
    throw new AuthorityError('constraint', 'spend field is not canonical', true)
  }
  const amount = assertCanonicalAmount(charge.amount, `parameters.${charge.field}`)
  const ceiling = assertCanonicalAmount(
    charge.ceiling,
    charge.field === 'amount' ? 'cumulative_max_amount' : `cumulative_${charge.field}`,
  )
  const currency =
    charge.field === 'amount'
      ? assertCanonicalCurrency(charge.currency, 'parameters.currency')
      : ''
  return {
    delegationId: charge.delegationId,
    field: charge.field,
    currency,
    ceiling,
    amount,
    intentHash: charge.intentHash,
  }
}

/**
 * Lock every pool touched by the call, in sorted order. The key deliberately
 * excludes the ceiling: a ceiling change must serialize against existing
 * charges so it can fail closed.
 */
async function lockPools(
  client: PoolClient,
  tenantId: string,
  charges: readonly NormalizedCharge[],
): Promise<void> {
  const keys = new Set<string>()
  for (const charge of charges) {
    keys.add(`${charge.delegationId}\u001f${charge.field}\u001f${charge.currency}`)
  }
  for (const key of [...keys].sort()) {
    await client.query(
      `SELECT pg_advisory_xact_lock(hashtextextended($1 || E'\\x1f' || $2, 0))`,
      [tenantId, key],
    )
  }
}
