/**
 * Fault-injection against real PostgreSQL when ADAP_PG_URL / ADAP_PG_FORCE is set.
 */
import { describe, expect, it } from 'vitest'
import { AuthorityError, SharedNonceLedger } from 'adap'
import { createPool } from './pool.js'
import { applyMigrations } from './migrate.js'
import { PostgresAtomicNonceBackend } from './nonce-backend.js'
import { PostgresPendingStore } from './pending-store.js'
import { DEFAULT_PG_URL } from './harness.js'

const PG_URL = process.env.ADAP_PG_URL ?? DEFAULT_PG_URL
const RUN = process.env.ADAP_PG_URL != null || process.env.ADAP_PG_FORCE === '1'

describe.skipIf(!RUN)('PostgreSQL failure injection', () => {
  it('connection refusal fails closed (no silent success)', async () => {
    const pool = createPool({
      connectionString: 'postgresql://adap:adap@127.0.0.1:1/adap',
      connectionTimeoutMillis: 500,
    })
    const backend = new PostgresAtomicNonceBackend({ pool })
    await expect(
      backend.compareAndSwap('x', 0, { status: 'pending', intentHash: 'h', inFlight: false }),
    ).rejects.toBeTruthy()
    await pool.end().catch(() => undefined)
  })

  it('statement timeout surfaces as rejection', async () => {
    const setup = createPool({ connectionString: PG_URL })
    try {
      await applyMigrations(setup)
    } finally {
      await setup.end()
    }
    const pool = createPool({ connectionString: PG_URL, statementTimeoutMs: 200 })
    try {
      await expect(pool.query('SELECT pg_sleep(2)')).rejects.toThrow(/timeout|cancel/i)
    } finally {
      await pool.end()
    }
  })

  it('duplicate concurrent consume after claim is deterministic', async () => {
    const pool = createPool({ connectionString: PG_URL, max: 8 })
    try {
      await applyMigrations(pool)
      await pool.query('TRUNCATE adap_nonces')
      const ledger = new SharedNonceLedger(new PostgresAtomicNonceBackend({ pool }))
      await ledger.claimForExecution('dup', 'h')
      await ledger.consume('dup', 'h')
      await ledger.consume('dup', 'h') // idempotent consume
      await expect(ledger.claimForExecution('dup', 'h')).rejects.toBeInstanceOf(AuthorityError)
    } finally {
      await pool.end()
    }
  })

  it('pending markApproved is one-shot under concurrency', async () => {
    const pool = createPool({ connectionString: PG_URL, max: 8 })
    try {
      await applyMigrations(pool)
      await pool.query('TRUNCATE adap_pending')
      const store = new PostgresPendingStore({ pool })
      await store.put({
        nonce: 'appr',
        intentHash: 'ih',
        principalId: 'p',
        agentId: 'a',
        delegationChainHash: 'd',
        policyUri: 'u',
        policyContentHash: 'c',
        policyVersion: '1',
        policyName: 'n',
        matchedRuleId: 'r',
        originalDecision: 'REQUIRE_HUMAN',
        approvalState: 'pending',
        expiry: new Date(Date.now() + 60_000).toISOString(),
        approverId: 'approver',
      })
      const results = await Promise.allSettled([
        store.markApproved('appr', 'ih'),
        store.markApproved('appr', 'ih'),
      ])
      expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1)
      expect(results.filter((r) => r.status === 'rejected')).toHaveLength(1)
    } finally {
      await pool.end()
    }
  })
})
