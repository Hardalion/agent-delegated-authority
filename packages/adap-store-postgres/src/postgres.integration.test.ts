/**
 * Real PostgreSQL integration tests.
 * Requires ADAP_PG_URL or ADAP_PG_FORCE=1 (uses DEFAULT_PG_URL).
 *
 * These are NOT in-memory doubles. They exercise shared durable CAS.
 */

import { describe, expect, it } from 'vitest'
import {
  AuthorityError,
  SharedNonceLedger,
  FixedClock,
  createIdentity,
  signDelegation,
  signIntent,
  runAuthorityPath,
  ImmutablePolicyResolver,
  sha256,
} from 'adap'
import type { Policy } from 'adap-policy'
import { createPool } from './pool.js'
import { applyMigrations } from './migrate.js'
import { PostgresAtomicNonceBackend } from './nonce-backend.js'
import { PostgresPendingStore } from './pending-store.js'
import { PostgresPolicyRegistry } from './policy-registry.js'
import { DEFAULT_PG_URL } from './harness.js'

const PG_URL = process.env.ADAP_PG_URL ?? DEFAULT_PG_URL
const RUN = process.env.ADAP_PG_URL != null || process.env.ADAP_PG_FORCE === '1'

const NOW = new Date('2026-10-06T18:00:00.000Z')
const ISSUED = NOW.toISOString()
const EXPIRES = new Date(NOW.getTime() + 15 * 60 * 1000).toISOString()

const ALLOW_APPLY: Policy = {
  version: '1.0.0',
  policyName: 'allow-apply',
  targetAgents: ['*'],
  defaultAction: 'BLOCK',
  rules: [
    { ruleId: 'allow_apply', action: 'ALLOW', condition: "tool.name == 'apply'", alertSeverity: 'LOW' },
  ],
}
const ALLOW_URI = 'allow-apply@1.0.0'

async function freshPool() {
  const pool = createPool({ connectionString: PG_URL, max: 16 })
  await applyMigrations(pool)
  await pool.query(`TRUNCATE adap_nonces, adap_pending, adap_policies, adap_execution_log`)
  return pool
}

describe.skipIf(!RUN)('PostgreSQL atomic nonce backend (real DB)', () => {
  it('CAS insert: only one of two concurrent creators wins', async () => {
    const pool = await freshPool()
    try {
      const a = new PostgresAtomicNonceBackend({ pool, tenantId: 't1' })
      const b = new PostgresAtomicNonceBackend({ pool, tenantId: 't1' })
      const record = { status: 'pending' as const, intentHash: 'ih1', inFlight: false }
      const results = await Promise.all([
        a.compareAndSwap('n-race', 0, record),
        b.compareAndSwap('n-race', 0, record),
      ])
      expect(results.filter(Boolean)).toHaveLength(1)
      const row = await a.read('n-race')
      expect(row?.version).toBe(1)
      expect(row?.record.intentHash).toBe('ih1')
    } finally {
      await pool.end()
    }
  })

  it('CAS update: concurrent claim yields one winner', async () => {
    const pool = await freshPool()
    try {
      const backend = new PostgresAtomicNonceBackend({ pool })
      await backend.compareAndSwap('n-claim', 0, {
        status: 'pending',
        intentHash: 'ih2',
        inFlight: false,
      })
      const ledgerA = new SharedNonceLedger(new PostgresAtomicNonceBackend({ pool }))
      const ledgerB = new SharedNonceLedger(new PostgresAtomicNonceBackend({ pool }))
      const outcomes = await Promise.allSettled([
        ledgerA.claimForExecution('n-claim', 'ih2'),
        ledgerB.claimForExecution('n-claim', 'ih2'),
      ])
      const fulfilled = outcomes.filter((o) => o.status === 'fulfilled')
      const rejected = outcomes.filter((o) => o.status === 'rejected')
      expect(fulfilled).toHaveLength(1)
      expect(rejected).toHaveLength(1)
      const err = (rejected[0] as PromiseRejectedResult).reason
      expect(err).toBeInstanceOf(AuthorityError)
      expect((err as AuthorityError).message).toMatch(/nonce_in_flight_or_used|already used/)
      expect(await ledgerA.statusOf('n-claim')).toBe('pending')
      const row = await backend.read('n-claim')
      expect(row?.record.inFlight).toBe(true)
    } finally {
      await pool.end()
    }
  })

  it('consumed nonce survives process restart (new pool)', async () => {
    {
      const pool = await freshPool()
      try {
        const ledger = new SharedNonceLedger(new PostgresAtomicNonceBackend({ pool }))
        await ledger.claimForExecution('n-persist', 'ih3')
        await ledger.consume('n-persist', 'ih3')
      } finally {
        await pool.end()
      }
    }
    {
      const pool = createPool({ connectionString: PG_URL })
      try {
        const ledger = new SharedNonceLedger(new PostgresAtomicNonceBackend({ pool }))
        await expect(ledger.assertUsable('n-persist', 'ih3')).rejects.toBeInstanceOf(AuthorityError)
        expect(await ledger.statusOf('n-persist')).toBe('consumed')
      } finally {
        await pool.end()
      }
    }
  })

  it('pending approval survives restart and rejects mismatched continuation', async () => {
    const pool = await freshPool()
    try {
      const store = new PostgresPendingStore({ pool })
      const expiry = new Date(Date.now() + 60_000).toISOString()
      await store.put({
        nonce: 'p1',
        intentHash: 'ihp',
        principalId: 'prin',
        agentId: 'agent',
        delegationChainHash: 'dch',
        policyUri: 'pol://x',
        policyContentHash: 'pch',
        policyVersion: '1',
        policyName: 'n',
        matchedRuleId: 'r1',
        originalDecision: 'REQUIRE_HUMAN',
        approvalState: 'pending',
        expiry,
        approverId: 'approver',
      })
    } finally {
      await pool.end()
    }

    const pool2 = createPool({ connectionString: PG_URL })
    try {
      const store = new PostgresPendingStore({ pool: pool2 })
      const got = await store.get('p1')
      expect(got?.intentHash).toBe('ihp')
      expect(got?.approvalState).toBe('pending')
      await expect(
        store.requireContinuation({
          nonce: 'p1',
          intentHash: 'WRONG',
          principalId: 'prin',
          agentId: 'agent',
          delegationChainHash: 'dch',
          policyUri: 'pol://x',
          policyContentHash: 'pch',
          policyVersion: '1',
          policyName: 'n',
          approverId: 'approver',
          now: new Date(),
        }),
      ).rejects.toBeInstanceOf(AuthorityError)
      await store.markApproved('p1', 'ihp')
      await expect(store.markApproved('p1', 'ihp')).rejects.toBeInstanceOf(AuthorityError)
    } finally {
      await pool2.end()
    }
  })

  it('failed CAS leaves prior version intact', async () => {
    const pool = await freshPool()
    try {
      const backend = new PostgresAtomicNonceBackend({ pool })
      expect(
        await backend.compareAndSwap('n-rb', 0, {
          status: 'pending',
          intentHash: 'ih4',
          inFlight: false,
        }),
      ).toBe(true)
      expect(
        await backend.compareAndSwap('n-rb', 0, {
          status: 'pending',
          intentHash: 'ih4',
          inFlight: true,
        }),
      ).toBe(false)
      const row = await backend.read('n-rb')
      expect(row?.version).toBe(1)
      expect(row?.record.inFlight).toBe(false)
    } finally {
      await pool.end()
    }
  })

  it('DB errors fail closed: pool ended before CAS rejects', async () => {
    const pool = await freshPool()
    const backend = new PostgresAtomicNonceBackend({ pool })
    await pool.end()
    await expect(
      backend.compareAndSwap('n-dead', 0, {
        status: 'pending',
        intentHash: 'ih5',
        inFlight: false,
      }),
    ).rejects.toBeTruthy()
  })

  it('tenant isolation: same nonce different tenants do not collide', async () => {
    const pool = await freshPool()
    try {
      const a = new PostgresAtomicNonceBackend({ pool, tenantId: 'alpha' })
      const b = new PostgresAtomicNonceBackend({ pool, tenantId: 'beta' })
      expect(
        await a.compareAndSwap('shared-nonce', 0, {
          status: 'pending',
          intentHash: 'a',
          inFlight: false,
        }),
      ).toBe(true)
      expect(
        await b.compareAndSwap('shared-nonce', 0, {
          status: 'pending',
          intentHash: 'b',
          inFlight: false,
        }),
      ).toBe(true)
      expect((await a.read('shared-nonce'))?.record.intentHash).toBe('a')
      expect((await b.read('shared-nonce'))?.record.intentHash).toBe('b')
    } finally {
      await pool.end()
    }
  })

  it('multi-instance authority path: second execute of same intent is blocked', async () => {
    const pool = await freshPool()
    try {
      const principal = createIdentity('prn_example')
      const agent = createIdentity('agt_personal')
      const signer = createIdentity('reference-runtime')
      const directory = new Map<string, string>([
        [principal.id, principal.publicKey],
        [agent.id, agent.publicKey],
      ])
      const policyResolver = new ImmutablePolicyResolver()
      policyResolver.register(ALLOW_APPLY, ALLOW_URI)
      const root = signDelegation(
        {
          delegation_id: 'del_root',
          issuer: principal.id,
          subject: agent.id,
          capabilities: [{ action: 'apply', target: 'resource/*', delegable: false }],
          constraints: { max_amount: 800 },
          issued_at: ISSUED,
          expires_at: EXPIRES,
        },
        principal,
      )
      const intent = signIntent(
        {
          intent_id: 'int_multi',
          actor: agent.id,
          delegation_chain: [root.delegation_id],
          action: 'apply',
          target: 'resource/example',
          parameters: { amount: 10 },
          nonce: 'nonce-multi-instance',
          issued_at: ISSUED,
          expires_at: EXPIRES,
        },
        agent,
      )

      const run = async () => {
        const ledger = new SharedNonceLedger(new PostgresAtomicNonceBackend({ pool }))
        const pending = new PostgresPendingStore({ pool })
        return runAuthorityPath({
          chain: [root],
          intent,
          directory,
          trustedRootIssuers: [principal.id],
          policy: ALLOW_APPLY,
          policyUri: ALLOW_URI,
          ledger,
          signer,
          pendingStore: pending,
          policyResolver,
          clock: new FixedClock(NOW),
          execute: () => ({ ok: true }),
        })
      }

      const [r1, r2] = await Promise.all([run(), run()])
      const executedCount = [r1, r2].filter((r) => r.executed).length
      expect(executedCount).toBe(1)
      expect([r1, r2].some((r) => !r.executed)).toBe(true)
    } finally {
      await pool.end()
    }
  })

  it('policy registry: first hash wins and revoke blocks re-register', async () => {
    const pool = await freshPool()
    try {
      const reg = new PostgresPolicyRegistry({ pool })
      const pin = await reg.registerAsync(ALLOW_APPLY, ALLOW_URI)
      expect(pin.contentHash).toBe(sha256(ALLOW_APPLY))
      await expect(
        reg.registerAsync({ ...ALLOW_APPLY, version: '9.9.9' }, ALLOW_URI),
      ).rejects.toBeInstanceOf(AuthorityError)
      await reg.revokeByUri(ALLOW_URI)
      await expect(reg.registerAsync(ALLOW_APPLY, ALLOW_URI)).rejects.toBeInstanceOf(AuthorityError)
    } finally {
      await pool.end()
    }
  })
})

describe.skipIf(RUN)('PostgreSQL integration gate (NOT EXECUTED)', () => {
  it('documents that real PG tests were skipped', () => {
    expect(process.env.ADAP_PG_URL ?? process.env.ADAP_PG_FORCE).toBeUndefined()
  })
})
