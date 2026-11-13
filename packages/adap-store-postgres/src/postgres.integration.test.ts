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
      const record = {
        status: 'pending' as const,
        intentHash: 'ih1',
        inFlight: false,
        actorId: 'agt_a',
      }
      const results = await Promise.all([
        a.compareAndSwap('agt_a', 'n-race', 0, record),
        b.compareAndSwap('agt_a', 'n-race', 0, record),
      ])
      expect(results.filter(Boolean)).toHaveLength(1)
      const row = await a.read('agt_a', 'n-race')
      expect(row?.version).toBe(1)
      expect(row?.record.intentHash).toBe('ih1')
    } finally {
      await pool.end()
    }
  })

  it('blocks reuse of a legacy empty-actor tombstone for every actor (#20)', async () => {
    const pool = await freshPool()
    try {
      await pool.query(
        `INSERT INTO adap_nonces (tenant_id, actor_id, nonce, version, status, intent_hash, in_flight)
         VALUES ('default', '', 'legacy-tombstone', 1, 'consumed', 'ih-legacy', false)`,
      )
      const backend = new PostgresAtomicNonceBackend({ pool })
      const seen = await backend.read('agt_a', 'legacy-tombstone')
      expect(seen?.record.actorId).toBe('')
      expect(seen?.record.status).toBe('consumed')

      const ledger = new SharedNonceLedger(backend)
      await expect(ledger.assertUsable('agt_a', 'legacy-tombstone', 'ih-new')).rejects.toBeInstanceOf(
        AuthorityError,
      )
      await expect(ledger.assertUsable('agt_b', 'legacy-tombstone', 'ih-new')).rejects.toBeInstanceOf(
        AuthorityError,
      )
      await expect(
        ledger.claimForExecution('agt_a', 'legacy-tombstone', 'ih-new'),
      ).rejects.toBeInstanceOf(AuthorityError)
      await expect(
        ledger.claimForExecution('agt_b', 'legacy-tombstone', 'ih-new'),
      ).rejects.toBeInstanceOf(AuthorityError)

      expect(
        await backend.compareAndSwap('agt_a', 'legacy-tombstone', 0, {
          status: 'pending',
          intentHash: 'ih-new',
          inFlight: true,
          actorId: 'agt_a',
        }),
      ).toBe(false)
      expect(
        await backend.compareAndSwap('agt_b', 'legacy-tombstone', 0, {
          status: 'pending',
          intentHash: 'ih-new',
          inFlight: true,
          actorId: 'agt_b',
        }),
      ).toBe(false)

      const { rows } = await pool.query(
        `SELECT actor_id FROM adap_nonces WHERE nonce = 'legacy-tombstone' ORDER BY actor_id`,
      )
      expect(rows).toHaveLength(1)
      expect(rows[0]?.actor_id).toBe('')

      // A different nonce still works for either actor.
      expect(
        await backend.compareAndSwap('agt_a', 'fresh-after-tombstone', 0, {
          status: 'pending',
          intentHash: 'ih-fresh',
          inFlight: false,
          actorId: 'agt_a',
        }),
      ).toBe(true)
      expect(
        await backend.compareAndSwap('agt_b', 'fresh-after-tombstone', 0, {
          status: 'pending',
          intentHash: 'ih-fresh-b',
          inFlight: false,
          actorId: 'agt_b',
        }),
      ).toBe(true)
    } finally {
      await pool.end()
    }
  })

  it('concurrent inserts against a legacy tombstone all fail closed (#20)', async () => {
    const pool = await freshPool()
    try {
      await pool.query(
        `INSERT INTO adap_nonces (tenant_id, actor_id, nonce, version, status, intent_hash, in_flight)
         VALUES ('default', '', 'race-tombstone', 1, 'failed', 'ih-race', false)`,
      )
      const a = new PostgresAtomicNonceBackend({ pool })
      const b = new PostgresAtomicNonceBackend({ pool })
      const results = await Promise.all([
        a.compareAndSwap('agt_a', 'race-tombstone', 0, {
          status: 'pending',
          intentHash: 'a',
          inFlight: true,
          actorId: 'agt_a',
        }),
        b.compareAndSwap('agt_b', 'race-tombstone', 0, {
          status: 'pending',
          intentHash: 'b',
          inFlight: true,
          actorId: 'agt_b',
        }),
      ])
      expect(results.every((ok) => ok === false)).toBe(true)
      const { rows } = await pool.query(
        `SELECT actor_id FROM adap_nonces WHERE nonce = 'race-tombstone'`,
      )
      expect(rows).toHaveLength(1)
      expect(rows[0]?.actor_id).toBe('')
    } finally {
      await pool.end()
    }
  })

  it('isolates the same nonce string across actors (#20)', async () => {
    const pool = await freshPool()
    try {
      const backend = new PostgresAtomicNonceBackend({ pool })
      expect(
        await backend.compareAndSwap('agt_a', 'shared', 0, {
          status: 'pending',
          intentHash: 'a',
          inFlight: false,
          actorId: 'agt_a',
        }),
      ).toBe(true)
      expect(
        await backend.compareAndSwap('agt_b', 'shared', 0, {
          status: 'pending',
          intentHash: 'b',
          inFlight: false,
          actorId: 'agt_b',
        }),
      ).toBe(true)
      expect((await backend.read('agt_a', 'shared'))?.record.intentHash).toBe('a')
      expect((await backend.read('agt_b', 'shared'))?.record.intentHash).toBe('b')
      const ledger = new SharedNonceLedger(backend)
      await ledger.consume('agt_a', 'shared', 'a')
      expect(await ledger.statusOf('agt_a', 'shared')).toBe('consumed')
      expect(await ledger.assertUsable('agt_b', 'shared', 'b')).toBe('pending')
    } finally {
      await pool.end()
    }
  })

  it('CAS update: concurrent claim yields one winner', async () => {
    const pool = await freshPool()
    try {
      const backend = new PostgresAtomicNonceBackend({ pool })
      await backend.compareAndSwap('agt_a', 'n-claim', 0, { status: 'pending', intentHash: 'ih2', inFlight: false, actorId: 'agt_a' })
      const ledgerA = new SharedNonceLedger(new PostgresAtomicNonceBackend({ pool }))
      const ledgerB = new SharedNonceLedger(new PostgresAtomicNonceBackend({ pool }))
      const outcomes = await Promise.allSettled([
        ledgerA.claimForExecution('agt_a', 'n-claim', 'ih2'),
        ledgerB.claimForExecution('agt_a', 'n-claim', 'ih2'),
      ])
      const fulfilled = outcomes.filter((o) => o.status === 'fulfilled')
      const rejected = outcomes.filter((o) => o.status === 'rejected')
      expect(fulfilled).toHaveLength(1)
      expect(rejected).toHaveLength(1)
      const err = (rejected[0] as PromiseRejectedResult).reason
      expect(err).toBeInstanceOf(AuthorityError)
      expect((err as AuthorityError).message).toMatch(/nonce_in_flight_or_used|already used/)
      expect(await ledgerA.statusOf('agt_a', 'n-claim')).toBe('pending')
      const row = await backend.read('agt_a', 'n-claim')
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
        await ledger.claimForExecution('agt_a', 'n-persist', 'ih3')
        await ledger.consume('agt_a', 'n-persist', 'ih3')
      } finally {
        await pool.end()
      }
    }
    {
      const pool = createPool({ connectionString: PG_URL })
      try {
        const ledger = new SharedNonceLedger(new PostgresAtomicNonceBackend({ pool }))
        await expect(ledger.assertUsable('agt_a', 'n-persist', 'ih3')).rejects.toBeInstanceOf(AuthorityError)
        expect(await ledger.statusOf('agt_a', 'n-persist')).toBe('consumed')
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
      const got = await store.get('agent', 'p1')
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
      await store.markApproved('agent', 'p1', 'ihp')
      await expect(store.markApproved('agent', 'p1', 'ihp')).rejects.toBeInstanceOf(AuthorityError)
    } finally {
      await pool2.end()
    }
  })

  it('failed CAS leaves prior version intact', async () => {
    const pool = await freshPool()
    try {
      const backend = new PostgresAtomicNonceBackend({ pool })
      expect(
        await backend.compareAndSwap('agt_a', 'n-rb', 0, { status: 'pending', intentHash: 'ih4', inFlight: false, actorId: 'agt_a' }),
      ).toBe(true)
      expect(
        await backend.compareAndSwap('agt_a', 'n-rb', 0, { status: 'pending', intentHash: 'ih4', inFlight: true, actorId: 'agt_a' }),
      ).toBe(false)
      const row = await backend.read('agt_a', 'n-rb')
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
      backend.compareAndSwap('agt_a', 'n-dead', 0, { status: 'pending', intentHash: 'ih5', inFlight: false, actorId: 'agt_a' }),
    ).rejects.toBeTruthy()
  })

  it('tenant isolation: same nonce different tenants do not collide', async () => {
    const pool = await freshPool()
    try {
      const a = new PostgresAtomicNonceBackend({ pool, tenantId: 'alpha' })
      const b = new PostgresAtomicNonceBackend({ pool, tenantId: 'beta' })
      expect(
        await a.compareAndSwap('agt_a', 'shared-nonce', 0, { status: 'pending', intentHash: 'a', inFlight: false, actorId: 'agt_a' }),
      ).toBe(true)
      expect(
        await b.compareAndSwap('agt_a', 'shared-nonce', 0, { status: 'pending', intentHash: 'b', inFlight: false, actorId: 'agt_a' }),
      ).toBe(true)
      expect((await a.read('agt_a', 'shared-nonce'))?.record.intentHash).toBe('a')
      expect((await b.read('agt_a', 'shared-nonce'))?.record.intentHash).toBe('b')
    } finally {
      await pool.end()
    }
  })

  it('enforces pending approval queue cap under concurrent puts (#21)', async () => {
    const pool = await freshPool()
    try {
      const store = new PostgresPendingStore({ pool, maxPendingApprovals: 2 })
      const expiry = new Date(Date.now() + 60_000).toISOString()
      const base = {
        intentHash: 'ih',
        principalId: 'prin',
        agentId: 'agent',
        delegationChainHash: 'dch',
        policyUri: 'pol://x',
        policyContentHash: 'pch',
        policyVersion: '1',
        policyName: 'n',
        matchedRuleId: 'r1',
        originalDecision: 'REQUIRE_HUMAN' as const,
        approvalState: 'pending' as const,
        expiry,
        approverId: 'approver',
      }
      const results = await Promise.allSettled(
        [1, 2, 3, 4].map((n) =>
          store.put({ ...base, nonce: `q${n}`, intentHash: `ih${n}`, agentId: 'agent' }),
        ),
      )
      const ok = results.filter((r) => r.status === 'fulfilled')
      const blocked = results.filter((r) => r.status === 'rejected')
      expect(ok).toHaveLength(2)
      expect(blocked).toHaveLength(2)
      for (const r of blocked) {
        expect((r as PromiseRejectedResult).reason).toBeInstanceOf(AuthorityError)
        expect(((r as PromiseRejectedResult).reason as AuthorityError).code).toBe('approval_queue_full')
      }
      expect(await store.countActivePending?.('prin', 'agent')).toBe(2)
      // Different agent under same principal has an independent quota.
      await store.put({ ...base, nonce: 'other', agentId: 'agent-b', intentHash: 'ih-other' })
      expect(await store.get('agent-b', 'other')).toBeTruthy()
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
