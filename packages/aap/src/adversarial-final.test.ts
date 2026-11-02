/**
 * Dedicated adversarial suite for the final hardening pass.
 * Each case names the invariant it protects.
 */
import { describe, expect, it } from 'vitest'
import type { Policy } from 'adap-policy'
import { evaluateToolCall } from 'adap-policy'
import { FixedClock } from './clock.js'
import { importPublicKey, sha256 } from './crypto.js'
import {
  MemoryAtomicNonceBackend,
  SharedNonceLedger,
  type AsyncAtomicNonceBackend,
  type NonceRecord,
  type VersionedNonceRecord,
} from './nonce.js'
import { PendingAuthorizationStore } from './pending.js'
import { ImmutablePolicyResolver } from './policy-resolver.js'
import {
  authenticatedReceipt,
  ExecutionNotDispatchedError,
  runAuthorityPath,
  verifyProtocolReceipt,
} from './path.js'
import {
  createIdentity,
  signApproval,
  signDelegation,
  signIntent,
  unsignedDelegation,
  unsignedIntent,
} from './protocol.js'
import { assertCanonicalTarget } from './runtime-validate.js'

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

class SharedMemoryBackend implements AsyncAtomicNonceBackend {
  private readonly rows = new Map<string, { version: number; record: NonceRecord }>()
  beforeCompareAndSwap?: () => Promise<void> | void
  private hookUsed = false

  async read(nonce: string): Promise<VersionedNonceRecord | undefined> {
    const row = this.rows.get(nonce)
    return row ? { version: row.version, record: row.record } : undefined
  }

  async compareAndSwap(nonce: string, expectedVersion: number, record: NonceRecord): Promise<boolean> {
    if (this.beforeCompareAndSwap && !this.hookUsed) {
      this.hookUsed = true
      const hook = this.beforeCompareAndSwap
      this.beforeCompareAndSwap = undefined
      await hook()
    }
    const row = this.rows.get(nonce)
    const version = row?.version ?? 0
    if (version !== expectedVersion) return false
    this.rows.set(nonce, { version: version + 1, record })
    return true
  }
}

function world() {
  const principal = createIdentity('prn_example')
  const agent = createIdentity('agt_personal')
  const signer = createIdentity('reference-runtime')
  const directory = new Map([
    [principal.id, principal.publicKey],
    [agent.id, agent.publicKey],
  ])
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
    principal
  )
  const policyResolver = new ImmutablePolicyResolver()
  policyResolver.register(ALLOW_APPLY, ALLOW_URI)
  return { principal, agent, signer, directory, root, policyResolver }
}

function intent(agent: ReturnType<typeof createIdentity>, root: ReturnType<typeof signDelegation>, nonce: string, parameters: Record<string, unknown> = { amount: 10 }) {
  return signIntent(
    {
      intent_id: `int_${nonce}`,
      actor: agent.id,
      delegation_chain: [root.delegation_id],
      action: 'apply',
      target: 'resource/example',
      parameters,
      nonce,
      issued_at: ISSUED,
      expires_at: EXPIRES,
    },
    agent
  )
}

describe('shared nonce adapter', () => {
  it('lets only one SharedNonceLedger claim win across a scripted async race', async () => {
    const backend = new SharedMemoryBackend()
    const first = new SharedNonceLedger(backend)
    const second = new SharedNonceLedger(backend)
    backend.beforeCompareAndSwap = async () => {
      await second.claimForExecution('shared-async', 'hash-1')
    }
    await expect(first.claimForExecution('shared-async', 'hash-1')).rejects.toThrow(/nonce_in_flight_or_used/)
    expect(await second.statusOf('shared-async')).toBe('pending')
    await expect(second.claimForExecution('shared-async', 'hash-1')).rejects.toThrow(/nonce_in_flight_or_used/)
  })

  it('does not coordinate two process-local MemoryAtomicNonceBackend instances', () => {
    const left = new MemoryAtomicNonceBackend()
    const right = new MemoryAtomicNonceBackend()
    expect(left.compareAndSwap('split', 0, { status: 'pending', intentHash: 'h', inFlight: true })).toBe(true)
    expect(right.compareAndSwap('split', 0, { status: 'pending', intentHash: 'h', inFlight: true })).toBe(true)
  })
})

describe('executor boundary', () => {
  it('reports executed false when the callback throws, and refuses the retry', async () => {
    const env = world()
    const ledger = new SharedNonceLedger(new SharedMemoryBackend())
    const signed = intent(env.agent, env.root, 'exec-throw')
    let calls = 0
    const failed = await runAuthorityPath({
      chain: [env.root],
      intent: signed,
      directory: env.directory,
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      clock: new FixedClock(NOW),
      ledger,
      policyResolver: env.policyResolver,
      signer: env.signer,
      execute: () => {
        calls += 1
        throw new Error('downstream failed after a partial write')
      },
    })
    expect(failed.decision).toBe('ALLOW')
    expect(failed.executed).toBe(false)
    expect(failed.executionKnowledge).toBe('unknown')
    expect(failed.receipt?.execution?.outcome).toBe('unknown')
    expect(failed.reason).not.toMatch(/nothing is recorded/)
    expect(failed.ruleId).toBe('execution')
    expect(await ledger.statusOf(signed.nonce)).toBe('failed')
    const retry = await runAuthorityPath({
      chain: [env.root],
      intent: signed,
      directory: env.directory,
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      clock: new FixedClock(NOW),
      ledger,
      policyResolver: env.policyResolver,
      signer: env.signer,
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(retry.decision).toBe('BLOCK')
    expect(retry.executionKnowledge).toBe('not_dispatched')
    expect(retry.ruleId).toBe('replay')
    expect(retry.executed).toBe(false)
    expect(retry.receipt?.execution?.outcome).toBe('not_dispatched')
    expect(calls).toBe(1)
  })

  it('records unknown after a side effect followed by timeout or cancellation', async () => {
    const env = world()
    const ledger = new SharedNonceLedger(new SharedMemoryBackend())
    const signed = intent(env.agent, env.root, 'exec-timeout')
    const effects: string[] = []
    const failed = await runAuthorityPath({
      chain: [env.root],
      intent: signed,
      directory: env.directory,
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      clock: new FixedClock(NOW),
      ledger,
      policyResolver: env.policyResolver,
      signer: env.signer,
      execute: async () => {
        effects.push('posted')
        throw new DOMException('The operation was aborted', 'AbortError')
      },
    })
    expect(effects).toEqual(['posted'])
    expect(failed.decision).toBe('ALLOW')
    expect(failed.executed).toBe(false)
    expect(failed.executionKnowledge).toBe('unknown')
    expect(failed.receipt?.decision.action).toBe('ALLOW')
    expect(failed.receipt?.execution?.outcome).toBe('unknown')
    expect(failed.receipt?.execution?.executed).not.toBe(true)
  })

  it('keeps unknown when the nonce terminal write fails after dispatch', async () => {
    const env = world()
    const inner = new SharedNonceLedger(new SharedMemoryBackend())
    const ledger = {
      assertUsable: (nonce: unknown, intentHash: string) => inner.assertUsable(nonce, intentHash),
      reserve: (nonce: unknown, intentHash: string) => inner.reserve(nonce, intentHash),
      claimForExecution: (nonce: unknown, intentHash: string) => inner.claimForExecution(nonce, intentHash),
      consume: (nonce: unknown, intentHash: string) => inner.consume(nonce, intentHash),
      fail: () => {
        throw new Error('store outage')
      },
    }
    const signed = intent(env.agent, env.root, 'exec-fail-store')
    const failed = await runAuthorityPath({
      chain: [env.root],
      intent: signed,
      directory: env.directory,
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      clock: new FixedClock(NOW),
      ledger,
      policyResolver: env.policyResolver,
      signer: env.signer,
      execute: () => {
        throw new Error('timed out after post')
      },
    })
    expect(failed.executionKnowledge).toBe('unknown')
    expect(failed.decision).toBe('ALLOW')
    expect(failed.executed).toBe(false)
    expect(failed.receipt?.execution?.outcome).toBe('unknown')
    expect(await inner.statusOf(signed.nonce)).toBe('pending')
    let retryCalls = 0
    const retry = await runAuthorityPath({
      chain: [env.root],
      intent: signed,
      directory: env.directory,
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      clock: new FixedClock(NOW),
      ledger: inner,
      policyResolver: env.policyResolver,
      signer: env.signer,
      execute: () => {
        retryCalls += 1
        return { ok: true }
      },
    })
    expect(retry.decision).toBe('BLOCK')
    expect(retry.ruleId).toBe('replay')
    expect(retry.executed).toBe(false)
    expect(retry.executionKnowledge).toBe('not_dispatched')
    expect(retryCalls).toBe(0)
  })

  it('keeps unknown when receipt signing fails after a side effect', async () => {
    const env = world()
    const ledger = new SharedNonceLedger(new SharedMemoryBackend())
    const signed = intent(env.agent, env.root, 'exec-seal-fail')
    const effects: string[] = []
    const failed = await runAuthorityPath({
      chain: [env.root],
      intent: signed,
      directory: env.directory,
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      clock: new FixedClock(NOW),
      ledger,
      policyResolver: env.policyResolver,
      signer: { ...env.signer, privateKey: {} as never },
      execute: () => {
        effects.push('posted')
        throw new Error('timed out after post')
      },
    })
    expect(effects).toEqual(['posted'])
    expect(failed.decision).toBe('ALLOW')
    expect(failed.executed).toBe(false)
    expect(failed.executionKnowledge).toBe('unknown')
    expect(failed.receipt).toBeUndefined()
    expect(await ledger.statusOf(signed.nonce)).toBe('failed')
    let retryCalls = 0
    const retry = await runAuthorityPath({
      chain: [env.root],
      intent: signed,
      directory: env.directory,
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      clock: new FixedClock(NOW),
      ledger,
      policyResolver: env.policyResolver,
      signer: env.signer,
      execute: () => {
        retryCalls += 1
        return { ok: true }
      },
    })
    expect(retry.decision).toBe('BLOCK')
    expect(retry.executed).toBe(false)
    expect(retryCalls).toBe(0)
  })

  it('records not_dispatched when the callback stops before the external call', async () => {
    const env = world()
    const ledger = new SharedNonceLedger(new SharedMemoryBackend())
    const signed = intent(env.agent, env.root, 'exec-not-dispatched')
    const failed = await runAuthorityPath({
      chain: [env.root],
      intent: signed,
      directory: env.directory,
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      clock: new FixedClock(NOW),
      ledger,
      policyResolver: env.policyResolver,
      signer: env.signer,
      execute: () => {
        throw new ExecutionNotDispatchedError('credential broker rejected the route')
      },
    })
    expect(failed.decision).toBe('ALLOW')
    expect(failed.executed).toBe(false)
    expect(failed.executionKnowledge).toBe('not_dispatched')
    expect(failed.receipt?.execution?.outcome).toBe('not_dispatched')
    expect(await ledger.statusOf(signed.nonce)).toBe('failed')
  })

  it('keeps executed true when the callback returned and seal later fails to hash the result', async () => {
    const env = world()
    const ledger = new SharedNonceLedger(new SharedMemoryBackend())
    const signed = intent(env.agent, env.root, 'exec-unhashable')
    const cycle: Record<string, unknown> = { ok: true }
    cycle.self = cycle
    const result = await runAuthorityPath({
      chain: [env.root],
      intent: signed,
      directory: env.directory,
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      clock: new FixedClock(NOW),
      ledger,
      policyResolver: env.policyResolver,
      signer: env.signer,
      execute: () => cycle,
    })
    expect(result.decision).toBe('ALLOW')
    expect(result.executed).toBe(true)
    expect(result.authenticated).toBe(true)
    expect(result.receipt).toBeUndefined()
    expect(result.executionHash).toBe('unhashable')
    expect(await ledger.statusOf(signed.nonce)).toBe('consumed')
  })
})

describe('policy resolver trust', () => {
  it('rejects a missing resolver instead of evaluating a caller document', async () => {
    const env = world()
    const result = await runAuthorityPath({
      chain: [env.root],
      intent: intent(env.agent, env.root, 'no-resolver'),
      directory: env.directory,
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      clock: new FixedClock(NOW),
      ledger: new SharedNonceLedger(new SharedMemoryBackend()),
      signer: env.signer,
      policyResolver: undefined as unknown as ImmutablePolicyResolver,
      execute: () => ({ ok: true }),
    })
    expect(result.decision).toBe('BLOCK')
    expect(result.authenticated).toBe(false)
    expect(result.ruleId).toBe('policy')
    expect(result.executed).toBe(false)
    expect(result.receipt).toBeUndefined()
  })
})

describe('approval binding on a fresh nonce', () => {
  it('blocks an approval presented with a mutated intent and a new nonce', async () => {
    const env = world()
    const human: Policy = {
      version: '1.0.0',
      policyName: 'human-apply',
      targetAgents: ['*'],
      defaultAction: 'BLOCK',
      rules: [
        {
          ruleId: 'needs_human',
          action: 'REQUIRE_HUMAN',
          condition: "tool.name == 'apply'",
          alertSeverity: 'MEDIUM',
        },
      ],
    }
    const uri = 'human-apply@1.0.0'
    env.policyResolver.register(human, uri)
    const pendingStore = new PendingAuthorizationStore()
    const ledger = new SharedNonceLedger(new SharedMemoryBackend())
    const original = intent(env.agent, env.root, 'approval-original', { amount: 10, note: 'example' })
    let calls = 0
    const pending = await runAuthorityPath({
      chain: [env.root],
      intent: original,
      directory: env.directory,
      policy: human,
      policyUri: uri,
      clock: new FixedClock(NOW),
      ledger,
      pendingStore,
      policyResolver: env.policyResolver,
      signer: env.signer,
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(pending.decision).toBe('REQUIRE_HUMAN')
    const mutated = intent(env.agent, env.root, 'approval-mutated', { amount: 20, note: 'example' })
    const blocked = await runAuthorityPath({
      chain: [env.root],
      intent: mutated,
      directory: env.directory,
      policy: human,
      policyUri: uri,
      clock: new FixedClock(NOW),
      ledger,
      pendingStore,
      policyResolver: env.policyResolver,
      signer: env.signer,
      approval: signApproval(
        {
          intent_hash: pending.intentHash,
          approver_id: env.principal.id,
          approved_at: ISSUED,
          decision: 'APPROVE',
          agent_id: env.agent.id,
          delegation_chain_hash: sha256([unsignedDelegation(env.root)]),
          policy_content_hash: pending.policyHash,
          matched_rule_id: pending.ruleId,
        },
        env.principal
      ),
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(blocked.decision).toBe('BLOCK')
    expect(blocked.executed).toBe(false)
    expect(blocked.reason).toMatch(/approval is not bound to this intent|no pending authorization/)
    expect(calls).toBe(0)
  })
})

describe('snapshot and receipt agreement', () => {
  it('keeps receipt args equal to the authorized snapshot after nested mutation', async () => {
    const env = world()
    const meta = { dest: 'legit' }
    const signed = intent(env.agent, env.root, 'snapshot-receipt', { amount: 10, meta })
    const authorized = sha256(unsignedIntent(signed))
    let release!: () => void
    const hold = new Promise<void>((resolve) => {
      release = resolve
    })
    let waiting!: () => void
    const waited = new Promise<void>((resolve) => {
      waiting = resolve
    })
    const pending = runAuthorityPath({
      chain: [env.root],
      intent: signed,
      directory: env.directory,
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      clock: new FixedClock(NOW),
      ledger: new SharedNonceLedger(new SharedMemoryBackend()),
      policyResolver: env.policyResolver,
      signer: env.signer,
      execute: async (ctx) => {
        waiting()
        await hold
        return { dest: (ctx.parameters.meta as { dest: string }).dest }
      },
    })
    await waited
    meta.dest = 'evil'
    release()
    const result = await pending
    expect(result.executed).toBe(true)
    expect(result.result).toEqual({ dest: 'legit' })
    const receipt = authenticatedReceipt(result)
    expect(receipt.intent.argsRedacted).toEqual({ amount: 10, meta: { dest: 'legit' } })
    expect(receipt.execution?.intentHash).toBe(authorized)
    expect(verifyProtocolReceipt(receipt, importPublicKey(env.signer.publicKey)).valid).toBe(true)
  })
})

describe('resource and identity fuzz', () => {
  it.each([
    'resource/.',
    'resource/..',
    'resource/./vault',
    'resource//vault',
    'resource/%2e',
    'resource/\uFF0E',
    'resource/\uFF0Fvault',
    'resource/foo/../bar',
  ])('rejects %s as a request target', (target) => {
    expect(() => assertCanonicalTarget(target)).toThrow()
  })

  it('rejects omitted and malformed roles even under a wildcard policy', () => {
    for (const agentRole of [undefined, '', ' ', null, 'agt other', 'agt\n']) {
      const decision = evaluateToolCall({
        policy: ALLOW_APPLY,
        toolName: 'apply',
        agentRole: agentRole as string | undefined,
      })
      expect(decision.action).toBe('BLOCK')
      expect(decision.ruleId).toBe('agent_not_in_scope')
    }
  })
})
