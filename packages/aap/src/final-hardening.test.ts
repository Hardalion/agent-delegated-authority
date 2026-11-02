/**
 * Independent regressions for the residual findings:
 * caller clock, omitted identity, resource canonicalization, policy pins,
 * and nonce compare-and-swap. Assertions are the security properties.
 */
import { describe, expect, it } from 'vitest'
import { evaluateToolCall, type Policy } from 'adap-policy'
import { FixedClock, type Clock } from './clock.js'
import { importPublicKey, sha256 } from './crypto.js'
import { AuthorityError } from './errors.js'
import { MemoryAtomicNonceBackend, NonceLedger } from './nonce.js'
import { PendingAuthorizationStore } from './pending.js'
import { ImmutablePolicyResolver } from './policy-resolver.js'
import {
  authenticatedReceipt,
  runAuthorityPath,
  verifyProtocolReceipt,
  type ExecutionContext,
} from './path.js'
import {
  createIdentity,
  signApproval,
  signDelegation,
  signIntent,
  unsignedDelegation,
  type Identity,
  type SignedDelegation,
  type SignedIntent,
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

function world(target = 'resource/*') {
  const principal = createIdentity('prn_example')
  const agent = createIdentity('agt_personal')
  const signer = createIdentity('reference-runtime')
  const directory = new Map<string, string>([
    [principal.id, principal.publicKey],
    [agent.id, agent.publicKey],
  ])
  const root = signDelegation(
    {
      delegation_id: 'del_root',
      issuer: principal.id,
      subject: agent.id,
      capabilities: [{ action: 'apply', target, delegable: false }],
      constraints: { max_amount: 800 },
      issued_at: ISSUED,
      expires_at: EXPIRES,
    },
    principal
  )
  return { principal, agent, signer, directory, root }
}

function intentFor(
  agent: Identity,
  root: SignedDelegation,
  nonce: string,
  target = 'resource/example',
  parameters: Record<string, unknown> = { amount: 10 }
): SignedIntent {
  return signIntent(
    {
      intent_id: `int_${nonce}`,
      actor: agent.id,
      delegation_chain: [root.delegation_id],
      action: 'apply',
      target,
      parameters,
      nonce,
      issued_at: ISSUED,
      expires_at: EXPIRES,
    },
    agent
  )
}

function run(
  env: ReturnType<typeof world>,
  intent: SignedIntent,
  options: {
    readonly clock?: Clock
    readonly now?: unknown
    readonly policy?: Policy
    readonly policyUri?: string
    readonly ledger?: NonceLedger
    readonly pendingStore?: PendingAuthorizationStore
    readonly policyResolver?: ImmutablePolicyResolver
    readonly approval?: ReturnType<typeof signApproval>
    readonly seenApprovals?: Set<string>
    readonly execute?: (ctx: ExecutionContext) => unknown
  } = {}
) {
  const policy = options.policy ?? ALLOW_APPLY
  const policyUri = options.policyUri ?? ALLOW_URI
  const policyResolver = options.policyResolver ?? new ImmutablePolicyResolver()
  if (!options.policyResolver) policyResolver.register(policy, policyUri)
  const input = {
    chain: [env.root],
    intent,
    directory: env.directory,
    policy,
    policyUri,
    clock: options.clock ?? new FixedClock(NOW),
    ledger: options.ledger ?? new NonceLedger(),
    pendingStore: options.pendingStore,
    policyResolver,
    signer: env.signer,
    approval: options.approval,
    seenApprovals: options.seenApprovals,
    execute: options.execute ?? (() => ({ ok: true })),
  }
  if (options.now !== undefined) {
    return runAuthorityPath({ ...input, now: options.now } as typeof input & { now: unknown })
  }
  return runAuthorityPath(input)
}

describe('RT-06 trusted clock', () => {
  it('rejects a caller now that would otherwise revive an expired intent', async () => {
    const env = world()
    const intent = intentFor(env.agent, env.root, 'clock-caller')
    let calls = 0
    const result = await run(env, intent, {
      clock: new FixedClock(new Date(Date.parse(EXPIRES) + 60_000)),
      now: NOW,
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(result.decision).toBe('BLOCK')
    expect(result.authenticated).toBe(false)
    expect(result.executed).toBe(false)
    expect(result.receipt).toBeUndefined()
    expect(result.ruleId).toBe('clock')
    expect(calls).toBe(0)
  })

  it('blocks expired, future, and exact-expiry instants and allows the issued boundary', async () => {
    const cases: Array<{ at: Date; blocked: boolean }> = [
      { at: new Date(Date.parse(ISSUED) - 1), blocked: true },
      { at: new Date(Date.parse(ISSUED)), blocked: false },
      { at: new Date(Date.parse(EXPIRES) - 1), blocked: false },
      { at: new Date(Date.parse(EXPIRES)), blocked: true },
      { at: new Date(Date.parse(EXPIRES) + 60_000), blocked: true },
    ]
    for (const [index, item] of cases.entries()) {
      const env = world()
      let calls = 0
      const result = await run(env, intentFor(env.agent, env.root, `clock-boundary-${index}`), {
        clock: new FixedClock(item.at),
        execute: () => {
          calls += 1
          return { ok: true }
        },
      })
      expect(result.executed).toBe(!item.blocked)
      expect(calls).toBe(item.blocked ? 0 : 1)
      if (item.blocked) {
        expect(result.decision).toBe('BLOCK')
        expect(result.ruleId).toBe('expired')
        expect(result.authenticated).toBe(true)
      } else {
        expect(result.decision).toBe('ALLOW')
      }
    }
  })

  it('fails closed when the trusted clock returns an invalid instant', async () => {
    const env = world()
    const result = await run(env, intentFor(env.agent, env.root, 'clock-invalid'), {
      clock: { now: () => new Date(Number.NaN) },
    })
    expect(result.decision).toBe('BLOCK')
    expect(result.ruleId).toBe('clock')
    expect(result.authenticated).toBe(false)
    expect(result.executed).toBe(false)
    expect(result.receipt).toBeUndefined()
  })
})

describe('RT-08 and policy defaults on the authority path', () => {
  it('does not ALLOW when the policy names a different agent', async () => {
    const env = world()
    let calls = 0
    const policy: Policy = {
      ...ALLOW_APPLY,
      targetAgents: ['agt_other'],
    }
    const result = await run(env, intentFor(env.agent, env.root, 'role-mismatch'), {
      policy,
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(result.decision).toBe('BLOCK')
    expect(result.ruleId).toBe('agent_not_in_scope')
    expect(result.executed).toBe(false)
    expect(calls).toBe(0)
  })

  it('still allows the actor the policy names', async () => {
    const env = world()
    const policy: Policy = { ...ALLOW_APPLY, targetAgents: [env.agent.id] }
    const result = await run(env, intentFor(env.agent, env.root, 'role-match'), { policy })
    expect(result.decision).toBe('ALLOW')
    expect(result.executed).toBe(true)
  })

  it('does not treat a missing defaultAction as ALLOW', async () => {
    const policy = {
      version: '1.0.0',
      policyName: 'missing-default',
      targetAgents: ['*'],
      rules: [
        { ruleId: 'allow_read', action: 'ALLOW', condition: "tool.name == 'read'", alertSeverity: 'LOW' },
      ],
    } as unknown as Policy
    const decision = evaluateToolCall({ policy, toolName: 'apply', agentRole: 'agt_personal' })
    expect(decision.action).toBe('BLOCK')
    expect(decision.ruleId).toBe('default_action_required')

    const env = world()
    let calls = 0
    const resolver = new ImmutablePolicyResolver()
    expect(() => resolver.register(policy, 'missing-default@1.0.0')).toThrow()
    const result = await run(env, intentFor(env.agent, env.root, 'missing-default'), {
      policy,
      policyUri: 'missing-default@1.0.0',
      policyResolver: resolver,
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(result.decision).toBe('BLOCK')
    expect(result.executed).toBe(false)
    expect(calls).toBe(0)
  })
})

describe('RT-10 canonical resources', () => {
  it('rejects ambiguous forms instead of rewriting them', () => {
    const rejected = [
      'resource/.',
      'resource/..',
      'resource/./vault',
      'resource/foo/../bar',
      'resource//vault',
      'resource/',
      '/resource',
      'resource/%2e%2e/vault',
      'resource/%2fvault',
      'resource\\vault',
      'resource/\uFF0Fvault',
      'resource/\uFF0E',
      'https://resource/vault',
      'resource/*',
    ]
    for (const target of rejected) {
      expect(() => assertCanonicalTarget(target), target).toThrow(AuthorityError)
    }
    expect(assertCanonicalTarget('resource/example')).toBe('resource/example')
    expect(assertCanonicalTarget('resource/*', { grant: true })).toBe('resource/*')
    expect(assertCanonicalTarget('resource/Example')).toBe('resource/Example')
  })

  it('does not execute a dot-segment or a case-different resource', async () => {
    const dotted = world('resource/bar')
    let calls = 0
    const dot = await run(dotted, intentFor(dotted.agent, dotted.root, 'dot-path', 'resource/foo/../bar'), {
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(dot.decision).toBe('BLOCK')
    expect(dot.executed).toBe(false)
    expect(dot.reason).toMatch(/dot-segment|target/)
    expect(calls).toBe(0)

    const cased = world('resource/Example')
    const lower = await run(cased, intentFor(cased.agent, cased.root, 'case-path', 'resource/example'), {
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(lower.decision).toBe('BLOCK')
    expect(lower.executed).toBe(false)
    expect(lower.ruleId).toBe('capability')
    expect(calls).toBe(0)

    const wildcard = world('Resource/*')
    const otherCase = await run(
      wildcard,
      intentFor(wildcard.agent, wildcard.root, 'prefix-case', 'resource/example'),
      {
        execute: () => {
          calls += 1
          return { ok: true }
        },
      }
    )
    expect(otherCase.executed).toBe(false)
    expect(otherCase.decision).toBe('BLOCK')
  })
})

describe('policy registration', () => {
  it('rejects a second document for the same URI and does not keep the rejected body', () => {
    const resolver = new ImmutablePolicyResolver()
    const first = resolver.register(ALLOW_APPLY, ALLOW_URI)
    const other: Policy = {
      ...ALLOW_APPLY,
      policyName: 'other-apply',
      rules: [
        { ruleId: 'other', action: 'ALLOW', condition: "tool.name == 'apply'", alertSeverity: 'LOW' },
      ],
    }
    expect(() => resolver.register(other, ALLOW_URI)).toThrow(/different immutable content hash/)
    expect(() => resolver.resolveByContentHash(sha256(other))).toThrow(/unknown policy content hash/)
    expect(resolver.resolveByUri(ALLOW_URI)?.contentHash).toBe(first.contentHash)
    expect(resolver.register(ALLOW_APPLY, ALLOW_URI).contentHash).toBe(first.contentHash)
  })

  it('does not execute an unknown URI or a caller document that disagrees with the pin', async () => {
    const env = world()
    let calls = 0
    const unknown = await run(env, intentFor(env.agent, env.root, 'unknown-uri'), {
      policyResolver: new ImmutablePolicyResolver(),
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(unknown.decision).toBe('BLOCK')
    expect(unknown.ruleId).toBe('policy')
    expect(unknown.reason).toMatch(/unknown policy URI/)
    expect(unknown.executed).toBe(false)
    expect(calls).toBe(0)

    const resolver = new ImmutablePolicyResolver()
    resolver.register(ALLOW_APPLY, ALLOW_URI)
    const permissive: Policy = {
      version: '1.0.0',
      policyName: 'permissive-apply',
      targetAgents: ['*'],
      defaultAction: 'ALLOW',
      rules: [
        { ruleId: 'allow_all', action: 'ALLOW', condition: "tool.name == 'apply'", alertSeverity: 'LOW' },
      ],
    }
    const mismatch = await run(env, intentFor(env.agent, env.root, 'policy-mismatch'), {
      policy: permissive,
      policyResolver: resolver,
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(mismatch.decision).toBe('BLOCK')
    expect(mismatch.executed).toBe(false)
    expect(mismatch.reason).toMatch(/does not match/)
    expect(calls).toBe(0)

    const ok = await run(env, intentFor(env.agent, env.root, 'policy-pin-ok'), {
      policyResolver: resolver,
    })
    expect(ok.decision).toBe('ALLOW')
    expect(ok.executed).toBe(true)
    expect(authenticatedReceipt(ok).policy.contentHash).toBe(sha256(ALLOW_APPLY))
  })

  it('keeps a pending approval bound to the original policy after a substitution attempt', async () => {
    const env = world()
    const resolver = new ImmutablePolicyResolver()
    resolver.register(ALLOW_APPLY, ALLOW_URI)
    const pendingStore = new PendingAuthorizationStore()
    const humanPolicy: Policy = {
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
    const humanUri = 'human-apply@1.0.0'
    resolver.register(humanPolicy, humanUri)
    const ledger = new NonceLedger()
    const intent = intentFor(env.agent, env.root, 'pending-pin')
    let calls = 0
    const pending = await run(env, intent, {
      policy: humanPolicy,
      policyUri: humanUri,
      policyResolver: resolver,
      pendingStore,
      ledger,
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(pending.decision).toBe('REQUIRE_HUMAN')
    expect(calls).toBe(0)
    const stored = pendingStore.get(intent.nonce)
    expect(stored?.approverId).toBe(env.principal.id)
    expect(stored?.policyContentHash).toBe(pending.policyHash)
    expect(stored?.intentHash).toBe(pending.intentHash)

    const swapped = await run(env, intent, {
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      policyResolver: resolver,
      pendingStore,
      ledger,
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(swapped.decision).toBe('BLOCK')
    expect(swapped.executed).toBe(false)
    expect(calls).toBe(0)
  })
})

describe('nonce adapter', () => {
  it('lets only one claimant win a scripted compare-and-swap race', () => {
    const backend = new MemoryAtomicNonceBackend()
    const first = new NonceLedger(backend)
    const second = new NonceLedger(backend)
    backend.beforeCompareAndSwap = () => {
      second.claimForExecution('shared-nonce', 'hash-1')
    }
    expect(() => first.claimForExecution('shared-nonce', 'hash-1')).toThrow(/nonce_in_flight_or_used/)
    expect(second.statusOf('shared-nonce')).toBe('pending')
    expect(() => second.claimForExecution('shared-nonce', 'hash-1')).toThrow(/nonce_in_flight_or_used/)
  })

  it('does not coordinate two process-local ledgers', () => {
    const left = new NonceLedger()
    const right = new NonceLedger()
    left.claimForExecution('split', 'hash-2')
    right.claimForExecution('split', 'hash-2')
    expect(left.statusOf('split')).toBe('pending')
    expect(right.statusOf('split')).toBe('pending')
  })

  it('spends a nonce when the executor throws and refuses the retry', async () => {
    const env = world()
    const ledger = new NonceLedger()
    const intent = intentFor(env.agent, env.root, 'executor-throw')
    let calls = 0
    const failed = await run(env, intent, {
      ledger,
      execute: () => {
        calls += 1
        throw new Error('downstream write failed after a side effect')
      },
    })
    expect(failed.decision).toBe('BLOCK')
    expect(failed.executed).toBe(false)
    expect(failed.ruleId).toBe('execution')
    expect(calls).toBe(1)
    expect(ledger.statusOf(intent.nonce)).toBe('failed')
    const retry = await run(env, intent, {
      ledger,
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(retry.decision).toBe('BLOCK')
    expect(retry.ruleId).toBe('replay')
    expect(retry.executed).toBe(false)
    expect(calls).toBe(1)
  })
})

describe('approval binding', () => {
  it('rejects the wrong approver and a repeated bad approval without spending the nonce', async () => {
    const env = world()
    const other = createIdentity('prn_other')
    env.directory.set(other.id, other.publicKey)
    const humanPolicy: Policy = {
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
    const pendingStore = new PendingAuthorizationStore()
    const seenApprovals = new Set<string>()
    const intent = intentFor(env.agent, env.root, 'approval-bind')
    const pending = await run(env, intent, { policy: humanPolicy, pendingStore, seenApprovals })
    expect(pending.decision).toBe('REQUIRE_HUMAN')
    const chainHash = sha256([unsignedDelegation(env.root)])
    const wrong = signApproval(
      {
        intent_hash: pending.intentHash,
        approver_id: other.id,
        approved_at: ISSUED,
        decision: 'APPROVE',
        agent_id: env.agent.id,
        delegation_chain_hash: chainHash,
        policy_content_hash: pending.policyHash,
        matched_rule_id: pending.ruleId,
      },
      other
    )
    let calls = 0
    const denied = await run(env, intent, {
      policy: humanPolicy,
      pendingStore,
      seenApprovals,
      approval: wrong,
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(denied.decision).toBe('BLOCK')
    expect(denied.executed).toBe(false)
    expect(denied.reason).toMatch(/approver/)
    expect(calls).toBe(0)

    const good = signApproval(
      {
        intent_hash: pending.intentHash,
        approver_id: env.principal.id,
        approved_at: ISSUED,
        decision: 'APPROVE',
        agent_id: env.agent.id,
        delegation_chain_hash: chainHash,
        policy_content_hash: pending.policyHash,
        matched_rule_id: pending.ruleId,
      },
      env.principal
    )
    const tampered = { ...good, signature: 'ab'.repeat(64) }
    const firstBad = await run(env, intent, {
      policy: humanPolicy,
      pendingStore,
      seenApprovals,
      approval: tampered,
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(firstBad.executed).toBe(false)
    expect(firstBad.ruleId).toBe('approval')
    expect(firstBad.reason).toMatch(/signature invalid/)
    const secondBad = await run(env, intent, {
      policy: humanPolicy,
      pendingStore,
      seenApprovals,
      approval: tampered,
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    // A forged approval must not reserve the dedup slot of the real approval.
    expect(secondBad.reason).toMatch(/signature invalid/)
    expect(calls).toBe(0)

    const allowed = await run(env, intent, {
      policy: humanPolicy,
      pendingStore,
      seenApprovals,
      approval: good,
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(allowed.decision).toBe('ALLOW')
    expect(allowed.executed).toBe(true)
    expect(calls).toBe(1)
    const receipt = authenticatedReceipt(allowed)
    expect(verifyProtocolReceipt(receipt, importPublicKey(env.signer.publicKey)).valid).toBe(true)
    expect(receipt.execution?.executed).toBe(true)
    expect(receipt.human?.approverId).toBe(env.principal.id)

    const replayed = await run(env, intent, {
      policy: humanPolicy,
      pendingStore,
      seenApprovals,
      approval: good,
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(replayed.executed).toBe(false)
    expect(replayed.reason).toMatch(/duplicate approval|nonce already used|pending/)
    expect(calls).toBe(1)
  })
})
