/**
 * Permanent adversarial regression suite for ADAP-001 through ADAP-011.
 * Failures here are security regressions.
 */
import { describe, expect, it } from 'vitest'
import { FixedClock } from './clock.js'
import type { Policy } from 'adap-policy'
import { evaluateToolCall } from 'adap-policy'
import { verifyAuthorizationReceipt } from 'adap-receipt'
import { assertCanonicalAmount } from './amount.js'
import { canonicalJson, sha256 } from './crypto.js'
import { BASIC_AGENT_AUTHORITY, BASIC_AGENT_AUTHORITY_URI } from './example-policy.js'
import { NonceLedger } from './nonce.js'
import { PendingAuthorizationStore } from './pending.js'
import { ImmutablePolicyResolver } from './policy-resolver.js'
import { runAuthorityPath } from './path.js'
import {
  createIdentity,
  signApproval,
  signDelegation,
  signIntent,
  unsignedDelegation,
  type SignedDelegation,
  type SignedIntent,
} from './protocol.js'
import { assertIntentWithinDelegation, validateDelegationNarrowing } from './validate.js'
import { assertValidNonce, validateSignedIntent } from './runtime-validate.js'

const NOW = new Date('2026-10-06T18:00:00.000Z')
const ISSUED = NOW.toISOString()
const EXPIRES = new Date(NOW.getTime() + 15 * 60 * 1000).toISOString()

function fixture() {
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
  const pendingStore = new PendingAuthorizationStore()
  const policyResolver = new ImmutablePolicyResolver()
  policyResolver.register(BASIC_AGENT_AUTHORITY, BASIC_AGENT_AUTHORITY_URI)
  return { principal, agent, signer, directory, root, pendingStore, policyResolver }
}

function signedApply(
  agent: ReturnType<typeof createIdentity>,
  root: SignedDelegation,
  amount: number,
  nonce: string
): SignedIntent {
  return signIntent(
    {
      intent_id: `int_${nonce}`,
      actor: agent.id,
      delegation_chain: [root.delegation_id],
      action: 'apply',
      target: 'resource/example',
      parameters: { amount, note: 'example' },
      nonce,
      issued_at: ISSUED,
      expires_at: EXPIRES,
    },
    agent
  )
}

describe('ADAP-001 human approval policy substitution', () => {
  it('rejects continuation with a substituted permissive policy (same URI)', async () => {
    const { principal, agent, signer, directory, root, pendingStore, policyResolver } = fixture()
    const intent = signedApply(agent, root, 420, 'adap001')
    const ledger = new NonceLedger()
    let exec = 0
    const pending = await runAuthorityPath({
      chain: [root],
      intent,
      directory,
      trustedRootIssuers: [principal.id],
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      clock: new FixedClock(NOW),
      ledger,
      pendingStore,
      policyResolver,
      signer,
      execute: () => {
        exec += 1
        return { ok: true }
      },
    })
    expect(pending.decision).toBe('REQUIRE_HUMAN')

    const permissive: Policy = {
      version: '1.0.0',
      policyName: 'basic-agent-authority',
      description: 'substituted',
      targetAgents: ['*'],
      defaultAction: 'ALLOW',
      rules: [
        {
          ruleId: 'allow_all',
          action: 'ALLOW',
          condition: "tool.name == 'apply'",
          alertSeverity: 'LOW',
        },
      ],
    }
    const withoutApproval = await runAuthorityPath({
      chain: [root],
      intent,
      directory,
      trustedRootIssuers: [principal.id],
      policy: permissive,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      clock: new FixedClock(NOW),
      ledger,
      pendingStore,
      policyResolver,
      signer,
      execute: () => {
        exec += 1
        return { ok: true }
      },
    })
    expect(withoutApproval.decision).toBe('BLOCK')
    expect(withoutApproval.executed).toBe(false)
    expect(exec).toBe(0)

    // A caller document that disagrees with the pinned hash is rejected even with a valid-looking approval.
    const mismatchStore = new PendingAuthorizationStore()
    const ledger2 = new NonceLedger()
    const intent2 = signedApply(agent, root, 420, 'adap001-nr')
    const pending2 = await runAuthorityPath({
      chain: [root],
      intent: intent2,
      directory,
      trustedRootIssuers: [principal.id],
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      clock: new FixedClock(NOW),
      ledger: ledger2,
      pendingStore: mismatchStore,
      policyResolver,
      signer,
    })
    const substituted = await runAuthorityPath({
      chain: [root],
      intent: intent2,
      directory,
      trustedRootIssuers: [principal.id],
      policy: permissive,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      clock: new FixedClock(NOW),
      ledger: ledger2,
      pendingStore: mismatchStore,
      policyResolver,
      signer,
      approval: signApproval(
        {
          intent_hash: pending2.intentHash,
          approver_id: principal.id,
          approved_at: ISSUED,
          decision: 'APPROVE',
          agent_id: agent.id,
          delegation_chain_hash: sha256([unsignedDelegation(root)]),
          policy_content_hash: pending2.policyHash,
          matched_rule_id: pending2.ruleId,
        },
        principal
      ),
      execute: () => {
        exec += 1
        return { ok: true }
      },
    })
    expect(substituted.decision).toBe('BLOCK')
    expect(substituted.executed).toBe(false)
    expect(substituted.reason).toMatch(/policy content hash/i)
    expect(exec).toBe(0)

    // Continuation must present the pinned document. The resolver refuses a different body.
    const approved = await runAuthorityPath({
      chain: [root],
      intent,
      directory,
      trustedRootIssuers: [principal.id],
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      clock: new FixedClock(NOW),
      ledger,
      pendingStore,
      policyResolver,
      signer,
      approval: signApproval(
        {
          intent_hash: pending.intentHash,
          approver_id: principal.id,
          approved_at: ISSUED,
          decision: 'APPROVE',
          agent_id: agent.id,
          delegation_chain_hash: sha256([unsignedDelegation(root)]),
          policy_content_hash: pending.policyHash,
          matched_rule_id: pending.ruleId,
        },
        principal
      ),
      execute: () => {
        exec += 1
        return { ok: true }
      },
    })
    expect(approved.decision).toBe('ALLOW')
    expect(approved.policyHash).toBe(pending.policyHash)
    expect(exec).toBe(1)
  })

  it('rejects approval replay and agent/policy binding mismatches', async () => {
    const { principal, agent, signer, directory, root, pendingStore, policyResolver } = fixture()
    const other = createIdentity('agt_other')
    directory.set(other.id, other.publicKey)
    const intent = signedApply(agent, root, 420, 'adap001b')
    const ledger = new NonceLedger()
    const seen = new Set<string>()
    const pending = await runAuthorityPath({
      chain: [root],
      intent,
      directory,
      trustedRootIssuers: [principal.id],
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      clock: new FixedClock(NOW),
      ledger,
      pendingStore,
      policyResolver,
      signer,
      seenApprovals: seen,
    })
    const approval = signApproval(
      {
        intent_hash: pending.intentHash,
        approver_id: principal.id,
        approved_at: ISSUED,
        decision: 'APPROVE',
        agent_id: other.id,
        delegation_chain_hash: sha256([unsignedDelegation(root)]),
        policy_content_hash: pending.policyHash,
        matched_rule_id: pending.ruleId,
      },
      principal
    )
    const wrongAgent = await runAuthorityPath({
      chain: [root],
      intent,
      directory,
      trustedRootIssuers: [principal.id],
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      clock: new FixedClock(NOW),
      ledger,
      pendingStore,
      policyResolver,
      signer,
      seenApprovals: seen,
      approval,
      execute: () => ({ ok: true }),
    })
    expect(wrongAgent.decision).toBe('BLOCK')
    expect(wrongAgent.reason).toMatch(/agent|approval/i)
    expect(wrongAgent.executed).toBe(false)
  })
})

describe('ADAP-002 object-valued nonce replay', () => {
  it('rejects object/array/number nonces and blocks independent JSON parse replay', () => {
    const ledger = new NonceLedger()
    const actor = 'agt_example'
    expect(() => ledger.claimForExecution(actor, { value: 'x' } as unknown as string, 'h')).toThrow(/nonce/)
    expect(() => ledger.claimForExecution(actor, ['x'] as unknown as string, 'h')).toThrow(/nonce/)
    expect(() => ledger.claimForExecution(actor, 1 as unknown as string, 'h')).toThrow(/nonce/)
    expect(() => assertValidNonce(null)).toThrow(/nonce/)

    const wire = JSON.stringify({ nonce: 'replay-wire-1' })
    const a = JSON.parse(wire) as { nonce: string }
    const b = JSON.parse(wire) as { nonce: string }
    ledger.claimForExecution(actor, a.nonce, 'hash-1')
    ledger.consume(actor, a.nonce, 'hash-1')
    expect(() => ledger.claimForExecution(actor, b.nonce, 'hash-1')).toThrow(/nonce/)

    const objectWire = JSON.stringify({ nonce: { value: 'same-nonce' } })
    const left = JSON.parse(objectWire) as { nonce: { value: string } }
    const right = JSON.parse(objectWire) as { nonce: { value: string } }
    expect(left).not.toBe(right)
    expect(left.nonce).not.toBe(right.nonce)
    expect(() => ledger.claimForExecution(actor, left.nonce as unknown as string, 'hash-obj')).toThrow(/nonce/)
    expect(() => ledger.claimForExecution(actor, right.nonce as unknown as string, 'hash-obj')).toThrow(/nonce/)
  })

  it('blocks a second authority request after an independent JSON parse of the same nonce', async () => {
    const { principal, agent, signer, directory, root } = fixture()
    const allow: Policy = {
      version: '1.0.0',
      policyName: 'allow-apply',
      targetAgents: ['*'],
      defaultAction: 'BLOCK',
      rules: [
        {
          ruleId: 'allow_apply',
          action: 'ALLOW',
          condition: "tool.name == 'apply'",
          alertSeverity: 'LOW',
        },
      ],
    }
    const resolver = new ImmutablePolicyResolver()
    resolver.register(allow, 'allow-apply@1')
    const signed = signedApply(agent, root, 10, 'independent-parse')
    const first = JSON.parse(JSON.stringify(signed)) as SignedIntent
    const second = JSON.parse(JSON.stringify(signed)) as SignedIntent
    expect(first).not.toBe(second)
    expect(first.nonce).toBe(second.nonce)
    let exec = 0
    const ledger = new NonceLedger()
    const shared = {
      chain: [root],
      directory,
      trustedRootIssuers: [principal.id],
      policy: allow,
      policyUri: 'allow-apply@1',
      clock: new FixedClock(NOW),
      ledger,
      pendingStore: new PendingAuthorizationStore(),
      policyResolver: resolver,
      signer,
      execute: () => {
        exec += 1
        return { ok: true }
      },
    }
    const allowed = await runAuthorityPath({ ...shared, intent: first })
    const replay = await runAuthorityPath({ ...shared, intent: second })
    expect(allowed.decision).toBe('ALLOW')
    expect(allowed.executed).toBe(true)
    expect(replay.decision).toBe('BLOCK')
    expect(replay.executed).toBe(false)
    expect(exec).toBe(1)
  })
})

describe('ADAP-003 non-finite amounts', () => {
  it('rejects NaN, Infinity, unsafe integers, and negatives', () => {
    expect(() => assertCanonicalAmount(Number.NaN, 'amount')).toThrow(/NaN/)
    expect(() => assertCanonicalAmount(Number.POSITIVE_INFINITY, 'amount')).toThrow(/finite/)
    expect(() => assertCanonicalAmount(Number.NEGATIVE_INFINITY, 'amount')).toThrow(/finite/)
    expect(() => assertCanonicalAmount(-1, 'amount')).toThrow(/>= 0/)
    expect(() => assertCanonicalAmount(1.5, 'amount')).toThrow(/safe integer/)
    expect(() => assertCanonicalAmount(Number.MAX_SAFE_INTEGER + 1, 'amount')).toThrow(/safe integer/)
    expect(assertCanonicalAmount(0, 'amount')).toBe(0)
    expect(assertCanonicalAmount(500, 'amount')).toBe(500)
  })

  it('rejects non-finite amounts at the intent boundary', () => {
    const { agent, root } = fixture()
    expect(() =>
      assertIntentWithinDelegation(
        {
          intent_id: 'i',
          actor: agent.id,
          delegation_chain: [root.delegation_id],
          action: 'apply',
          target: 'resource/example',
          parameters: { amount: Number.NaN },
          nonce: 'n',
          issued_at: ISSUED,
          expires_at: EXPIRES,
        },
        root
      )
    ).toThrow()
  })
})

describe('ADAP-004 prototype pollution and canonicalization', () => {
  it('rejects dangerous keys and non-plain prototypes during canonicalization', () => {
    expect(() => canonicalJson(JSON.parse('{"a":1,"__proto__":{"x":1}}'))).toThrow(/dangerous key/)
    expect(() => canonicalJson(JSON.parse('{"constructor":1}'))).toThrow(/dangerous key/)
    const inherited = Object.create({ leaked: 9 })
    inherited.a = 1
    expect(() => canonicalJson(inherited)).toThrow(/prototype/)
    const ordered = canonicalJson({ b: 1, a: 2 })
    expect(ordered).toBe(canonicalJson({ a: 2, b: 1 }))
  })
})

describe('ADAP-005 inherited delegation constraints', () => {
  it('rejects prototype-bearing constraint objects and missing own constraints', () => {
    const parent = {
      delegation_id: 'd1',
      issuer: 'human',
      subject: 'agent-a',
      capabilities: [{ action: 'apply', target: 'resource/*' }],
      constraints: { max_amount: 100, currency: 'EUR' },
      issued_at: ISSUED,
      expires_at: EXPIRES,
      signature: 'x',
    }
    const childConstraints = Object.create(parent.constraints) as Record<string, unknown>
    childConstraints.max_amount = 100
    const child = {
      ...parent,
      delegation_id: 'd2',
      issuer: 'agent-a',
      subject: 'agent-b',
      parent_delegation_id: 'd1',
      capabilities: [{ action: 'apply', target: 'resource/example' }],
      constraints: childConstraints,
    }
    expect(() => validateDelegationNarrowing(parent as never, child as never)).toThrow(/plain data object|constraint/)
  })
})

describe('ADAP-006 empty actor / targetAgents', () => {
  it('rejects empty identities and empty agentRole scope bypass', () => {
    expect(() => createIdentity('')).toThrow(/empty|identity/i)
    const decision = evaluateToolCall({
      policy: {
        version: '1',
        policyName: 'basic-agent-authority',
        targetAgents: ['agt_a'],
        rules: [
          { ruleId: 'r', action: 'ALLOW', condition: "tool.name == 'read'", alertSeverity: 'LOW' },
        ],
      },
      toolName: 'read',
      agentRole: '',
    })
    expect(decision.action).toBe('BLOCK')
    expect(decision.ruleId).toBe('agent_not_in_scope')
  })
})

describe('ADAP-007 missing required intent fields', () => {
  it('rejects missing, null, and malformed intent fields before execution', () => {
    expect(() => validateSignedIntent({ actor: 'a' })).toThrow(/required|schema/)
    expect(() =>
      validateSignedIntent({
        intent_id: 'i',
        actor: 'agt_a',
        delegation_chain: ['d1'],
        action: 'apply',
        target: 'resource/example',
        parameters: {},
        nonce: 'n1',
        issued_at: ISSUED,
        expires_at: EXPIRES,
        signature: null,
      })
    ).toThrow(/signature/)
  })

  it('rejects a malformed intent at runAuthorityPath before the executor is called', async () => {
    const { principal, agent, signer, directory, root, policyResolver } = fixture()
    const good = signedApply(agent, root, 10, 'adap007-boundary')
    let exec = 0
    const malformed = [
      { ...good, signature: null },
      { ...good, actor: null },
      { ...good, nonce: null },
      { intent_id: 'only-an-id' },
    ]
    for (const intent of malformed) {
      const result = await runAuthorityPath({
        chain: [root],
        intent: intent as unknown as SignedIntent,
        directory,
        trustedRootIssuers: [principal.id],
        policy: BASIC_AGENT_AUTHORITY,
        policyUri: BASIC_AGENT_AUTHORITY_URI,
        clock: new FixedClock(NOW),
        ledger: new NonceLedger(),
        pendingStore: new PendingAuthorizationStore(),
        policyResolver,
        signer,
        execute: () => {
          exec += 1
          return { ok: true }
        },
      })
      expect(result.decision).toBe('BLOCK')
      expect(result.executed).toBe(false)
      expect(result.authenticated).toBe(false)
    }
    expect(exec).toBe(0)
  })
})

describe('ADAP-008 trusted clock', () => {
  it('rejects expired authority against the trusted now, not intent-embedded clocks alone', async () => {
    const { principal, agent, signer, directory, root, pendingStore, policyResolver } = fixture()
    const intent = signedApply(agent, root, 420, 'adap008')
    const expired = await runAuthorityPath({
      chain: [root],
      intent,
      directory,
      trustedRootIssuers: [principal.id],
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      clock: new FixedClock(new Date(Date.parse(EXPIRES) + 1000)),
      ledger: new NonceLedger(),
      pendingStore,
      policyResolver,
      signer,
      execute: () => ({ ok: true }),
    })
    expect(expired.decision).toBe('BLOCK')
    expect(expired.executed).toBe(false)
    expect(expired.reason).toMatch(/expired/i)
  })

  it('rejects caller-supplied now that would revive an expired intent', async () => {
    const { principal, agent, signer, directory, root, policyResolver } = fixture()
    const intent = signedApply(agent, root, 10, 'adap008-caller-now')
    let exec = 0
    const result = await runAuthorityPath({
      chain: [root],
      intent,
      directory,
      trustedRootIssuers: [principal.id],
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      clock: new FixedClock(new Date(Date.parse(EXPIRES) + 60_000)),
      now: NOW,
      ledger: new NonceLedger(),
      pendingStore: new PendingAuthorizationStore(),
      policyResolver,
      signer,
      execute: () => {
        exec += 1
        return { ok: true }
      },
    })
    expect(result.decision).toBe('BLOCK')
    expect(result.ruleId).toBe('clock')
    expect(result.authenticated).toBe(false)
    expect(result.executed).toBe(false)
    expect(result.receipt).toBeUndefined()
    expect(exec).toBe(0)
  })
})

describe('ADAP-009/010 amount and target domain', () => {
  it('rejects ambiguous targets and non-canonical currency', () => {
    const { agent, root } = fixture()
    expect(() =>
      assertIntentWithinDelegation(
        {
          intent_id: 'i',
          actor: agent.id,
          delegation_chain: [root.delegation_id],
          action: 'apply',
          target: 'resource/../secret',
          parameters: { amount: 1 },
          nonce: 'n',
          issued_at: ISSUED,
          expires_at: EXPIRES,
        },
        root
      )
    ).toThrow(/dot-segment|target/)
  })
})

describe('ADAP-011 receipt semantic consistency', () => {
  it('rejects contradictory action/outcome/execution combinations', () => {
    const forged = {
      v: 1,
      kind: 'adap.receipt',
      receiptId: 'r1',
      issuer: 'x',
      issuerKeyId: 'ed25519:deadbeefdeadbeefdeadbeefdeadbeef',
      decidedAt: '2026-10-06T18:00:00.000Z',
      intent: { toolName: 'apply', argsHash: 'a'.repeat(64) },
      identity: { agentId: 'agt', actorType: 'non_human_agent' },
      policy: {
        policyUri: 'p@1',
        policyName: 'basic-agent-authority',
        policyVersion: '1',
        ruleId: 'r',
        contentHash: 'b'.repeat(64),
      },
      decision: {
        action: 'BLOCK',
        outcome: 'allowed',
        reason: 'contradiction',
        alertSeverity: 'CRITICAL',
        matched: true,
      },
      integrity: { contentHash: 'c'.repeat(64) },
      signature: 'ab'.repeat(64),
      execution: { intentHash: 'd'.repeat(64), executed: true },
    }
    const result = verifyAuthorizationReceipt(forged)
    expect(result.structureOk).toBe(false)
    expect(result.errors.some((e) => /inconsistent|executed/i.test(e))).toBe(true)
  })
})

describe('execution gate', () => {
  it('never executes BLOCK or unresolved REQUIRE_HUMAN', async () => {
    const { principal, agent, signer, directory, root, pendingStore, policyResolver } = fixture()
    let exec = 0
    const pending = await runAuthorityPath({
      chain: [root],
      intent: signedApply(agent, root, 420, 'exec-gate'),
      directory,
      trustedRootIssuers: [principal.id],
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      clock: new FixedClock(NOW),
      ledger: new NonceLedger(),
      pendingStore,
      policyResolver,
      signer,
      execute: () => {
        exec += 1
        return { ok: true }
      },
    })
    expect(pending.decision).toBe('REQUIRE_HUMAN')
    expect(pending.executed).toBe(false)
    expect(exec).toBe(0)
  })
})
