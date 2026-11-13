/**
 * Signed-object profile compatibility matrix (#19 finalization).
 * A verifier upgrade must never widen a legacy signed authorization.
 */
import { describe, expect, it } from 'vitest'
import { FixedClock } from './clock.js'
import { sha256 } from './crypto.js'
import { MemoryAuthorityDirectory } from './directory.js'
import { BASIC_AGENT_AUTHORITY, BASIC_AGENT_AUTHORITY_URI } from './example-policy.js'
import { NonceLedger } from './nonce.js'
import { runAuthorityPath } from './path.js'
import { PendingAuthorizationStore } from './pending.js'
import { ImmutablePolicyResolver } from './policy-resolver.js'
import {
  createIdentity,
  signApproval,
  signDelegation,
  signIntent,
  unsignedDelegation,
  type SignedDelegation,
} from './protocol.js'
import { ADAP_SIGNED_VERSION } from './signed-object.js'
import {
  assertApprovalMatchesAuthorityProfile,
  assertChainProfileConsistency,
  assertIntentMatchesAuthorityProfile,
  validateDelegationNarrowing,
  verifyAuthority,
  verifyHumanApproval,
} from './validate.js'

const NOW = new Date('2026-10-06T18:00:00.000Z')
const ISSUED = NOW.toISOString()
const EXPIRES = new Date(NOW.getTime() + 15 * 60 * 1000).toISOString()
const t0 = '2026-10-06T10:00:00.000Z'
const t1 = '2026-10-06T10:15:00.000Z'

function legacyShape(over: Partial<SignedDelegation>): SignedDelegation {
  return {
    delegation_id: 'd1',
    issuer: 'human',
    subject: 'agent-a',
    capabilities: [{ action: 'purchase', target: 'airline/*', delegable: true }],
    constraints: { max_amount: 500 },
    issued_at: t0,
    expires_at: t1,
    signature: 'x',
    ...over,
  }
}

function v02Shape(over: Partial<SignedDelegation>): SignedDelegation {
  return legacyShape({
    adap: ADAP_SIGNED_VERSION,
    typ: 'delegation',
    alg: 'Ed25519',
    kid: 'ed25519:test',
    ...over,
  })
}

describe('profile-aware delegation narrowing', () => {
  it('allows legacy parent/child with matching exact constraints', () => {
    const parent = legacyShape({ constraints: { max_amount: 500, max_quantity: 5 } })
    const child = legacyShape({
      delegation_id: 'd2',
      issuer: 'agent-a',
      subject: 'agent-b',
      parent_delegation_id: 'd1',
      capabilities: [{ action: 'purchase', target: 'airline/example' }],
      constraints: { max_amount: 400, max_quantity: 5 },
    })
    expect(() => validateDelegationNarrowing(parent, child)).not.toThrow()
  })

  it('rejects legacy child that changes max_quantity (exact-match)', () => {
    const parent = legacyShape({ constraints: { max_amount: 500, max_quantity: 5 } })
    const child = legacyShape({
      delegation_id: 'd2',
      issuer: 'agent-a',
      subject: 'agent-b',
      parent_delegation_id: 'd1',
      capabilities: [{ action: 'purchase', target: 'airline/example' }],
      constraints: { max_amount: 500, max_quantity: 3 },
    })
    expect(() => validateDelegationNarrowing(parent, child)).toThrow(/alters constraint max_quantity/)
  })

  it('rejects legacy child that raises max_amount', () => {
    const parent = legacyShape({})
    const child = legacyShape({
      delegation_id: 'd2',
      issuer: 'agent-a',
      subject: 'agent-b',
      parent_delegation_id: 'd1',
      capabilities: [{ action: 'purchase', target: 'airline/example' }],
      constraints: { max_amount: 900 },
    })
    expect(() => validateDelegationNarrowing(parent, child)).toThrow(/raises max_amount/)
  })

  it('allows v0.2 child to reduce a generic ceiling', () => {
    const parent = v02Shape({ constraints: { max_quantity: 5 } })
    const child = v02Shape({
      delegation_id: 'd2',
      issuer: 'agent-a',
      subject: 'agent-b',
      parent_delegation_id: 'd1',
      capabilities: [{ action: 'purchase', target: 'airline/example' }],
      constraints: { max_quantity: 3 },
    })
    expect(() => validateDelegationNarrowing(parent, child)).not.toThrow()
  })

  it('rejects v0.2 child that raises a generic ceiling', () => {
    const parent = v02Shape({ constraints: { max_quantity: 5 } })
    const child = v02Shape({
      delegation_id: 'd2',
      issuer: 'agent-a',
      subject: 'agent-b',
      parent_delegation_id: 'd1',
      capabilities: [{ action: 'purchase', target: 'airline/example' }],
      constraints: { max_quantity: 9 },
    })
    expect(() => validateDelegationNarrowing(parent, child)).toThrow(/raises max_quantity/)
  })

  it('rejects legacy parent with v0.2 child', () => {
    const parent = legacyShape({})
    const child = v02Shape({
      delegation_id: 'd2',
      issuer: 'agent-a',
      subject: 'agent-b',
      parent_delegation_id: 'd1',
      capabilities: [{ action: 'purchase', target: 'airline/example' }],
    })
    expect(() => validateDelegationNarrowing(parent, child)).toThrow(/signed-object profile/)
  })

  it('rejects v0.2 parent with legacy child', () => {
    const parent = v02Shape({})
    const child = legacyShape({
      delegation_id: 'd2',
      issuer: 'agent-a',
      subject: 'agent-b',
      parent_delegation_id: 'd1',
      capabilities: [{ action: 'purchase', target: 'airline/example' }],
    })
    expect(() => validateDelegationNarrowing(parent, child)).toThrow(/signed-object profile/)
  })

  it('rejects a mixed-profile multi-level chain', () => {
    const root = legacyShape({})
    const mid = v02Shape({
      delegation_id: 'd2',
      issuer: 'agent-a',
      subject: 'agent-b',
      parent_delegation_id: 'd1',
    })
    expect(() => assertChainProfileConsistency([root, mid])).toThrow(/mixes signed-object profiles/)
  })
})

describe('intent and approval profile compatibility', () => {
  it('rejects legacy chain with versioned intent', () => {
    const principal = createIdentity('prn_example')
    const agent = createIdentity('agt_example')
    const root = signDelegation(
      {
        delegation_id: 'del_root',
        issuer: principal.id,
        subject: agent.id,
        capabilities: [{ action: 'apply', target: 'resource/*' }],
        constraints: { max_amount: 800 },
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      principal
    )
    const intent = signIntent(
      {
        intent_id: 'int_mix',
        actor: agent.id,
        delegation_chain: [root.delegation_id],
        action: 'apply',
        target: 'resource/example',
        parameters: { amount: 10 },
        nonce: 'n-mix',
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      agent,
      { profile: '0.2' }
    )
    const directory = new MemoryAuthorityDirectory([
      {
        identityId: principal.id,
        kid: principal.kid,
        alg: 'Ed25519',
        publicKey: principal.publicKey,
        status: 'active',
      },
      {
        identityId: agent.id,
        kid: agent.kid,
        alg: 'Ed25519',
        publicKey: agent.publicKey,
        status: 'active',
      },
    ])
    expect(() =>
      verifyAuthority({ chain: [root], intent, directory, now: NOW }),
    ).toThrow(/intent signed-object profile/)
  })

  it('rejects versioned chain with legacy intent', () => {
    const principal = createIdentity('prn_example')
    const agent = createIdentity('agt_example')
    const root = signDelegation(
      {
        delegation_id: 'del_root',
        issuer: principal.id,
        subject: agent.id,
        capabilities: [{ action: 'apply', target: 'resource/*' }],
        constraints: { max_amount: 800 },
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      principal,
      { profile: '0.2' }
    )
    const intent = signIntent(
      {
        intent_id: 'int_mix2',
        actor: agent.id,
        delegation_chain: [root.delegation_id],
        action: 'apply',
        target: 'resource/example',
        parameters: { amount: 10 },
        nonce: 'n-mix2',
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      agent
    )
    const directory = new MemoryAuthorityDirectory([
      {
        identityId: principal.id,
        kid: principal.kid,
        alg: 'Ed25519',
        publicKey: principal.publicKey,
        status: 'active',
      },
      {
        identityId: agent.id,
        kid: agent.kid,
        alg: 'Ed25519',
        publicKey: agent.publicKey,
        status: 'active',
      },
    ])
    expect(() =>
      verifyAuthority({ chain: [root], intent, directory, now: NOW }),
    ).toThrow(/intent signed-object profile/)
  })

  it('rejects v0.2 context continued with a legacy approval', async () => {
    const principal = createIdentity('prn_example')
    const agent = createIdentity('agt_example')
    const signer = createIdentity('reference-runtime')
    const root = signDelegation(
      {
        delegation_id: 'del_root',
        issuer: principal.id,
        subject: agent.id,
        capabilities: [{ action: 'apply', target: 'resource/*' }],
        constraints: { max_amount: 800 },
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      principal,
      { profile: '0.2' }
    )
    const intent = signIntent(
      {
        intent_id: 'int_appr',
        actor: agent.id,
        delegation_chain: [root.delegation_id],
        action: 'apply',
        target: 'resource/example',
        parameters: { amount: 10 },
        nonce: 'n-appr-legacy',
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      agent,
      { profile: '0.2' }
    )
    const directory = new Map([
      [principal.id, principal.publicKey],
      [agent.id, agent.publicKey],
    ])
    const policyResolver = new ImmutablePolicyResolver()
    policyResolver.register(BASIC_AGENT_AUTHORITY, BASIC_AGENT_AUTHORITY_URI)
    const ledger = new NonceLedger()
    const pendingStore = new PendingAuthorizationStore()
    const pending = await runAuthorityPath({
      chain: [root],
      intent,
      directory,
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      clock: new FixedClock(NOW),
      ledger,
      pendingStore,
      policyResolver,
      signer,
      execute: () => ({ ok: true }),
    })
    expect(pending.decision).toBe('REQUIRE_HUMAN')
    const legacyApproval = signApproval(
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
    )
    expect(legacyApproval.adap).toBeUndefined()
    const resumed = await runAuthorityPath({
      chain: [root],
      intent,
      directory,
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      clock: new FixedClock(NOW),
      ledger,
      pendingStore,
      policyResolver,
      signer,
      approval: legacyApproval,
      execute: () => ({ ok: true }),
    })
    expect(resumed.decision).toBe('BLOCK')
    expect(resumed.executed).toBe(false)
    expect(resumed.reason).toMatch(/signed-object profile/)
  })

  it('rejects legacy context continued with a v0.2 approval', () => {
    const principal = createIdentity('prn_example')
    const agent = createIdentity('agt_example')
    const approval = signApproval(
      {
        intent_hash: 'a'.repeat(64),
        approver_id: principal.id,
        approved_at: ISSUED,
        decision: 'APPROVE',
        agent_id: agent.id,
        delegation_chain_hash: 'b'.repeat(64),
        policy_content_hash: 'c'.repeat(64),
      },
      principal,
      { profile: '0.2' }
    )
    expect(() => assertApprovalMatchesAuthorityProfile(approval, 'legacy')).toThrow(
      /signed-object profile/,
    )
    expect(() => assertIntentMatchesAuthorityProfile(
      signIntent(
        {
          intent_id: 'i',
          actor: agent.id,
          delegation_chain: ['d'],
          action: 'apply',
          target: 'resource/example',
          parameters: { amount: 1 },
          nonce: 'n',
          issued_at: ISSUED,
          expires_at: EXPIRES,
        },
        agent,
        { profile: '0.2' }
      ),
      'legacy'
    )).toThrow(/signed-object profile/)
  })

  it('accepts matching legacy approval bindings under verifyHumanApproval', () => {
    const principal = createIdentity('prn_example')
    const agent = createIdentity('agt_example')
    const intentHash = 'a'.repeat(64)
    const chainHash = 'b'.repeat(64)
    const policyHash = 'c'.repeat(64)
    const approval = signApproval(
      {
        intent_hash: intentHash,
        approver_id: principal.id,
        approved_at: ISSUED,
        decision: 'APPROVE',
        agent_id: agent.id,
        delegation_chain_hash: chainHash,
        policy_content_hash: policyHash,
      },
      principal
    )
    expect(() =>
      verifyHumanApproval({
        approval,
        intentHash,
        principalId: principal.id,
        agentId: agent.id,
        delegationChainHash: chainHash,
        policyContentHash: policyHash,
        intent: {
          intent_id: 'i',
          actor: agent.id,
          delegation_chain: ['d'],
          action: 'apply',
          target: 'resource/example',
          parameters: { amount: 1 },
          nonce: 'n',
          issued_at: ISSUED,
          expires_at: EXPIRES,
        },
        directory: new Map([[principal.id, principal.publicKey]]),
        now: NOW,
        authorityProfile: 'legacy',
      }),
    ).not.toThrow()
  })
})
