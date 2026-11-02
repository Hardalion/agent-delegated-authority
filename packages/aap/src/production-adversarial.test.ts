/**
 * Additional adversarial cases for production readiness (phase 8).
 * Does not weaken ADAP-001–011 or RT regressions.
 */
import { describe, expect, it } from 'vitest'
import type { Policy } from 'adap-policy'
import { FixedClock } from './clock.js'
import { AuthorityError } from './errors.js'
import { MemoryAtomicNonceBackend, NonceLedger } from './nonce.js'
import { PendingAuthorizationStore } from './pending.js'
import { ImmutablePolicyResolver } from './policy-resolver.js'
import { runAuthorityPath } from './path.js'
import { createIdentity, signDelegation, signIntent, signApproval } from './protocol.js'

const NOW = new Date('2026-10-06T18:00:00.000Z')
const ISSUED = NOW.toISOString()
const EXPIRES = new Date(NOW.getTime() + 15 * 60 * 1000).toISOString()

const ALLOW: Policy = {
  version: '1.0.0',
  policyName: 'allow-apply',
  targetAgents: ['*'],
  defaultAction: 'BLOCK',
  rules: [
    { ruleId: 'allow_apply', action: 'ALLOW', condition: "tool.name == 'apply'", alertSeverity: 'LOW' },
  ],
}
const HUMAN: Policy = {
  version: '1.0.0',
  policyName: 'human-apply',
  targetAgents: ['*'],
  defaultAction: 'BLOCK',
  rules: [
    {
      ruleId: 'need_human',
      action: 'REQUIRE_HUMAN',
      condition: "tool.name == 'apply'",
      alertSeverity: 'MEDIUM',
    },
  ],
}

function env(policy: Policy, uri: string) {
  const principal = createIdentity('prn_example')
  const agent = createIdentity('agt_personal')
  const signer = createIdentity('reference-runtime')
  const directory = new Map([
    [principal.id, principal.publicKey],
    [agent.id, agent.publicKey],
  ])
  const resolver = new ImmutablePolicyResolver()
  resolver.register(policy, uri)
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
  return { principal, agent, signer, directory, resolver, root, policy, uri }
}

describe('production adversarial suite', () => {
  it('rejects prototype-polluted parameters that break canonicalization', async () => {
    const e = env(ALLOW, 'allow@1')
    // __proto__ injection attempt on a plain object literal — must fail closed at canonicalization
    const parameters = JSON.parse('{"amount":10,"__proto__":{"admin":true}}')
    expect(() =>
      signIntent(
        {
          intent_id: 'int_proto',
          actor: e.agent.id,
          delegation_chain: [e.root.delegation_id],
          action: 'apply',
          target: 'resource/example',
          parameters,
          nonce: 'nonce-proto',
          issued_at: ISSUED,
          expires_at: EXPIRES,
        },
        e.agent,
      ),
    ).toThrow(/dangerous key|__proto__/)
  })

  it('rejects resource traversal targets', async () => {
    const e = env(ALLOW, 'allow@1')
    const intent = signIntent(
      {
        intent_id: 'int_trav',
        actor: e.agent.id,
        delegation_chain: [e.root.delegation_id],
        action: 'apply',
        target: 'resource/../admin',
        parameters: { amount: 1 },
        nonce: 'nonce-trav',
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      e.agent,
    )
    const result = await runAuthorityPath({
      chain: [e.root],
      intent,
      directory: e.directory,
      policy: e.policy,
      policyUri: e.uri,
      ledger: new NonceLedger(),
      signer: e.signer,
      policyResolver: e.resolver,
      clock: new FixedClock(NOW),
      execute: () => ({ ok: true }),
    })
    expect(result.executed).toBe(false)
  })

  it('numeric boundary: amount above grant is blocked', async () => {
    const e = env(ALLOW, 'allow@1')
    const intent = signIntent(
      {
        intent_id: 'int_amt',
        actor: e.agent.id,
        delegation_chain: [e.root.delegation_id],
        action: 'apply',
        target: 'resource/example',
        parameters: { amount: 10_000 },
        nonce: 'nonce-amt',
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      e.agent,
    )
    const result = await runAuthorityPath({
      chain: [e.root],
      intent,
      directory: e.directory,
      policy: e.policy,
      policyUri: e.uri,
      ledger: new NonceLedger(),
      signer: e.signer,
      policyResolver: e.resolver,
      clock: new FixedClock(NOW),
      execute: () => ({ ok: true }),
    })
    expect(result.executed).toBe(false)
    expect(result.decision).toBe('BLOCK')
  })

  it('approval after intent mutation does not authorize', async () => {
    const e = env(HUMAN, 'human@1')
    const pending = new PendingAuthorizationStore()
    const ledger = new NonceLedger()
    const intent = signIntent(
      {
        intent_id: 'int_mut',
        actor: e.agent.id,
        delegation_chain: [e.root.delegation_id],
        action: 'apply',
        target: 'resource/example',
        parameters: { amount: 10 },
        nonce: 'nonce-mut',
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      e.agent,
    )
    const first = await runAuthorityPath({
      chain: [e.root],
      intent,
      directory: e.directory,
      policy: e.policy,
      policyUri: e.uri,
      ledger,
      signer: e.signer,
      pendingStore: pending,
      policyResolver: e.resolver,
      clock: new FixedClock(NOW),
    })
    expect(first.decision).toBe('REQUIRE_HUMAN')
    const mutated = signIntent(
      {
        intent_id: 'int_mut',
        actor: e.agent.id,
        delegation_chain: [e.root.delegation_id],
        action: 'apply',
        target: 'resource/example',
        parameters: { amount: 500 },
        nonce: 'nonce-mut',
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      e.agent,
    )
    const approval = signApproval(
      {
        intent_hash: first.intentHash,
        approver_id: e.principal.id,
        approved_at: ISSUED,
        decision: 'APPROVE',
        agent_id: e.agent.id,
        delegation_chain_hash: first.delegationHash,
        policy_content_hash: first.policyHash,
        matched_rule_id: first.ruleId,
      },
      e.principal,
    )
    const second = await runAuthorityPath({
      chain: [e.root],
      intent: mutated,
      directory: e.directory,
      policy: e.policy,
      policyUri: e.uri,
      ledger,
      signer: e.signer,
      pendingStore: pending,
      policyResolver: e.resolver,
      clock: new FixedClock(NOW),
      approval,
      execute: () => ({ ok: true }),
    })
    expect(second.executed).toBe(false)
  })

  it('shared memory backend multi-ledger race: one claim winner', async () => {
    const backend = new MemoryAtomicNonceBackend()
    const la = new NonceLedger(backend)
    const lb = new NonceLedger(backend)
    la.reserve('race', 'h')
    backend.beforeCompareAndSwap = () => {
      lb.claimForExecution('race', 'h')
    }
    expect(() => la.claimForExecution('race', 'h')).toThrow(AuthorityError)
  })
})
