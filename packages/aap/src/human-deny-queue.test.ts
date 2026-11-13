import { describe, expect, it } from 'vitest'
import { FixedClock } from './clock.js'
import { sha256 } from './crypto.js'
import { BASIC_AGENT_AUTHORITY, BASIC_AGENT_AUTHORITY_URI } from './example-policy.js'
import { NonceLedger } from './nonce.js'
import { authenticatedReceipt, runAuthorityPath } from './path.js'
import { DEFAULT_MAX_PENDING_APPROVALS, PendingAuthorizationStore } from './pending.js'
import { ImmutablePolicyResolver } from './policy-resolver.js'
import {
  createIdentity,
  signApproval,
  signDelegation,
  signIntent,
  unsignedDelegation,
  unsignedIntent,
} from './protocol.js'

const NOW = new Date('2026-10-06T18:00:00.000Z')
const ISSUED = NOW.toISOString()
const EXPIRES = new Date(NOW.getTime() + 15 * 60 * 1000).toISOString()

function env() {
  const principal = createIdentity('prn_example')
  const agent = createIdentity('agt_example')
  const signer = createIdentity('reference-runtime')
  const directory = new Map([
    [principal.id, principal.publicKey],
    [agent.id, agent.publicKey],
    [signer.id, signer.publicKey],
  ])
  const root = signDelegation(
    {
      delegation_id: 'del_root',
      issuer: principal.id,
      subject: agent.id,
      capabilities: [{ action: 'apply', target: 'resource/*', delegable: true }],
      constraints: { max_amount: 800 },
      issued_at: ISSUED,
      expires_at: EXPIRES,
    },
    principal
  )
  const policyResolver = new ImmutablePolicyResolver()
  policyResolver.register(BASIC_AGENT_AUTHORITY, BASIC_AGENT_AUTHORITY_URI)
  return { principal, agent, signer, directory, root, policyResolver }
}

function intentFor(agent: ReturnType<typeof createIdentity>, rootId: string, nonce: string, amount = 420) {
  return signIntent(
    {
      intent_id: `int_${nonce}`,
      actor: agent.id,
      delegation_chain: [rootId],
      action: 'apply',
      target: 'resource/example',
      parameters: { amount },
      nonce,
      issued_at: ISSUED,
      expires_at: EXPIRES,
    },
    agent
  )
}

describe('human DENY and approval queue (#21)', () => {
  it('DENY never executes and emits a declined receipt', async () => {
    const { principal, agent, signer, directory, root, policyResolver } = env()
    const ledger = new NonceLedger()
    const pendingStore = new PendingAuthorizationStore()
    const intent = intentFor(agent, root.delegation_id, 'nonce-deny-1')
    let executed = 0
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
        executed += 1
        return { ok: true }
      },
    })
    expect(pending.decision).toBe('REQUIRE_HUMAN')

    const approval = signApproval(
      {
        intent_hash: pending.intentHash,
        approver_id: principal.id,
        approved_at: NOW.toISOString(),
        decision: 'DENY',
        agent_id: agent.id,
        delegation_chain_hash: sha256([root].map(unsignedDelegation)),
        policy_content_hash: pending.policyHash,
        matched_rule_id: pending.ruleId,
      },
      principal
    )
    const denied = await runAuthorityPath({
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
      approval,
      execute: () => {
        executed += 1
        return { ok: true }
      },
    })
    expect(denied.decision).toBe('BLOCK')
    expect(denied.executed).toBe(false)
    expect(executed).toBe(0)
    const receipt = authenticatedReceipt(denied)
    expect(receipt.human?.status).toBe('declined')
    expect(receipt.decision.action).toBe('BLOCK')

    // Cannot later approve the same pending request.
    const approve = signApproval(
      {
        intent_hash: pending.intentHash,
        approver_id: principal.id,
        approved_at: NOW.toISOString(),
        decision: 'APPROVE',
        agent_id: agent.id,
        delegation_chain_hash: sha256([root].map(unsignedDelegation)),
        policy_content_hash: pending.policyHash,
        matched_rule_id: pending.ruleId,
      },
      principal
    )
    const again = await runAuthorityPath({
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
      approval: approve,
      execute: () => {
        executed += 1
        return { ok: true }
      },
    })
    expect(again.decision).toBe('BLOCK')
    expect(executed).toBe(0)
  })

  it('blocks when the pending approval queue is full', async () => {
    const { principal, agent, signer, directory, root, policyResolver } = env()
    const ledger = new NonceLedger()
    const pendingStore = new PendingAuthorizationStore({ maxPendingApprovals: 2 })
    const base = {
      chain: [root] as const,
      directory,
      trustedRootIssuers: [principal.id],
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      clock: new FixedClock(NOW),
      ledger,
      pendingStore,
      policyResolver,
      signer,
      maxPendingApprovals: 2,
      execute: () => ({ ok: true }),
    }
    const first = await runAuthorityPath({
      ...base,
      intent: intentFor(agent, root.delegation_id, 'nonce-q1', 100),
    })
    const second = await runAuthorityPath({
      ...base,
      intent: intentFor(agent, root.delegation_id, 'nonce-q2', 110),
    })
    expect(first.decision).toBe('REQUIRE_HUMAN')
    expect(second.decision).toBe('REQUIRE_HUMAN')
    const thirdIntent = intentFor(agent, root.delegation_id, 'nonce-q3', 120)
    const full = await runAuthorityPath({
      ...base,
      intent: thirdIntent,
    })
    expect(full.decision).toBe('BLOCK')
    expect(full.ruleId).toBe('approval_queue_full')
    expect(full.executed).toBe(false)
    // Queue-full must not reserve the nonce.
    expect(ledger.assertUsable(agent.id, 'nonce-q3', sha256(unsignedIntent(thirdIntent)))).toBe('fresh')
    expect(DEFAULT_MAX_PENDING_APPROVALS).toBe(5)
    void principal
  })

  it('gives independent quotas to different agents under the same principal', async () => {
    const { principal, signer, directory, policyResolver } = env()
    const agentA = createIdentity('agt_a')
    const agentB = createIdentity('agt_b')
    directory.set(agentA.id, agentA.publicKey)
    directory.set(agentB.id, agentB.publicKey)
    const rootA = signDelegation(
      {
        delegation_id: 'del_a',
        issuer: principal.id,
        subject: agentA.id,
        capabilities: [{ action: 'apply', target: 'resource/*', delegable: true }],
        constraints: { max_amount: 800 },
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      principal
    )
    const rootB = signDelegation(
      {
        delegation_id: 'del_b',
        issuer: principal.id,
        subject: agentB.id,
        capabilities: [{ action: 'apply', target: 'resource/*', delegable: true }],
        constraints: { max_amount: 800 },
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      principal
    )
    const ledger = new NonceLedger()
    const pendingStore = new PendingAuthorizationStore({ maxPendingApprovals: 1 })
    const a1 = await runAuthorityPath({
      chain: [rootA],
      intent: intentFor(agentA, rootA.delegation_id, 'na1'),
      directory,
      trustedRootIssuers: [principal.id],
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      clock: new FixedClock(NOW),
      ledger,
      pendingStore,
      policyResolver,
      signer,
      maxPendingApprovals: 1,
    })
    const b1 = await runAuthorityPath({
      chain: [rootB],
      intent: intentFor(agentB, rootB.delegation_id, 'nb1'),
      directory,
      trustedRootIssuers: [principal.id],
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      clock: new FixedClock(NOW),
      ledger,
      pendingStore,
      policyResolver,
      signer,
      maxPendingApprovals: 1,
    })
    expect(a1.decision).toBe('REQUIRE_HUMAN')
    expect(b1.decision).toBe('REQUIRE_HUMAN')
  })
})
