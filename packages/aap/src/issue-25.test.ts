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
} from './protocol.js'

const NOW = new Date('2026-10-06T18:00:00.000Z')
const ISSUED = NOW.toISOString()
const EXPIRES = new Date(NOW.getTime() + 15 * 60 * 1000).toISOString()

function env(options?: { readonly kindOnPrincipal?: 'human' | 'agent' }) {
  const principal = createIdentity('prn_example')
  const agent = createIdentity('agt_example')
  const signer = createIdentity('reference-runtime')
  const directory = new MemoryAuthorityDirectory([
    {
      identityId: principal.id,
      kid: principal.kid,
      alg: 'Ed25519',
      publicKey: principal.publicKey,
      status: 'active',
      kind: options?.kindOnPrincipal,
    },
    {
      identityId: agent.id,
      kid: agent.kid,
      alg: 'Ed25519',
      publicKey: agent.publicKey,
      status: 'active',
      kind: 'agent',
    },
    {
      identityId: signer.id,
      kid: signer.kid,
      alg: 'Ed25519',
      publicKey: signer.publicKey,
      status: 'active',
    },
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

function intentFor(
  agent: ReturnType<typeof createIdentity>,
  rootId: string,
  nonce: string,
  amount = 420
) {
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

describe('issue #25 pending nonce + root/approval kinds', () => {
  it('does not retire a pending nonce when approval schema is malformed', async () => {
    const { principal, agent, signer, directory, root, policyResolver } = env()
    const ledger = new NonceLedger()
    const pendingStore = new PendingAuthorizationStore()
    const intent = intentFor(agent, root.delegation_id, 'nonce-malformed-1')

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
    })
    expect(pending.decision).toBe('REQUIRE_HUMAN')
    expect(await ledger.statusOf(agent.id, intent.nonce)).toBe('pending')
    expect((await pendingStore.get(agent.id, intent.nonce))?.approvalState).toBe('pending')

    const blocked = await runAuthorityPath({
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
      approval: {
        intent_hash: pending.intentHash,
        approver_id: principal.id,
        approved_at: NOW.toISOString(),
        decision: 'APPROVE',
        agent_id: agent.id,
        delegation_chain_hash: sha256([root].map(unsignedDelegation)),
        policy_content_hash: pending.policyHash,
        matched_rule_id: pending.ruleId,
        signature: 'not-a-real-signature',
      } as never,
    })
    expect(blocked.decision).toBe('BLOCK')
    expect(await ledger.statusOf(agent.id, intent.nonce)).toBe('pending')
    expect((await pendingStore.get(agent.id, intent.nonce))?.approvalState).toBe('pending')

    const approval = signApproval(
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
    const approved = await runAuthorityPath({
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
      approval,
      execute: () => ({ ok: true }),
    })
    expect(approved.decision).toBe('ALLOW')
    expect(approved.executed).toBe(true)
  })

  it('rejects self-issued roots unless allowSelfIssuedRoot is set', async () => {
    const principal = createIdentity('prn_self')
    const signer = createIdentity('reference-runtime')
    const directory = new Map([
      [principal.id, principal.publicKey],
      [signer.id, signer.publicKey],
    ])
    const root = signDelegation(
      {
        delegation_id: 'del_self',
        issuer: principal.id,
        subject: principal.id,
        capabilities: [{ action: 'apply', target: 'resource/*', delegable: true }],
        constraints: { max_amount: 800 },
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      principal
    )
    const intent = signIntent(
      {
        intent_id: 'int_self',
        actor: principal.id,
        delegation_chain: [root.delegation_id],
        action: 'apply',
        target: 'resource/example',
        parameters: { amount: 10 },
        nonce: 'nonce-self-1',
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      principal
    )
    const policyResolver = new ImmutablePolicyResolver()
    policyResolver.register(BASIC_AGENT_AUTHORITY, BASIC_AGENT_AUTHORITY_URI)
    const ledger = new NonceLedger()

    const rejected = await runAuthorityPath({
      chain: [root],
      intent,
      directory,
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      clock: new FixedClock(NOW),
      ledger,
      pendingStore: new PendingAuthorizationStore(),
      policyResolver,
      signer,
    })
    expect(rejected.decision).toBe('BLOCK')
    expect(rejected.reason).toMatch(/self-issued root not allowed/)

    const allowed = await runAuthorityPath({
      chain: [root],
      intent,
      directory,
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      clock: new FixedClock(NOW),
      ledger: new NonceLedger(),
      pendingStore: new PendingAuthorizationStore(),
      policyResolver,
      signer,
      rootAuthority: {
        mayIssueRoot: () => true,
        allowSelfIssuedRoot: true,
      },
    })
    expect(allowed.decision).toBe('REQUIRE_HUMAN')
  })

  it('rejects approvals when the directory kind is configured as non-human', async () => {
    const { principal, agent, signer, directory, root, policyResolver } = env({
      kindOnPrincipal: 'agent',
    })
    const ledger = new NonceLedger()
    const pendingStore = new PendingAuthorizationStore()
    const intent = intentFor(agent, root.delegation_id, 'nonce-kind-1')

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
    })
    expect(pending.decision).toBe('REQUIRE_HUMAN')

    const approval = signApproval(
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
    const blocked = await runAuthorityPath({
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
      approval,
      execute: () => ({ ok: true }),
    })
    expect(blocked.decision).toBe('BLOCK')
    expect(blocked.reason).toMatch(/wrong identity kind/)
    expect(await ledger.statusOf(agent.id, intent.nonce)).toBe('pending')
  })
})
