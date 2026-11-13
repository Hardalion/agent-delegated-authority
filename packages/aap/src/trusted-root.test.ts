import { describe, expect, it } from 'vitest'
import type { Policy } from 'adap-policy'
import {
  createIdentity,
  FixedClock,
  ImmutablePolicyResolver,
  NonceLedger,
  PendingAuthorizationStore,
  runAuthorityPath,
  signDelegation,
  signIntent,
  verifyAuthority,
} from './index.js'

const NOW = new Date('2026-11-11T12:00:00.000Z')
const ISSUED = NOW.toISOString()
const EXPIRES = new Date(NOW.getTime() + 15 * 60_000).toISOString()

const ALLOW_APPLY: Policy = {
  version: '1.0.0',
  policyName: 'trusted-root-allow',
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
const ALLOW_URI = 'trusted-root-allow@1'

function fixture(issuerName = 'prn_treasury') {
  const principal = createIdentity(issuerName)
  const agent = createIdentity('agt_treasury')
  const signer = createIdentity('iss_runtime')
  const directory = new Map([
    [principal.id, principal.publicKey],
    [agent.id, agent.publicKey],
  ])
  const root = signDelegation(
    {
      delegation_id: 'del_trusted_root',
      issuer: principal.id,
      subject: agent.id,
      capabilities: [{ action: 'apply', target: 'resource/*', delegable: false }],
      constraints: { max_amount: 100 },
      issued_at: ISSUED,
      expires_at: EXPIRES,
    },
    principal,
  )
  const intent = signIntent(
    {
      intent_id: 'int_trusted',
      actor: agent.id,
      delegation_chain: [root.delegation_id],
      action: 'apply',
      target: 'resource/example',
      parameters: { amount: 1 },
      nonce: 'n-trusted-root',
      issued_at: ISSUED,
      expires_at: EXPIRES,
    },
    agent,
  )
  const resolver = new ImmutablePolicyResolver()
  resolver.register(ALLOW_APPLY, ALLOW_URI)
  return { principal, agent, signer, directory, root, intent, resolver }
}

describe('trusted root issuers', () => {
  it('fails closed when the executable path omits every root trust policy', async () => {
    const { principal, agent, signer, directory, root, intent, resolver } = fixture()
    const ledger = new NonceLedger()
    const pendingStore = new PendingAuthorizationStore()
    let executed = 0
    const result = await runAuthorityPath({
      chain: [root],
      intent,
      directory,
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      ledger,
      pendingStore,
      policyResolver: resolver,
      signer,
      clock: new FixedClock(NOW),
      execute: () => {
        executed += 1
        return { ok: true }
      },
    })
    expect(result.decision).toBe('BLOCK')
    expect(result.authenticated).toBe(false)
    expect(result.executed).toBe(false)
    expect(result.ruleId).toBe('root_not_authorized')
    expect(executed).toBe(0)
    expect(ledger.statusOf(agent.id, intent.nonce)).toBeUndefined()
    expect(pendingStore.get(agent.id, intent.nonce)).toBeUndefined()
    void principal
  })

  it('fails closed when the allow-list is empty', async () => {
    const { agent, signer, directory, root, intent, resolver } = fixture()
    const ledger = new NonceLedger()
    let executed = 0
    const result = await runAuthorityPath({
      chain: [root],
      intent,
      directory,
      trustedRootIssuers: [],
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      ledger,
      pendingStore: new PendingAuthorizationStore(),
      policyResolver: resolver,
      signer,
      clock: new FixedClock(NOW),
      execute: () => {
        executed += 1
        return { ok: true }
      },
    })
    expect(result.decision).toBe('BLOCK')
    expect(result.authenticated).toBe(false)
    expect(result.executed).toBe(false)
    expect(executed).toBe(0)
    expect(ledger.statusOf(agent.id, intent.nonce)).toBeUndefined()
  })

  it('rejects a self-issued root that is only present in the directory', async () => {
    const operator = createIdentity('prn_operator')
    const impostor = createIdentity('prn_impostor')
    const agent = createIdentity('agt_agent')
    const signer = createIdentity('iss_runtime')
    const directory = new Map([
      [operator.id, operator.publicKey],
      [impostor.id, impostor.publicKey],
      [agent.id, agent.publicKey],
    ])
    const forgedRoot = signDelegation(
      {
        delegation_id: 'del_forged_root',
        issuer: impostor.id,
        subject: agent.id,
        capabilities: [{ action: 'apply', target: 'resource/*', delegable: false }],
        constraints: { max_amount: 100 },
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      impostor,
    )
    const intent = signIntent(
      {
        intent_id: 'int_forged',
        actor: agent.id,
        delegation_chain: [forgedRoot.delegation_id],
        action: 'apply',
        target: 'resource/example',
        parameters: { amount: 1 },
        nonce: 'n-forged-root',
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      agent,
    )

    expect(() =>
      verifyAuthority({
        chain: [forgedRoot],
        intent,
        directory,
        now: NOW,
        trustedRootIssuers: [operator.id],
      }),
    ).toThrow(/trusted authority/i)

    const resolver = new ImmutablePolicyResolver()
    resolver.register(ALLOW_APPLY, ALLOW_URI)
    const ledger = new NonceLedger()
    const pendingStore = new PendingAuthorizationStore()
    let executed = 0
    const result = await runAuthorityPath({
      chain: [forgedRoot],
      intent,
      directory,
      trustedRootIssuers: [operator.id],
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      ledger,
      pendingStore,
      policyResolver: resolver,
      signer,
      clock: new FixedClock(NOW),
      execute: () => {
        executed += 1
        return { ok: true }
      },
    })
    expect(result.executed).toBe(false)
    expect(result.authenticated).toBe(false)
    expect(result.decision).toBe('BLOCK')
    expect(executed).toBe(0)
    expect(ledger.statusOf(agent.id, intent.nonce)).toBeUndefined()
    expect(pendingStore.get(agent.id, intent.nonce)).toBeUndefined()
  })

  it('accepts a root only when the issuer is operator-trusted', async () => {
    const { principal, signer, directory, root, intent, resolver } = fixture()
    let executed = 0
    const result = await runAuthorityPath({
      chain: [root],
      intent,
      directory,
      trustedRootIssuers: new Set([principal.id]),
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      ledger: new NonceLedger(),
      pendingStore: new PendingAuthorizationStore(),
      policyResolver: resolver,
      signer,
      clock: new FixedClock(NOW),
      execute: () => {
        executed += 1
        return { ok: true }
      },
    })
    expect(result.authenticated).toBe(true)
    expect(result.decision).toBe('ALLOW')
    expect(result.executed).toBe(true)
    expect(executed).toBe(1)
  })

  it('lets rootAuthority allow or reject based on issuer, subject and capabilities', async () => {
    const { principal, agent, signer, directory, root, intent, resolver } = fixture()
    let executed = 0
    const denied = await runAuthorityPath({
      chain: [root],
      intent,
      directory,
      rootAuthority: {
        mayIssueRoot: (input) =>
          input.issuerId === principal.id &&
          input.subjectId === agent.id &&
          input.capabilities.some((cap) => cap.action === 'payment'),
      },
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      ledger: new NonceLedger(),
      pendingStore: new PendingAuthorizationStore(),
      policyResolver: resolver,
      signer,
      clock: new FixedClock(NOW),
      execute: () => {
        executed += 1
        return { ok: true }
      },
    })
    expect(denied.authenticated).toBe(false)
    expect(denied.decision).toBe('BLOCK')
    expect(denied.ruleId).toBe('root_not_authorized')
    expect(executed).toBe(0)

    const allowed = await runAuthorityPath({
      chain: [root],
      intent: signIntent(
        {
          intent_id: 'int_root_cb',
          actor: agent.id,
          delegation_chain: [root.delegation_id],
          action: 'apply',
          target: 'resource/example',
          parameters: { amount: 1 },
          nonce: 'n-root-cb-ok',
          issued_at: ISSUED,
          expires_at: EXPIRES,
        },
        agent,
      ),
      directory,
      rootAuthority: {
        mayIssueRoot: (input) =>
          input.issuerId === principal.id &&
          input.subjectId === agent.id &&
          input.capabilities.some((cap) => cap.action === 'apply' && cap.target === 'resource/*'),
      },
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      ledger: new NonceLedger(),
      pendingStore: new PendingAuthorizationStore(),
      policyResolver: resolver,
      signer,
      clock: new FixedClock(NOW),
      execute: () => {
        executed += 1
        return { ok: true }
      },
    })
    expect(allowed.authenticated).toBe(true)
    expect(allowed.decision).toBe('ALLOW')
    expect(allowed.executed).toBe(true)
    expect(executed).toBe(1)
  })
})
