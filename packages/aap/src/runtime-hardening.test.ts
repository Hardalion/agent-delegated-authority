import { describe, expect, it } from 'vitest'
import type { Policy } from 'adap-policy'
import { FixedClock } from './clock.js'
import { createIdentity, signDelegation, signIntent } from './protocol.js'
import { NonceLedger } from './nonce.js'
import { PendingAuthorizationStore } from './pending.js'
import { ImmutablePolicyResolver } from './policy-resolver.js'
import { authenticatedReceipt, runAuthorityPath } from './path.js'
import { MemorySpendLedger, cumulativeCharges } from './spend.js'

const NOW = new Date('2026-10-06T18:00:00.000Z')
const ISSUED = NOW.toISOString()
const EXPIRES = new Date(NOW.getTime() + 15 * 60 * 1000).toISOString()

const HUMAN: Policy = {
  version: '1.0.0',
  policyName: 'needs-human',
  targetAgents: ['*'],
  defaultAction: 'BLOCK',
  rules: [{ ruleId: 'wait', action: 'REQUIRE_HUMAN', condition: "tool.name == 'apply'", alertSeverity: 'MEDIUM' }],
}
const ALLOW: Policy = {
  version: '1.0.0',
  policyName: 'allow-apply',
  targetAgents: ['*'],
  defaultAction: 'BLOCK',
  rules: [{ ruleId: 'allow', action: 'ALLOW', condition: "tool.name == 'apply'", alertSeverity: 'LOW' }],
}

function env() {
  const principal = createIdentity('prn_example')
  const agent = createIdentity('agt_example')
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
      constraints: { max_amount: 100 },
      issued_at: ISSUED,
      expires_at: EXPIRES,
    },
    principal,
  )
  return { principal, agent, signer, directory, root }
}

describe('pending approval cannot be executed as ALLOW', () => {
  it('blocks a second worker that presents an ALLOW policy for a waiting nonce', async () => {
    const { principal, agent, signer, directory, root } = env()
    const humanResolver = new ImmutablePolicyResolver()
    const allowResolver = new ImmutablePolicyResolver()
    humanResolver.register(HUMAN, 'needs-human@1')
    allowResolver.register(ALLOW, 'allow-apply@1')
    const ledger = new NonceLedger()
    const intent = signIntent(
      {
        intent_id: 'int_wait',
        actor: agent.id,
        delegation_chain: [root.delegation_id],
        action: 'apply',
        target: 'resource/example',
        parameters: { amount: 10, secret: 'raw-token' },
        nonce: 'nonce-mixed-policy',
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      agent,
    )
    const pending = await runAuthorityPath({
      unsafeDevAllowUnconfiguredChecks: true,
      chain: [root],
      intent,
      directory,
      policy: HUMAN,
      policyUri: 'needs-human@1',
      clock: new FixedClock(NOW),
      ledger,
      pendingStore: new PendingAuthorizationStore(),
      policyResolver: humanResolver,
      signer,
    })
    expect(pending.decision).toBe('REQUIRE_HUMAN')
    let calls = 0
    const raced = await runAuthorityPath({
      unsafeDevAllowUnconfiguredChecks: true,
      chain: [root],
      intent,
      directory,
      policy: ALLOW,
      policyUri: 'allow-apply@1',
      clock: new FixedClock(NOW),
      ledger,
      pendingStore: new PendingAuthorizationStore(),
      policyResolver: allowResolver,
      signer,
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(raced.decision).toBe('BLOCK')
    expect(raced.reason).toMatch(/human approval/)
    expect(calls).toBe(0)
    expect(principal.id).toBeTruthy()
  })
})

describe('receipt redaction default', () => {
  it('does not copy raw tool inputs into a refusal receipt', async () => {
    const { agent, signer, directory, root } = env()
    const policy: Policy = {
      version: '1.0.0',
      policyName: 'block-apply',
      targetAgents: ['*'],
      defaultAction: 'BLOCK',
      rules: [{ ruleId: 'block', action: 'BLOCK', condition: "tool.name == 'apply'", alertSeverity: 'CRITICAL' }],
    }
    const resolver = new ImmutablePolicyResolver()
    resolver.register(policy, 'block-apply@1')
    const intent = signIntent(
      {
        intent_id: 'int_secret',
        actor: agent.id,
        delegation_chain: [root.delegation_id],
        action: 'apply',
        target: 'resource/example',
        parameters: { amount: 10, secret: 'raw-token' },
        nonce: 'nonce-redact',
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      agent,
    )
    const blocked = await runAuthorityPath({
      unsafeDevAllowUnconfiguredChecks: true,
      chain: [root],
      intent,
      directory,
      policy,
      policyUri: 'block-apply@1',
      clock: new FixedClock(NOW),
      ledger: new NonceLedger(),
      pendingStore: new PendingAuthorizationStore(),
      policyResolver: resolver,
      signer,
    })
    expect(blocked.decision).toBe('BLOCK')
    const receipt = authenticatedReceipt(blocked)
    expect(receipt.intent.argsRedacted).toEqual({})
    expect(JSON.stringify(receipt)).not.toContain('raw-token')
  })
})

describe('spend pools', () => {
  it('does not let a reused delegation id spend a higher ceiling against a lower cap', () => {
    const ledger = new MemorySpendLedger()
    expect(() =>
      ledger.spend([
        {
          delegationId: 'del_same',
          intentHash: 'h1',
          amount: 50,
          ceiling: 100,
          field: 'amount',
          currency: 'EUR',
        },
        {
          delegationId: 'del_same',
          intentHash: 'h1',
          amount: 50,
          ceiling: 10,
          field: 'amount',
          currency: 'EUR',
        },
      ]),
    ).toThrow(/cumulative/)
  })

  it('does not add amounts across currencies and rejects a missing currency', () => {
    const ledger = new MemorySpendLedger()
    ledger.spend([
      { delegationId: 'del', intentHash: 'eur', amount: 40, ceiling: 50, field: 'amount', currency: 'EUR' },
    ])
    ledger.spend([
      { delegationId: 'del', intentHash: 'usd', amount: 40, ceiling: 50, field: 'amount', currency: 'USD' },
    ])
    expect(ledger.spent('del')).toBe(80)
    expect(() =>
      ledger.spend([
        { delegationId: 'del', intentHash: 'more-eur', amount: 20, ceiling: 50, field: 'amount', currency: 'EUR' },
      ]),
    ).toThrow(/cumulative/)
    expect(() =>
      cumulativeCharges({
        chain: [{ delegation_id: 'del', constraints: { cumulative_max_amount: 10 } }],
        parameters: { amount: 1 },
        intentHash: 'h',
      }),
    ).toThrow(/currency/)
    expect(() =>
      cumulativeCharges({
        chain: [{ delegation_id: 'del', constraints: { cumulative_max_amount: 10, currency: 'EUR' } }],
        parameters: { amount: 1, currency: 'USD' },
        intentHash: 'h',
      }),
    ).toThrow(/currency/)
  })
})
