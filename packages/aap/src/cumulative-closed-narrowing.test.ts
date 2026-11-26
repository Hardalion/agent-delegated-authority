import { describe, expect, it } from 'vitest'
import type { Policy } from 'adap-policy'
import { FixedClock } from './clock.js'
import { MemorySpendLedger } from './spend.js'
import { NonceLedger } from './nonce.js'
import { runAuthorityPath } from './path.js'
import { PendingAuthorizationStore } from './pending.js'
import { ImmutablePolicyResolver } from './policy-resolver.js'
import { validateDelegationNarrowing } from './validate.js'
import { createIdentity, signDelegation, signIntent, type SignedDelegation } from './protocol.js'

const NOW = new Date('2026-10-06T18:00:00.000Z')
const ISSUED = NOW.toISOString()
const EXPIRES = new Date(NOW.getTime() + 15 * 60 * 1000).toISOString()

const ALLOW_APPLY: Policy = {
  version: '1.0.0',
  policyName: 'allow-apply',
  targetAgents: ['*'],
  defaultAction: 'BLOCK',
  rules: [{ ruleId: 'allow_apply', action: 'ALLOW', condition: "tool.name == 'apply'", alertSeverity: 'LOW' }],
}
const ALLOW_URI = 'allow-apply@1.0.0'

const prn = createIdentity('prn_example')
const agt = createIdentity('agt_example')
const agt2 = createIdentity('agt_example_child')
const signer = createIdentity('reference-runtime')
const directory = new Map([
  [prn.id, prn.publicKey],
  [agt.id, agt.publicKey],
  [agt2.id, agt2.publicKey],
])

function root(constraints: Record<string, string | number | boolean>): SignedDelegation {
  return signDelegation(
    {
      delegation_id: 'del_root',
      issuer: prn.id,
      subject: agt.id,
      capabilities: [{ action: 'apply', target: 'resource/*' }],
      constraints,
      issued_at: ISSUED,
      expires_at: EXPIRES,
    },
    prn,
  )
}

function child(constraints: Record<string, string | number | boolean>): SignedDelegation {
  return signDelegation(
    {
      delegation_id: 'del_child',
      issuer: agt.id,
      subject: agt2.id,
      parent_delegation_id: 'del_root',
      capabilities: [{ action: 'apply', target: 'resource/*' }],
      constraints,
      issued_at: ISSUED,
      expires_at: EXPIRES,
    },
    agt,
  )
}

describe('#58 closed-world admits the parameter a cumulative ceiling bounds', () => {
  it('ALLOWs an intent under closed:true + cumulative_max_amount with no max_amount', async () => {
    const policyResolver = new ImmutablePolicyResolver()
    policyResolver.register(ALLOW_APPLY, ALLOW_URI)
    const grant = root({ closed: true, cumulative_max_amount: 500, currency: 'EUR' })
    const result = await runAuthorityPath({
      unsafeDevAllowUnconfiguredChecks: true,
      chain: [grant],
      intent: signIntent(
        {
          intent_id: 'int_1',
          actor: agt.id,
          delegation_chain: ['del_root'],
          action: 'apply',
          target: 'resource/example',
          parameters: { amount: 100, currency: 'EUR' },
          nonce: 'n-58',
          issued_at: ISSUED,
          expires_at: EXPIRES,
        },
        agt,
      ),
      directory,
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      clock: new FixedClock(NOW),
      ledger: new NonceLedger(),
      spendLedger: new MemorySpendLedger(),
      pendingStore: new PendingAuthorizationStore(),
      policyResolver,
      signer,
      execute: () => ({ ok: true }),
    })
    expect(result.decision).toBe('ALLOW')
    expect(result.executed).toBe(true)
  })

  it('still rejects a genuinely undeclared parameter under closed:true', async () => {
    const policyResolver = new ImmutablePolicyResolver()
    policyResolver.register(ALLOW_APPLY, ALLOW_URI)
    const grant = root({ closed: true, cumulative_max_amount: 500, currency: 'EUR' })
    const result = await runAuthorityPath({
      unsafeDevAllowUnconfiguredChecks: true,
      chain: [grant],
      intent: signIntent(
        {
          intent_id: 'int_2',
          actor: agt.id,
          delegation_chain: ['del_root'],
          action: 'apply',
          target: 'resource/example',
          parameters: { amount: 100, currency: 'EUR', memo: 'x' },
          nonce: 'n-58b',
          issued_at: ISSUED,
          expires_at: EXPIRES,
        },
        agt,
      ),
      directory,
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      clock: new FixedClock(NOW),
      ledger: new NonceLedger(),
      spendLedger: new MemorySpendLedger(),
      pendingStore: new PendingAuthorizationStore(),
      policyResolver,
      signer,
      execute: () => ({ ok: true }),
    })
    expect(result.decision).toBe('BLOCK')
    expect(result.reason).toMatch(/undeclared parameter memo/)
  })
})

describe('#59 a child may lower any cumulative_<field>', () => {
  it('accepts a child that lowers cumulative_quantity', () => {
    expect(() =>
      validateDelegationNarrowing(
        root({ cumulative_quantity: 100 }),
        child({ cumulative_quantity: 50 }),
      ),
    ).not.toThrow()
  })

  it('still rejects a child that raises cumulative_quantity', () => {
    expect(() =>
      validateDelegationNarrowing(
        root({ cumulative_quantity: 100 }),
        child({ cumulative_quantity: 200 }),
      ),
    ).toThrow(/child raises cumulative_quantity/)
  })
})
