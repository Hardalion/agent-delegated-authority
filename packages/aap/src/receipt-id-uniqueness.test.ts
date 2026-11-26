import { describe, expect, it } from 'vitest'
import type { Policy } from 'adap-policy'
import { FixedClock } from './clock.js'
import { NonceLedger } from './nonce.js'
import { authenticatedReceipt, runAuthorityPath } from './path.js'
import { PendingAuthorizationStore } from './pending.js'
import { ImmutablePolicyResolver } from './policy-resolver.js'
import { createIdentity, signDelegation, signIntent } from './protocol.js'

const NOW = new Date('2026-10-06T18:00:00.000Z')
const ISSUED = NOW.toISOString()
const EXPIRES = new Date(NOW.getTime() + 15 * 60 * 1000).toISOString()

// defaultAction BLOCK and no matching rule: every presentation of the intent is refused.
const BLOCK_ALL: Policy = {
  version: '1.0.0',
  policyName: 'block-all',
  targetAgents: ['*'],
  defaultAction: 'BLOCK',
  // A rule that never matches 'apply', so every presentation falls to defaultAction BLOCK.
  rules: [{ ruleId: 'noop', action: 'ALLOW', condition: "tool.name == 'never'", alertSeverity: 'LOW' }],
}
const URI = 'block-all@1.0.0'

describe('#62 two refusals of the same intent get distinct receiptIds', () => {
  it('does not reuse a receiptId, so a receipt log passes duplicate detection', async () => {
    const prn = createIdentity('prn_example')
    const agt = createIdentity('agt_example')
    const signer = createIdentity('reference-runtime')
    const directory = new Map([
      [prn.id, prn.publicKey],
      [agt.id, agt.publicKey],
    ])
    const root = signDelegation(
      {
        delegation_id: 'del_root',
        issuer: prn.id,
        subject: agt.id,
        capabilities: [{ action: 'apply', target: 'resource/*' }],
        constraints: { max_amount: 800 },
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      prn,
    )
    const policyResolver = new ImmutablePolicyResolver()
    policyResolver.register(BLOCK_ALL, URI)
    const intent = signIntent(
      {
        intent_id: 'int_1',
        actor: agt.id,
        delegation_chain: ['del_root'],
        action: 'apply',
        target: 'resource/example',
        parameters: { amount: 10 },
        nonce: 'n-62',
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      agt,
    )
    const ledger = new NonceLedger()
    const run = () =>
      runAuthorityPath({
        unsafeDevAllowUnconfiguredChecks: true,
        chain: [root],
        intent,
        directory,
        policy: BLOCK_ALL,
        policyUri: URI,
        clock: new FixedClock(NOW),
        ledger,
        pendingStore: new PendingAuthorizationStore(),
        policyResolver,
        signer,
        execute: () => ({ ok: true }),
      })

    const first = await run()
    const second = await run()
    expect(first.decision).toBe('BLOCK')
    expect(second.decision).toBe('BLOCK')

    const id1 = authenticatedReceipt(first).receiptId
    const id2 = authenticatedReceipt(second).receiptId
    expect(id1).not.toBe(id2)
    expect(id1.startsWith('rcpt_')).toBe(true)
    expect(id2.startsWith('rcpt_')).toBe(true)
  })
})
