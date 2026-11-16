import { describe, expect, it } from 'vitest'
import type { Policy } from 'adap-policy'
import { FixedClock, MAX_ISSUED_AT_SKEW_MS } from './clock.js'
import { MemorySpendLedger } from './spend.js'
import { NonceLedger } from './nonce.js'
import { authenticatedReceipt, runAuthorityPath } from './path.js'
import { PendingAuthorizationStore } from './pending.js'
import { ImmutablePolicyResolver } from './policy-resolver.js'
import { createIdentity, signDelegation, signIntent } from './protocol.js'

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

function world(constraints: Record<string, number> = { max_amount: 800 }) {
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
      constraints,
      issued_at: ISSUED,
      expires_at: EXPIRES,
    },
    principal
  )
  const policyResolver = new ImmutablePolicyResolver()
  policyResolver.register(ALLOW_APPLY, ALLOW_URI)
  return { principal, agent, signer, directory, root, policyResolver }
}

function intentFor(
  agent: ReturnType<typeof createIdentity>,
  rootId: string,
  nonce: string,
  amount: number,
  issued = ISSUED,
  expires = EXPIRES
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
      issued_at: issued,
      expires_at: expires,
    },
    agent
  )
}

describe('review bounds: lifetime, skew, cumulative spend', () => {
  it('rejects a delegation lifetime over 24 hours', async () => {
    const { agent, signer, directory, policyResolver, principal } = world()
    const root = signDelegation(
      {
        delegation_id: 'del_long',
        issuer: principal.id,
        subject: agent.id,
        capabilities: [{ action: 'apply', target: 'resource/*', delegable: false }],
        constraints: { max_amount: 800 },
        issued_at: ISSUED,
        expires_at: new Date(NOW.getTime() + 25 * 60 * 60 * 1000).toISOString(),
      },
      principal
    )
    const result = await runAuthorityPath({
      chain: [root],
      intent: intentFor(agent, root.delegation_id, 'nonce-long', 10, ISSUED, EXPIRES),
      directory,
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      clock: new FixedClock(NOW),
      ledger: new NonceLedger(),
      pendingStore: new PendingAuthorizationStore(),
      policyResolver,
      signer,
      execute: () => ({ ok: true }),
    })
    expect(result.decision).toBe('BLOCK')
    expect(result.reason).toMatch(/24 hours/)
  })

  it('accepts issued_at slightly ahead only within the skew bound', async () => {
    const { agent, signer, directory, root, policyResolver } = world()
    const ahead = new Date(NOW.getTime() + 30_000).toISOString()
    const expires = new Date(NOW.getTime() + 15 * 60 * 1000).toISOString()
    const intent = intentFor(agent, root.delegation_id, 'nonce-skew', 10, ahead, expires)
    const base = {
      chain: [root],
      intent,
      directory,
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      clock: new FixedClock(NOW),
      pendingStore: new PendingAuthorizationStore(),
      policyResolver,
      signer,
      execute: () => ({ ok: true }),
    }
    const tight = await runAuthorityPath({ ...base, ledger: new NonceLedger() })
    expect(tight.decision).toBe('BLOCK')
    expect(tight.reason).toMatch(/not-yet-valid/)

    const loose = await runAuthorityPath({
      ...base,
      ledger: new NonceLedger(),
      issuedAtSkewMs: 60_000,
    })
    expect(loose.decision).toBe('ALLOW')
    expect(authenticatedReceipt(loose).extensions).toEqual({ issuedAtSkewMs: 60_000 })

    const over = await runAuthorityPath({
      ...base,
      ledger: new NonceLedger(),
      issuedAtSkewMs: MAX_ISSUED_AT_SKEW_MS + 1,
    })
    expect(over.decision).toBe('BLOCK')
    expect(over.authenticated).toBe(false)
  })

  it('does not let three 400 intents pass a 500 cumulative pool', async () => {
    const { agent, signer, directory, root, policyResolver } = world({
      max_amount: 800,
      cumulative_max_amount: 500,
    })
    const ledger = new NonceLedger()
    const spendLedger = new MemorySpendLedger()
    const run = (nonce: string, amount: number) =>
      runAuthorityPath({
        chain: [root],
        intent: intentFor(agent, root.delegation_id, nonce, amount),
        directory,
        policy: ALLOW_APPLY,
        policyUri: ALLOW_URI,
        clock: new FixedClock(NOW),
        ledger,
        spendLedger,
        pendingStore: new PendingAuthorizationStore(),
        policyResolver,
        signer,
        execute: () => ({ ok: true }),
      })

    const first = await run('n1', 400)
    expect(first.decision).toBe('ALLOW')
    expect(first.executed).toBe(true)

    const second = await run('n2', 400)
    expect(second.decision).toBe('BLOCK')
    expect(second.executed).toBe(false)
    expect(second.reason).toMatch(/cumulative/)

    const third = await run('n3', 100)
    expect(third.decision).toBe('ALLOW')
    expect(spendLedger.spent(root.delegation_id)).toBe(500)
  })

  it('fails closed when cumulative_max_amount is set and no ledger is passed', async () => {
    const { agent, signer, directory, root, policyResolver } = world({
      max_amount: 800,
      cumulative_max_amount: 500,
    })
    let executed = 0
    const blocked = await runAuthorityPath({
      chain: [root],
      intent: intentFor(agent, root.delegation_id, 'n-missing', 10),
      directory,
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      clock: new FixedClock(NOW),
      ledger: new NonceLedger(),
      pendingStore: new PendingAuthorizationStore(),
      policyResolver,
      signer,
      execute: () => {
        executed += 1
        return { ok: true }
      },
    })
    expect(blocked.decision).toBe('BLOCK')
    expect(blocked.reason).toMatch(/spend ledger is required/)
    expect(executed).toBe(0)
  })
})
