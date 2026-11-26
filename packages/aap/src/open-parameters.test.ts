import { describe, expect, it } from 'vitest'
import type { Policy } from 'adap-policy'
import { FixedClock } from './clock.js'
import { NonceLedger } from './nonce.js'
import { ImmutablePolicyResolver } from './policy-resolver.js'
import { runAuthorityPath, type ExecutionContext } from './path.js'
import {
  createIdentity,
  signDelegation,
  signIntent,
  type Constraints,
  type SignProfile,
  type SignedDelegation,
} from './protocol.js'

const NOW = new Date('2026-11-26T14:00:00.000Z')
const ISSUED = NOW.toISOString()
const EXPIRES = new Date(NOW.getTime() + 15 * 60 * 1000).toISOString()
const AUD = 'adap-gateway.acme.example'
const ACTION = 'payments.transfer'
const TARGET = 'rail/acme'

const ALLOW_SMALL_TRANSFERS: Policy = {
  version: '1.0.0',
  policyName: 'allow-small-transfers',
  targetAgents: ['*'],
  defaultAction: 'BLOCK',
  rules: [
    {
      ruleId: 'transfer_under_cap',
      action: 'ALLOW',
      condition: "tool.name == 'payments.transfer' && args.amount <= 50000",
      alertSeverity: 'LOW',
    },
  ],
}
const POLICY_URI = 'allow-small-transfers@1.0.0'

const principal = createIdentity('prn_alice')
const agent = createIdentity('agt_shopper')
const subAgent = createIdentity('agt_shopper_sub')
const signer = createIdentity('reference-runtime')
const directory = new Map<string, string>([
  [principal.id, principal.publicKey],
  [agent.id, agent.publicKey],
  [subAgent.id, subAgent.publicKey],
])

function rootGrant(constraints: Constraints, profile: SignProfile = '0.2'): SignedDelegation {
  return signDelegation(
    {
      delegation_id: 'del_root',
      issuer: principal.id,
      subject: agent.id,
      capabilities: [{ action: ACTION, target: TARGET, delegable: true }],
      constraints,
      issued_at: ISSUED,
      expires_at: EXPIRES,
      aud: AUD,
    },
    principal,
    { profile }
  )
}

function childGrant(constraints: Constraints, profile: SignProfile = '0.2'): SignedDelegation {
  return signDelegation(
    {
      delegation_id: 'del_child',
      issuer: agent.id,
      subject: subAgent.id,
      capabilities: [{ action: ACTION, target: TARGET, delegable: false }],
      constraints,
      issued_at: ISSUED,
      expires_at: EXPIRES,
      parent_delegation_id: 'del_root',
      aud: AUD,
    },
    agent,
    { profile }
  )
}

let nonceCounter = 0

async function attempt(
  chain: readonly SignedDelegation[],
  parameters: Record<string, unknown>,
  profile: SignProfile = '0.2'
) {
  const actor = chain.length > 1 ? subAgent : agent
  const nonce = `open-params-${(nonceCounter += 1)}`
  const intent = signIntent(
    {
      intent_id: `int_${nonce}`,
      actor: actor.id,
      delegation_chain: chain.map((delegation) => delegation.delegation_id),
      action: ACTION,
      target: TARGET,
      parameters,
      nonce,
      issued_at: ISSUED,
      expires_at: EXPIRES,
      aud: AUD,
    },
    actor,
    { profile }
  )
  const policyResolver = new ImmutablePolicyResolver()
  policyResolver.register(ALLOW_SMALL_TRANSFERS, POLICY_URI)
  const dispatched: ExecutionContext[] = []
  const result = await runAuthorityPath({
    chain,
    intent,
    directory,
    policy: ALLOW_SMALL_TRANSFERS,
    policyUri: POLICY_URI,
    policyResolver,
    clock: new FixedClock(NOW),
    ledger: new NonceLedger(),
    signer,
    audience: AUD,
    rootAuthority: { mayIssueRoot: ({ issuerId }) => issuerId === principal.id },
    revocationCheck: () => 'active',
    execute: (ctx) => {
      dispatched.push(ctx)
      return { ok: true }
    },
  })
  return { result, dispatched }
}

const CAP = { max_amount: 50000, currency: 'USD' } as const

describe('#6 unnamed parameters (signed-object 0.2)', () => {
  it('blocks a recipient the grant never named (prompt-injected payee)', async () => {
    const { result, dispatched } = await attempt([rootGrant({ ...CAP })], {
      amount: 50000,
      currency: 'USD',
      recipient: 'IBAN-GB00-ATTACKER',
    })
    expect(result.decision).toBe('BLOCK')
    expect(result.ruleId).toBe('constraint')
    expect(dispatched).toHaveLength(0)
    expect(result.receipt?.execution?.executed).toBe(false)
  })

  it('blocks a smuggled extra argument next to a pinned recipient', async () => {
    const { result, dispatched } = await attempt(
      [rootGrant({ ...CAP, recipient: 'acme-supplies' })],
      {
        amount: 1200,
        currency: 'USD',
        recipient: 'acme-supplies',
        callback_url: 'https://evil.example/exfil',
      }
    )
    expect(result.decision).toBe('BLOCK')
    expect(dispatched).toHaveLength(0)
  })

  it('still allows a call that only uses parameters the grant names', async () => {
    const { result, dispatched } = await attempt(
      [rootGrant({ ...CAP, recipient: 'acme-supplies' })],
      { amount: 1200, currency: 'USD', recipient: 'acme-supplies' }
    )
    expect(result.decision).toBe('ALLOW')
    expect(dispatched).toHaveLength(1)
    expect(dispatched[0]?.parameters.recipient).toBe('acme-supplies')
  })

  it('allows unnamed parameters only when the grant signs closed: false', async () => {
    const { result, dispatched } = await attempt([rootGrant({ ...CAP, closed: false })], {
      amount: 1200,
      currency: 'USD',
      recipient: 'anyone',
    })
    expect(result.decision).toBe('ALLOW')
    expect(dispatched).toHaveLength(1)
  })
})

describe('#6 sub-agents cannot reopen a closed parent', () => {
  it('rejects a child that adds a parameter the closed parent did not declare', async () => {
    const root = rootGrant({ ...CAP, recipient: 'acme-supplies', closed: true })
    const child = childGrant({
      ...CAP,
      recipient: 'acme-supplies',
      closed: true,
      callback_url: 'https://evil.example/exfil',
    })
    const { result, dispatched } = await attempt([root, child], {
      amount: 1200,
      currency: 'USD',
      recipient: 'acme-supplies',
      callback_url: 'https://evil.example/exfil',
    })
    expect(result.decision).toBe('BLOCK')
    expect(dispatched).toHaveLength(0)
  })

  it('rejects the same widening when the parent is closed by default', async () => {
    const root = rootGrant({ ...CAP, recipient: 'acme-supplies' })
    const child = childGrant({ ...CAP, recipient: 'acme-supplies', memo: 'x' })
    const { result, dispatched } = await attempt([root, child], {
      amount: 1200,
      currency: 'USD',
      recipient: 'acme-supplies',
      memo: 'x',
    })
    expect(result.decision).toBe('BLOCK')
    expect(result.ruleId).toBe('narrowing')
    expect(dispatched).toHaveLength(0)
  })

  it('rejects a child that signs closed: false under a closed parent', async () => {
    const root = rootGrant({ ...CAP })
    const child = childGrant({ ...CAP, closed: false })
    const { result, dispatched } = await attempt([root, child], {
      amount: 1200,
      currency: 'USD',
      recipient: 'IBAN-GB00-ATTACKER',
    })
    expect(result.decision).toBe('BLOCK')
    expect(result.ruleId).toBe('narrowing')
    expect(dispatched).toHaveLength(0)
  })

  it('lets a child close an open parent', async () => {
    const root = rootGrant({ ...CAP, closed: false })
    const child = childGrant({ ...CAP, closed: true, recipient: 'acme-supplies' })
    const ok = await attempt([root, child], {
      amount: 1200,
      currency: 'USD',
      recipient: 'acme-supplies',
    })
    expect(ok.result.decision).toBe('ALLOW')
    const smuggled = await attempt([root, child], {
      amount: 1200,
      currency: 'USD',
      recipient: 'acme-supplies',
      note: 'extra',
    })
    expect(smuggled.result.decision).toBe('BLOCK')
    expect(smuggled.dispatched).toHaveLength(0)
  })
})

describe('#6 legacy v0.1 grants keep their signed meaning', () => {
  it('does not reinterpret a legacy grant (open unless closed: true)', async () => {
    const { result } = await attempt(
      [rootGrant({ max_amount: 50000 }, 'legacy')],
      { amount: 1200, recipient: 'anyone' },
      'legacy'
    )
    expect(result.decision).toBe('ALLOW')
  })
})