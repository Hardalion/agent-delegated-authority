/**
 * Independent regressions for RT-01, RT-03, and RT-04.
 * These tests assert the security properties, not the internal helper names.
 */
import { describe, expect, it } from 'vitest'
import { FixedClock } from './clock.js'
import type { Policy } from 'adap-policy'
import { importPublicKey, sha256 } from './crypto.js'
import { BASIC_AGENT_AUTHORITY, BASIC_AGENT_AUTHORITY_URI } from './example-policy.js'
import { NonceLedger } from './nonce.js'
import { PendingAuthorizationStore } from './pending.js'
import { ImmutablePolicyResolver, type PolicyResolver } from './policy-resolver.js'
import {
  authenticatedReceipt,
  runAuthorityPath,
  verifyProtocolReceipt,
  type ExecutionContext,
  type ProtocolResult,
} from './path.js'
import {
  createIdentity,
  signApproval,
  signDelegation,
  signIntent,
  unsignedDelegation,
  unsignedIntent,
  type Identity,
  type SignedDelegation,
  type SignedIntent,
} from './protocol.js'

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

function deferred() {
  let release!: () => void
  const hold = new Promise<void>((resolve) => {
    release = resolve
  })
  return { hold, release }
}

function actors(maxAmount = 800) {
  const principal = createIdentity('prn_example')
  const agent = createIdentity('agt_personal')
  const signer = createIdentity('reference-runtime')
  const directory = new Map<string, string>([
    [principal.id, principal.publicKey],
    [agent.id, agent.publicKey],
  ])
  const root = signDelegation(
    {
      delegation_id: 'del_root',
      issuer: principal.id,
      subject: agent.id,
      capabilities: [{ action: 'apply', target: 'resource/*', delegable: false }],
      constraints: { max_amount: maxAmount },
      issued_at: ISSUED,
      expires_at: EXPIRES,
    },
    principal
  )
  return { principal, agent, signer, directory, root }
}

function signed(
  agent: Identity,
  root: SignedDelegation,
  parameters: Record<string, unknown>,
  nonce: string,
  action = 'apply'
): SignedIntent {
  return signIntent(
    {
      intent_id: `int_${nonce}`,
      actor: agent.id,
      delegation_chain: [root.delegation_id],
      action,
      target: 'resource/example',
      parameters,
      nonce,
      issued_at: ISSUED,
      expires_at: EXPIRES,
    },
    agent
  )
}

function run(
  env: ReturnType<typeof actors>,
  intent: SignedIntent,
  options: {
    readonly ledger?: NonceLedger
    readonly policy?: Policy
    readonly policyUri?: string
    readonly pendingStore?: PendingAuthorizationStore
    readonly policyResolver?: PolicyResolver
    readonly approval?: ReturnType<typeof signApproval>
    readonly execute?: (ctx: ExecutionContext) => unknown
  } = {}
): Promise<ProtocolResult> {
  const policy = options.policy ?? ALLOW_APPLY
  const policyUri = options.policyUri ?? ALLOW_URI
  const policyResolver = options.policyResolver ?? new ImmutablePolicyResolver()
  if (!options.policyResolver) policyResolver.register(policy, policyUri)
  return runAuthorityPath({
    chain: [env.root],
    intent,
    directory: env.directory,
    trustedRootIssuers: [env.principal.id],
    policy,
    policyUri,
    clock: new FixedClock(NOW),
    ledger: options.ledger ?? new NonceLedger(),
    pendingStore: options.pendingStore,
    policyResolver,
    signer: env.signer,
    approval: options.approval,
    execute: options.execute ?? (() => ({ ok: true })),
  })
}

function approvalFor(
  env: ReturnType<typeof actors>,
  pending: ProtocolResult
) {
  return signApproval(
    {
      intent_hash: pending.intentHash,
      approver_id: env.principal.id,
      approved_at: ISSUED,
      decision: 'APPROVE',
      agent_id: env.agent.id,
      delegation_chain_hash: sha256([unsignedDelegation(env.root)]),
      policy_content_hash: pending.policyHash,
      matched_rule_id: pending.ruleId,
    },
    env.principal
  )
}

describe('RT-01 immutable authorization snapshot', () => {
  it('keeps the authorized nested values when the caller mutates them during the executor yield', async () => {
    const env = actors()
    const meta = { dest: 'legit' }
    const items = ['legit']
    const parameters: Record<string, unknown> = { amount: 10, meta, items }
    const intent = signed(env.agent, env.root, parameters, 'rt01-yield')
    const authorizedHash = sha256(unsignedIntent(intent))
    const { hold, release } = deferred()
    const seen: ExecutionContext[] = []
    let calls = 0

    const pending = run(env, intent, {
      execute: async (ctx) => {
        calls += 1
        await hold
        seen.push(ctx)
        return { dest: (ctx.parameters.meta as { dest: string }).dest }
      },
    })

    meta.dest = 'evil'
    items[0] = 'evil'
    items.push('extra')
    parameters.meta = { dest: 'replaced' }
    parameters.amount = 999
    intent.parameters = { amount: 1, meta: { dest: 'replaced-top' } }
    release()

    const result = await pending
    expect(result.decision).toBe('ALLOW')
    expect(result.executed).toBe(true)
    expect(result.authenticated).toBe(true)
    expect(calls).toBe(1)
    expect(seen).toHaveLength(1)
    expect(seen[0]?.action).toBe('apply')
    expect(seen[0]?.parameters.amount).toBe(10)
    expect(seen[0]?.parameters.meta).toEqual({ dest: 'legit' })
    expect(seen[0]?.parameters.items).toEqual(['legit'])
    expect(seen[0]?.parameters.meta).not.toBe(meta)
    const receipt = authenticatedReceipt(result)
    expect(receipt.intent.argsRedacted).toEqual({ amount: 10, meta: { dest: 'legit' }, items: ['legit'] })
    expect(receipt.execution?.intentHash).toBe(authorizedHash)
    expect(verifyProtocolReceipt(receipt, importPublicKey(env.signer.publicKey)).valid).toBe(true)
  })

  it('does not re-read a live accessor after the snapshot', async () => {
    const env = actors()
    let reads = 0
    const parameters = {}
    Object.defineProperty(parameters, 'amount', {
      enumerable: true,
      configurable: true,
      get() {
        reads += 1
        return reads < 3 ? 10 : 999
      },
    })
    Object.defineProperty(parameters, 'note', { enumerable: true, value: 'example' })
    const intent = signed(env.agent, env.root, parameters, 'rt01-getter')
    let observed: unknown
    const result = await run(env, intent, {
      execute: (ctx) => {
        observed = ctx.parameters.amount
        return { amount: observed }
      },
    })
    expect(result.decision).toBe('ALLOW')
    expect(result.executed).toBe(true)
    expect(observed).toBe(10)
    expect(authenticatedReceipt(result).intent.argsRedacted).toMatchObject({ amount: 10 })
    expect(observed).not.toBe(999)
  })

  it('rejects a mutated continuation and never executes the mutated parameters', async () => {
    const env = actors()
    const meta = { dest: 'legit' }
    const intent = signed(env.agent, env.root, { amount: 10, note: 'example', meta }, 'rt01-before-approval')
    const authorizedHash = sha256(unsignedIntent(intent))
    const ledger = new NonceLedger()
    const pendingStore = new PendingAuthorizationStore()
    const policyResolver = new ImmutablePolicyResolver()
    policyResolver.register(BASIC_AGENT_AUTHORITY, BASIC_AGENT_AUTHORITY_URI)
    let calls = 0
    const pending = await run(env, intent, {
      ledger,
      pendingStore,
      policyResolver,
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(pending.decision).toBe('REQUIRE_HUMAN')
    expect(pending.intentHash).toBe(authorizedHash)
    expect(authenticatedReceipt(pending).intent.argsRedacted).toMatchObject({ meta: { dest: 'legit' }, amount: 10 })

    meta.dest = 'evil'
    const continued = await run(env, intent, {
      ledger,
      pendingStore,
      policyResolver,
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      approval: approvalFor(env, pending),
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(continued.decision).toBe('BLOCK')
    expect(continued.executed).toBe(false)
    expect(continued.authenticated).toBe(false)
    expect(calls).toBe(0)
  })

  it('executes the approved snapshot when the caller mutates after approval is recorded', async () => {
    const env = actors()
    const meta = { dest: 'legit' }
    const intent = signed(env.agent, env.root, { amount: 10, note: 'example', meta }, 'rt01-after-approval')
    const authorizedHash = sha256(unsignedIntent(intent))
    const ledger = new NonceLedger()
    const pendingStore = new PendingAuthorizationStore()
    const policyResolver = new ImmutablePolicyResolver()
    policyResolver.register(BASIC_AGENT_AUTHORITY, BASIC_AGENT_AUTHORITY_URI)
    const seen: unknown[] = []
    const pending = await run(env, intent, {
      ledger,
      pendingStore,
      policyResolver,
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      execute: () => ({ ok: true }),
    })
    expect(pending.decision).toBe('REQUIRE_HUMAN')

    const original = pendingStore.markApproved.bind(pendingStore)
    pendingStore.markApproved = (nonce, intentHash) => {
      original(nonce, intentHash)
      meta.dest = 'evil'
      intent.parameters = { amount: 999, note: 'example', meta: { dest: 'evil' } }
    }
    const result = await run(env, intent, {
      ledger,
      pendingStore,
      policyResolver,
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      approval: approvalFor(env, pending),
      execute: (ctx) => {
        seen.push(ctx.parameters)
        return { dest: (ctx.parameters.meta as { dest: string }).dest }
      },
    })
    expect(result.decision).toBe('ALLOW')
    expect(result.executed).toBe(true)
    expect(seen).toEqual([{ amount: 10, note: 'example', meta: { dest: 'legit' } }])
    const receipt = authenticatedReceipt(result)
    expect(receipt.intent.argsRedacted).toEqual({ amount: 10, note: 'example', meta: { dest: 'legit' } })
    expect(receipt.execution?.intentHash).toBe(authorizedHash)
    expect(receipt.human?.status).toBe('approved')
  })

  it('ignores a nested mutation performed by the policy resolver', async () => {
    const env = actors()
    const meta = { dest: 'legit' }
    const intent = signed(env.agent, env.root, { amount: 10, meta }, 'rt01-resolver')
    const resolver = new ImmutablePolicyResolver()
    resolver.register(ALLOW_APPLY, ALLOW_URI)
    const original = resolver.resolveByUri.bind(resolver)
    resolver.resolveByUri = (uri) => {
      meta.dest = 'evil'
      return original(uri)
    }
    let observed: unknown
    const result = await run(env, intent, {
      policyResolver: resolver,
      execute: (ctx) => {
        observed = (ctx.parameters.meta as { dest: string }).dest
        return { dest: observed }
      },
    })
    expect(result.decision).toBe('ALLOW')
    expect(observed).toBe('legit')
    expect(authenticatedReceipt(result).intent.argsRedacted).toMatchObject({ meta: { dest: 'legit' } })
  })

  it('lets one concurrent execution proceed with the authorized nested value', async () => {
    const env = actors()
    const meta = { dest: 'legit' }
    const intent = signed(env.agent, env.root, { amount: 10, meta }, 'rt01-concurrent')
    const ledger = new NonceLedger()
    const { hold, release } = deferred()
    let signalClaimed!: () => void
    const claimed = new Promise<void>((resolve) => {
      signalClaimed = resolve
    })
    const seen: unknown[] = []
    let calls = 0
    const firstPromise = run(env, intent, {
      ledger,
      execute: async (ctx) => {
        calls += 1
        signalClaimed()
        await hold
        seen.push((ctx.parameters.meta as { dest: string }).dest)
        return { ok: true }
      },
    })
    await claimed
    const second = await run(env, intent, {
      ledger,
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    meta.dest = 'evil'
    release()
    const first = await firstPromise
    expect(first.decision).toBe('ALLOW')
    expect(first.executed).toBe(true)
    expect(second.decision).toBe('BLOCK')
    expect(second.executed).toBe(false)
    expect(second.reason).toBe('nonce_in_flight_or_used')
    expect(calls).toBe(1)
    expect(seen).toEqual(['legit'])
  })
})

describe('RT-03 authentication before nonce consumption', () => {
  it('does not consume a nonce for an invalid signature with a malformed amount', async () => {
    const env = actors()
    const ledger = new NonceLedger()
    const good = signed(env.agent, env.root, { amount: 10, note: 'example' }, 'rt03-amount')
    const forged = {
      ...good,
      parameters: { amount: -1, note: 'example' },
      signature: 'not-a-signature',
    } as SignedIntent
    let calls = 0
    const first = await run(env, forged, {
      ledger,
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      pendingStore: new PendingAuthorizationStore(),
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(first.decision).toBe('BLOCK')
    expect(first.authenticated).toBe(false)
    expect(first.receipt).toBeUndefined()
    expect(first.executed).toBe(false)
    expect(first.reason).not.toContain('not-a-signature')
    expect(ledger.has('rt03-amount')).toBe(false)
    expect(calls).toBe(0)

    const second = await run(env, good, {
      ledger,
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      pendingStore: new PendingAuthorizationStore(),
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(second.decision).toBe('REQUIRE_HUMAN')
    expect(second.ruleId).not.toBe('replay')
    expect(second.authenticated).toBe(true)
    expect(calls).toBe(0)
  })

  it('does not consume a nonce for an invalid signature on an otherwise valid payload', async () => {
    const env = actors()
    const ledger = new NonceLedger()
    const good = signed(env.agent, env.root, { amount: 10 }, 'rt03-valid-looking')
    const forged = { ...good, signature: 'aa' } as SignedIntent
    const first = await run(env, forged, { ledger })
    expect(first.authenticated).toBe(false)
    expect(first.receipt).toBeUndefined()
    expect(first.executed).toBe(false)
    expect(ledger.has('rt03-valid-looking')).toBe(false)

    let calls = 0
    const second = await run(env, good, {
      ledger,
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(second.decision).toBe('ALLOW')
    expect(second.executed).toBe(true)
    expect(calls).toBe(1)

    const replay = await run(env, good, {
      ledger,
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(replay.decision).toBe('BLOCK')
    expect(replay.ruleId).toBe('replay')
    expect(replay.executed).toBe(false)
    expect(calls).toBe(1)
  })

  it('does not let an invalid signature reserve another principal nonce while a valid request is in flight', async () => {
    const env = actors()
    const other = createIdentity('agt_other')
    env.directory.set(other.id, other.publicKey)
    const ledger = new NonceLedger()
    const good = signed(env.agent, env.root, { amount: 10 }, 'rt03-race')
    const forged = { ...good, signature: 'not-a-signature' } as SignedIntent
    const { hold, release } = deferred()
    let signalClaimed!: () => void
    const claimed = new Promise<void>((resolve) => {
      signalClaimed = resolve
    })
    let calls = 0
    const validPromise = run(env, good, {
      ledger,
      execute: async () => {
        calls += 1
        signalClaimed()
        await hold
        return { ok: true }
      },
    })
    await claimed
    const invalid = await run(env, forged, {
      ledger,
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    release()
    const valid = await validPromise
    expect(invalid.authenticated).toBe(false)
    expect(invalid.receipt).toBeUndefined()
    expect(invalid.executed).toBe(false)
    expect(valid.decision).toBe('ALLOW')
    expect(valid.executed).toBe(true)
    expect(calls).toBe(1)
    const replay = await run(env, good, { ledger })
    expect(replay.ruleId).toBe('replay')
    expect(replay.executed).toBe(false)
  })

  it('fails closed on a malformed signature and does not consume the nonce', async () => {
    const env = actors()
    const good = signed(env.agent, env.root, { amount: 10 }, 'rt03-malformed')
    for (const signature of ['', '%%%', 'not-a-signature']) {
      const ledger = new NonceLedger()
      const result = await run(env, { ...good, signature } as SignedIntent, { ledger })
      expect(result.decision).toBe('BLOCK')
      expect(result.authenticated).toBe(false)
      expect(result.receipt).toBeUndefined()
      expect(result.executed).toBe(false)
      if (signature.length > 0) expect(result.reason).not.toContain(signature)
      expect(ledger.has('rt03-malformed')).toBe(false)
    }
  })

  it('consumes a nonce only after a valid signature, including an authenticated malformed amount', async () => {
    const env = actors()
    const ledger = new NonceLedger()
    let calls = 0
    const bad = signed(env.agent, env.root, { amount: -1 }, 'rt03-authenticated-amount')
    const result = await run(env, bad, {
      ledger,
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(result.decision).toBe('BLOCK')
    expect(result.authenticated).toBe(true)
    expect(result.executed).toBe(false)
    expect(result.ruleId).toBe('amount')
    expect(calls).toBe(0)
    expect(ledger.statusOf('rt03-authenticated-amount')).toBe('consumed')
    const receipt = authenticatedReceipt(result)
    expect(receipt.execution?.executed).toBe(false)
    expect(verifyProtocolReceipt(receipt, importPublicKey(env.signer.publicKey)).valid).toBe(true)
    const again = await run(env, bad, { ledger })
    expect(again.ruleId).toBe('replay')
  })
})

describe('RT-04 controlled authority error boundary', () => {
  async function rejected(parameters: Record<string, unknown>, nonce: string) {
    const env = actors()
    const carrier = signed(env.agent, env.root, { amount: 10 }, nonce)
    const intent = { ...carrier, parameters } as SignedIntent
    let calls = 0
    let thrown: unknown
    let result: ProtocolResult | undefined
    try {
      result = await run(env, intent, {
        execute: () => {
          calls += 1
          return { ok: true }
        },
      })
    } catch (error) {
      thrown = error
    }
    return { env, result, thrown, calls }
  }

  it('turns NaN, Infinity, cycles, and unsupported values into structured failures', async () => {
    const nan = await rejected({ amount: Number.NaN }, 'rt04-nan')
    expect(nan.thrown).toBeUndefined()
    expect(nan.result?.decision).toBe('BLOCK')
    expect(nan.result?.executed).toBe(false)
    expect(nan.result?.authenticated).toBe(false)
    expect(nan.result?.receipt).toBeUndefined()
    expect(nan.result?.ruleId).toBe('canonicalization')
    expect(nan.calls).toBe(0)

    for (const value of [Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      const outcome = await rejected({ amount: value }, `rt04-${value}`)
      expect(outcome.thrown).toBeUndefined()
      expect(outcome.result?.authenticated).toBe(false)
      expect(outcome.result?.receipt).toBeUndefined()
      expect(outcome.result?.executed).toBe(false)
      expect(outcome.result?.ruleId).toBe('canonicalization')
      expect(outcome.calls).toBe(0)
    }

    const cycle: Record<string, unknown> = { dest: 'legit' }
    cycle.self = cycle
    const cyclic = await rejected({ amount: 10, meta: cycle }, 'rt04-cycle')
    expect(cyclic.thrown).toBeUndefined()
    expect(cyclic.result?.authenticated).toBe(false)
    expect(cyclic.result?.receipt).toBeUndefined()
    expect(cyclic.result?.reason).toContain('cycle')
    expect(cyclic.calls).toBe(0)

    const dated = await rejected({ amount: 10, when: new Date(ISSUED) }, 'rt04-date')
    expect(dated.thrown).toBeUndefined()
    expect(dated.result?.authenticated).toBe(false)
    expect(dated.result?.executed).toBe(false)
    expect(dated.calls).toBe(0)

    const fn = await rejected({ amount: 10, run: () => 1 }, 'rt04-fn')
    expect(fn.thrown).toBeUndefined()
    expect(fn.result?.ruleId).toBe('schema')
    expect(fn.calls).toBe(0)

    const dangerous: Record<string, unknown> = { amount: 10 }
    Object.defineProperty(dangerous, '__proto__', {
      enumerable: true,
      configurable: true,
      value: { admin: true },
    })
    const proto = await rejected(dangerous, 'rt04-proto')
    expect(proto.thrown).toBeUndefined()
    expect(proto.result?.decision).toBe('BLOCK')
    expect(proto.result?.authenticated).toBe(false)
    expect(proto.calls).toBe(0)
  })

  it('still allows a normal REQUIRE_HUMAN decision and a later approved execution', async () => {
    const env = actors()
    const intent = signed(env.agent, env.root, { amount: 10, note: 'example' }, 'rt04-human')
    const ledger = new NonceLedger()
    const pendingStore = new PendingAuthorizationStore()
    const policyResolver = new ImmutablePolicyResolver()
    policyResolver.register(BASIC_AGENT_AUTHORITY, BASIC_AGENT_AUTHORITY_URI)
    let calls = 0
    const pending = await run(env, intent, {
      ledger,
      pendingStore,
      policyResolver,
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(pending.decision).toBe('REQUIRE_HUMAN')
    expect(pending.authenticated).toBe(true)
    expect(authenticatedReceipt(pending).human?.status).toBe('pending')
    expect(calls).toBe(0)

    const approved = await run(env, intent, {
      ledger,
      pendingStore,
      policyResolver,
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      approval: approvalFor(env, pending),
      execute: (ctx) => {
        calls += 1
        return { amount: ctx.parameters.amount }
      },
    })
    expect(approved.decision).toBe('ALLOW')
    expect(approved.executed).toBe(true)
    expect(approved.result).toEqual({ amount: 10 })
    expect(calls).toBe(1)
    const receipt = authenticatedReceipt(approved)
    expect(verifyProtocolReceipt(receipt, importPublicKey(env.signer.publicKey)).valid).toBe(true)
    expect(receipt.execution?.intentHash).toBe(sha256(unsignedIntent(intent)))
  })

  it('rejects a signed fractional amount with an authenticated receipt and no execution', async () => {
    const env = actors()
    let calls = 0
    const intent = signed(env.agent, env.root, { amount: 10.5 }, 'rt04-fraction')
    const result = await run(env, intent, {
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(result.decision).toBe('BLOCK')
    expect(result.authenticated).toBe(true)
    expect(result.executed).toBe(false)
    expect(result.ruleId).toBe('amount')
    expect(calls).toBe(0)
    const receipt = authenticatedReceipt(result)
    expect(receipt.execution?.executed).toBe(false)
    expect(verifyProtocolReceipt(receipt, importPublicKey(env.signer.publicKey)).valid).toBe(true)
  })
})
