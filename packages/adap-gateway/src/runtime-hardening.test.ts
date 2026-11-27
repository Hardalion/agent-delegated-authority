import { describe, expect, it } from 'vitest'
import { verifyAuthorizationReceipt } from 'adap-receipt'
import {
  createIdentity,
  FixedClock,
  ImmutablePolicyResolver,
  MemoryAuthorityDirectory,
  NonceLedger,
  PendingAuthorizationStore,
  runAuthorityPath,
  sha256,
  signApproval,
  signDelegation,
  signIntent,
} from 'adap-core'
import type { Policy } from 'adap-policy'
import {
  decideReconciliation,
  PostgresPolicyRegistry,
  predecessorsOf,
  type ExecutionKnowledge,
  type Pool,
} from 'adap-store-postgres'
import { executeAuthorized } from './executor.js'
import { createRootAuthority } from './root-authority.js'
import { createGatewayServer, directoryFromConfig } from './server.js'

const NOW = new Date('2026-10-06T18:00:00.000Z')
const ISSUED = NOW.toISOString()
const EXPIRES = new Date(NOW.getTime() + 15 * 60 * 1000).toISOString()

const POLICY: Policy = {
  version: '1.0.0',
  policyName: 'allow-apply',
  targetAgents: ['*'],
  defaultAction: 'BLOCK',
  rules: [{ ruleId: 'allow', action: 'ALLOW', condition: "tool.name == 'apply'", alertSeverity: 'LOW' }],
}
const URI = 'allow-apply@1'

interface Row {
  tenant_id: string
  uri: string
  body: Policy
  content_hash: string
  revoked: boolean
}

function fakePool(rows: Row[]): Pool {
  return {
    query: async (sql: string, params: unknown[] = []) => {
      const text = sql.replace(/\s+/g, ' ').trim()
      if (text.startsWith('SELECT content_hash, revoked')) {
        const row = rows.find((item) => item.tenant_id === params[0] && item.uri === params[1])
        return {
          rows: row ? [{ content_hash: row.content_hash, revoked: row.revoked }] : [],
          rowCount: row ? 1 : 0,
        }
      }
      if (text.startsWith('INSERT INTO adap_policies')) {
        rows.push({
          content_hash: String(params[0]),
          uri: String(params[1]),
          body: JSON.parse(String(params[2])) as Policy,
          tenant_id: String(params[3]),
          revoked: false,
        })
        return { rows: [], rowCount: 1 }
      }
      if (text.startsWith('UPDATE adap_policies')) {
        const row = rows.find((item) => item.tenant_id === params[0] && item.uri === params[1] && !item.revoked)
        if (!row) return { rows: [], rowCount: 0 }
        row.revoked = true
        return { rows: [{ content_hash: row.content_hash }], rowCount: 1 }
      }
      if (text.startsWith('SELECT uri, body, content_hash, revoked')) {
        const found = rows.filter((item) => item.tenant_id === params[0])
        return {
          rows: found.map((item) => ({
            uri: item.uri,
            body: item.body,
            content_hash: item.content_hash,
            revoked: item.revoked,
          })),
          rowCount: found.length,
        }
      }
      throw new Error(`unexpected sql: ${text}`)
    },
  } as unknown as Pool
}

describe('worker policy revocation', () => {
  it('evicts a revoked URI on hydrate and still resolves the historical hash', async () => {
    const rows: Row[] = []
    const pool = fakePool(rows)
    const workerA = new PostgresPolicyRegistry({ pool })
    const workerB = new PostgresPolicyRegistry({ pool })
    const pin = await workerA.registerAsync(POLICY, URI)
    expect(await workerB.hydrate()).toBe(1)
    expect(workerB.resolveByUri(URI)?.contentHash).toBe(pin.contentHash)

    await workerA.revokeByUri(URI)
    expect(workerA.resolveByUri(URI)).toBeUndefined()
    expect(workerB.resolveByUri(URI)?.contentHash).toBe(pin.contentHash)

    expect(await workerB.hydrate()).toBe(0)
    expect(workerB.resolveByUri(URI)).toBeUndefined()
    expect(workerB.resolveByContentHash(pin.contentHash).contentHash).toBe(pin.contentHash)

    const principal = createIdentity('prn_example')
    const agent = createIdentity('agt_example')
    const signer = createIdentity('reference-runtime')
    const root = signDelegation(
      {
        delegation_id: 'del_root',
        issuer: principal.id,
        subject: agent.id,
        capabilities: [{ action: 'apply', target: 'resource/*', delegable: false }],
        constraints: {},
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      principal,
    )
    const intent = signIntent(
      {
        intent_id: 'int_new',
        actor: agent.id,
        delegation_chain: [root.delegation_id],
        action: 'apply',
        target: 'resource/example',
        parameters: {},
        nonce: 'nonce-revoked-policy',
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      agent,
    )
    let calls = 0
    const blocked = await runAuthorityPath({
      unsafeDevAllowUnconfiguredChecks: true,
      chain: [root],
      intent,
      directory: new Map([
        [principal.id, principal.publicKey],
        [agent.id, agent.publicKey],
      ]),
      policy: POLICY,
      policyUri: URI,
      clock: new FixedClock(NOW),
      ledger: new NonceLedger(),
      pendingStore: new PendingAuthorizationStore(),
      policyResolver: workerB,
      signer,
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(blocked.decision).toBe('BLOCK')
    expect(blocked.ruleId).toBe('policy')
    expect(calls).toBe(0)
    expect(sha256(POLICY)).toBe(pin.contentHash)
  })
})

describe('in-flight reconciliation', () => {
  it('does not finalize a started write from a negative lookup', async () => {
    const log = new Map<string, { state: ExecutionKnowledge; detail: string | null }>()
    const intentHash = 'a'.repeat(64)
    log.set(intentHash, { state: 'started', detail: null })
    let released = false

    const negative = decideReconciliation('started', released)
    expect(negative.action).toBe('annotate')
    if (negative.action === 'annotate') log.get(intentHash)!.detail = negative.detail
    expect(log.get(intentHash)).toEqual({ state: 'started', detail: 'downstream_has_no_record' })

    released = true
    const completed: ExecutionKnowledge = 'completed'
    expect(predecessorsOf(completed)).toContain('started')
    expect(predecessorsOf(completed)).not.toContain('reconciled')
    log.set(intentHash, { state: completed, detail: 'broker_returned' })
    expect(log.get(intentHash)?.state).toBe('completed')
    expect(decideReconciliation('unknown', false).action).toBe('transition')
  })
})

describe('gateway directory kinds', () => {
  it('keeps kind and refuses non-human approvers', () => {
    const principal = createIdentity('prn_example')
    const agent = createIdentity('agt_example')
    const service = createIdentity('svc_example')
    const directory = directoryFromConfig({
      entries: [
        { id: principal.id, publicKey: principal.publicKey, kind: 'human' },
        { id: agent.id, publicKey: agent.publicKey, kind: 'agent' },
        { id: service.id, publicKey: service.publicKey, kind: 'service' },
      ],
    })
    expect(directory).toBeInstanceOf(MemoryAuthorityDirectory)
    expect(directory.lookup(principal.id)?.kind).toBe('human')
    expect(directory.lookup(agent.id)?.kind).toBe('agent')
    expect(directory.lookup(service.id)?.kind).toBe('service')
    const isHuman = (identityId: string) => directory.lookup(identityId)?.kind === 'human'
    expect(isHuman(principal.id)).toBe(true)
    expect(isHuman(agent.id)).toBe(false)
    expect(isHuman(service.id)).toBe(false)
    const bare = directoryFromConfig({
      entries: [
        { id: principal.id, publicKey: principal.publicKey },
        { id: agent.id, publicKey: agent.publicKey },
      ],
    })
    expect(bare.lookup(principal.id)?.kind).toBeUndefined()
    expect(bare.lookup(principal.id)?.kind === 'human').toBe(false)
    expect(createRootAuthority(
      [{ issuerId: principal.id, action: 'apply', target: 'resource/*' }],
      directory,
    ).allowSelfIssuedRoot).toBe(false)
  })
})

const AUDIENCE = 'https://gw.example'
const HUMAN: Policy = {
  version: '1.0.0',
  policyName: 'needs-human',
  targetAgents: ['*'],
  defaultAction: 'BLOCK',
  rules: [{ ruleId: 'wait', action: 'REQUIRE_HUMAN', condition: "tool.name == 'apply'", alertSeverity: 'MEDIUM' }],
}

function conformingFixture(revoked = new Set<string>()) {
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
      kind: 'human',
    },
    {
      identityId: agent.id,
      kid: agent.kid,
      alg: 'Ed25519',
      publicKey: agent.publicKey,
      status: 'active',
      kind: 'agent',
    },
  ])
  const root = signDelegation(
    {
      delegation_id: 'del_root',
      issuer: principal.id,
      subject: agent.id,
      capabilities: [{ action: 'apply', target: 'resource/*', delegable: false }],
      constraints: {},
      issued_at: ISSUED,
      expires_at: EXPIRES,
      aud: AUDIENCE,
    },
    principal,
  )
  const resolver = new ImmutablePolicyResolver()
  resolver.register(POLICY, URI)
  resolver.register(HUMAN, 'needs-human@1')
  const gateway = createGatewayServer({
    audience: AUDIENCE,
    directory,
    rootAuthority: { mayIssueRoot: () => true },
    approvalPolicy: { isHuman: (id) => directory.lookup(id)?.kind === 'human' },
    revocationCheck: (id) => (revoked.has(id) ? 'revoked' : 'active'),
  })
  return { principal, agent, signer, directory, root, resolver, gateway, revoked }
}

function intentFor(
  env: ReturnType<typeof conformingFixture>,
  nonce: string,
  aud = AUDIENCE,
) {
  return signIntent(
    {
      intent_id: `int_${nonce}`,
      actor: env.agent.id,
      delegation_chain: [env.root.delegation_id],
      action: 'apply',
      target: 'resource/example',
      parameters: { amount: 10 },
      nonce,
      issued_at: ISSUED,
      expires_at: EXPIRES,
      aud,
    },
    env.agent,
  )
}

describe('gateway fail-closed defaults', () => {
  it('issues a conforming receipt when audience, revocation, and approval policy are set', async () => {
    const env = conformingFixture()
    expect(env.gateway.unsafeDevAllowUnconfiguredChecks).toBe(false)
    const result = await executeAuthorized({
      ...env.gateway,
      chain: [env.root],
      intent: intentFor(env, 'nonce-conforming'),
      policy: POLICY,
      policyUri: URI,
      ledger: new NonceLedger(),
      pendingStore: new PendingAuthorizationStore(),
      policyResolver: env.resolver,
      signer: env.signer,
      clock: new FixedClock(NOW),
      broker: {
        resolveHandle: async () => 'handle',
        execute: async () => ({ status: 'completed', correlationId: 'c', body: { ok: true } }),
      },
    })
    expect(result.decision).toBe('ALLOW')
    expect(result.executed).toBe(true)
    const checks = result.receipt?.extensions?.checks_applied as { unsafe_dev_unconfigured_checks?: boolean }
    expect(checks.unsafe_dev_unconfigured_checks).toBe(false)
    const offline = verifyAuthorizationReceipt(result.receipt, { publicKeySpki: env.signer.publicKey })
    expect(offline.status).toBe('verified')
    expect(offline.valid).toBe(true)

    const bare = await executeAuthorized({
      chain: [env.root],
      intent: intentFor(env, 'nonce-bare-executor'),
      directory: env.directory,
      policy: POLICY,
      policyUri: URI,
      ledger: new NonceLedger(),
      pendingStore: new PendingAuthorizationStore(),
      policyResolver: env.resolver,
      signer: env.signer,
      clock: new FixedClock(NOW),
      rootAuthority: env.gateway.rootAuthority,
      broker: {
        resolveHandle: async () => 'handle',
        execute: async () => ({ status: 'completed', correlationId: 'c', body: { ok: true } }),
      },
    })
    expect(bare.decision).toBe('BLOCK')
    expect(bare.executed).toBe(false)
    const bareChecks = bare.receipt?.extensions?.checks_applied as { unsafe_dev_unconfigured_checks?: boolean }
    expect(bareChecks.unsafe_dev_unconfigured_checks).toBe(false)
    expect(verifyAuthorizationReceipt(bare.receipt, { publicKeySpki: env.signer.publicKey }).status).toBe('verified')
  })

  it('blocks a revoked grant, a mismatched audience, and a non-human approver', async () => {
    const revoked = new Set<string>()
    const env = conformingFixture(revoked)
    const ledger = new NonceLedger()
    const pending = new PendingAuthorizationStore()
    revoked.add(env.root.delegation_id)
    let calls = 0
    const blocked = await executeAuthorized({
      ...env.gateway,
      chain: [env.root],
      intent: intentFor(env, 'nonce-revoked'),
      policy: POLICY,
      policyUri: URI,
      ledger,
      pendingStore: pending,
      policyResolver: env.resolver,
      signer: env.signer,
      clock: new FixedClock(NOW),
      broker: {
        resolveHandle: async () => 'handle',
        execute: async () => {
          calls += 1
          return { status: 'completed', correlationId: 'c', body: {} }
        },
      },
    })
    expect(blocked.decision).toBe('BLOCK')
    expect(blocked.ruleId).toBe('revoked')
    expect(calls).toBe(0)

    revoked.delete(env.root.delegation_id)
    const mismatch = await executeAuthorized({
      ...env.gateway,
      chain: [env.root],
      intent: intentFor(env, 'nonce-aud', 'https://other.example'),
      policy: POLICY,
      policyUri: URI,
      ledger: new NonceLedger(),
      pendingStore: new PendingAuthorizationStore(),
      policyResolver: env.resolver,
      signer: env.signer,
      clock: new FixedClock(NOW),
      broker: { resolveHandle: async () => 'handle', execute: async () => ({ status: 'completed', correlationId: 'c', body: {} }) },
    })
    expect(mismatch.decision).toBe('BLOCK')
    expect(mismatch.reason).toBe('AUDIENCE_MISMATCH')

    const closed = createGatewayServer({
      ...env.gateway,
      approvalPolicy: { isHuman: () => false },
    })
    const waiting = await executeAuthorized({
      ...closed,
      chain: [env.root],
      intent: intentFor(env, 'nonce-approval'),
      policy: HUMAN,
      policyUri: 'needs-human@1',
      ledger,
      pendingStore: pending,
      policyResolver: env.resolver,
      signer: env.signer,
      clock: new FixedClock(NOW),
      broker: { resolveHandle: async () => 'handle', execute: async () => ({ status: 'completed', correlationId: 'c', body: {} }) },
    })
    expect(waiting.decision).toBe('REQUIRE_HUMAN')
    const approval = signApproval(
      {
        intent_hash: waiting.intentHash,
        approver_id: env.principal.id,
        approved_at: ISSUED,
        decision: 'APPROVE',
        agent_id: env.agent.id,
        delegation_chain_hash: waiting.delegationHash,
        policy_content_hash: waiting.policyHash,
        matched_rule_id: waiting.ruleId,
        aud: AUDIENCE,
      },
      env.principal,
    )
    const denied = await executeAuthorized({
      ...closed,
      chain: [env.root],
      intent: intentFor(env, 'nonce-approval'),
      approval,
      policy: HUMAN,
      policyUri: 'needs-human@1',
      ledger,
      pendingStore: pending,
      policyResolver: env.resolver,
      signer: env.signer,
      clock: new FixedClock(NOW),
      broker: { resolveHandle: async () => 'handle', execute: async () => ({ status: 'completed', correlationId: 'c', body: {} }) },
    })
    expect(denied.decision).toBe('BLOCK')
    expect(denied.reason).toMatch(/not a human/)
  })
})
