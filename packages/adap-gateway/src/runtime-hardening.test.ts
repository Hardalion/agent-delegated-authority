import { describe, expect, it } from 'vitest'
import {
  createIdentity,
  FixedClock,
  ImmutablePolicyResolver,
  MemoryAuthorityDirectory,
  NonceLedger,
  PendingAuthorizationStore,
  runAuthorityPath,
  sha256,
  signDelegation,
  signIntent,
} from 'adap'
import type { Policy } from 'adap-policy'
import {
  decideReconciliation,
  PostgresPolicyRegistry,
  predecessorsOf,
  type ExecutionKnowledge,
  type Pool,
} from 'adap-store-postgres'
import { createRootAuthority } from './root-authority.js'
import { directoryFromConfig } from './server.js'

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
