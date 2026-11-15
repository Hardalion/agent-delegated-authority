import { createServer } from 'node:http'
import { describe, expect, it } from 'vitest'
import {
  createIdentity,
  signDelegation,
  signIntent,
  NonceLedger,
  ImmutablePolicyResolver,
  FixedClock,
  AuthorityError,
} from 'adap'
import type { Policy } from 'adap-policy'
import { MemoryCredentialBroker } from './credentials.js'
import { executeAuthorized, attemptDirectBrokerExecute } from './executor.js'
import {
  StaticIdentityDirectory,
  assertUsableKey,
  toAuthorityDirectory,
} from './identity.js'
import { MemorySecurityEventSink } from './events.js'
import { canonicalizeAction, freezeAuthorizedParameters } from './canonicalize.js'

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

async function startEchoServer() {
  const seen: Array<{ auth?: string; body: unknown }> = []
  const server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      seen.push({
        auth: req.headers.authorization,
        body: JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'),
      })
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: true }))
    })
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const addr = server.address()
  if (!addr || typeof addr === 'string') throw new Error('no port')
  return {
    url: `http://127.0.0.1:${addr.port}/write`,
    seen,
    close: () => new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve()))),
  }
}

describe('credential isolation gateway', () => {
  it('executes through broker without exposing rail token to agent surface', async () => {
    const echo = await startEchoServer()
    try {
      const broker = new MemoryCredentialBroker()
      const handle = broker.registerRoute('apply', 'resource/*', 'rail-secret-token', echo.url)
      expect(broker.listPublicHandles()).toContain(handle)
      expect(JSON.stringify(broker)).not.toContain('rail-secret-token')

      const principal = createIdentity('prn_example')
      const agent = createIdentity('agt_personal')
      const signer = createIdentity('reference-runtime')
      const directory = new Map([
        [principal.id, principal.publicKey],
        [agent.id, agent.publicKey],
      ])
      const policyResolver = new ImmutablePolicyResolver()
      policyResolver.register(ALLOW_APPLY, ALLOW_URI)
      const root = signDelegation(
        {
          delegation_id: 'del_root',
          issuer: principal.id,
          subject: agent.id,
          capabilities: [{ action: 'apply', target: 'resource/*', delegable: false }],
          constraints: { max_amount: 800 },
          issued_at: ISSUED,
          expires_at: EXPIRES,
        },
        principal,
      )
      const intent = signIntent(
        {
          intent_id: 'int_gw',
          actor: agent.id,
          delegation_chain: [root.delegation_id],
          action: 'apply',
          target: 'resource/example',
          parameters: { amount: 10 },
          nonce: 'nonce-gw-1',
          issued_at: ISSUED,
          expires_at: EXPIRES,
        },
        agent,
      )
      const events = new MemorySecurityEventSink()
      const result = await executeAuthorized({
        chain: [root],
        intent,
        directory,
        trustedRootIssuers: [principal.id],
        policy: ALLOW_APPLY,
        policyUri: ALLOW_URI,
        ledger: new NonceLedger(),
        signer,
        policyResolver,
        clock: new FixedClock(NOW),
        broker,
        events,
      })
      expect(result.executed).toBe(true)
      expect(result.downstream?.status).toBe('completed')
      expect(echo.seen[0]?.auth).toBe('Bearer rail-secret-token')
      expect(events.events.some((e) => e.type === 'execution.completed')).toBe(true)
    } finally {
      await echo.close()
    }
  })

  it('blocks alternate tool route that is not registered on the broker', async () => {
    const broker = new MemoryCredentialBroker()
    broker.registerRoute('apply', 'resource/*', 'tok', 'http://127.0.0.1:9/nope')
    await expect(broker.resolveHandle('transfer', 'resource/example')).rejects.toThrow(/no credential handle/)
  })

  it('rejects post-validation parameter mutation affecting frozen copy', () => {
    const frozen = freezeAuthorizedParameters({ amount: 10 })
    expect(() => {
      ;(frozen as { amount: number }).amount = 999
    }).toThrow()
  })

  it('canonicalizes actions consistently', () => {
    expect(canonicalizeAction('Apply')).toBe('apply')
    expect(() => canonicalizeAction('APPLY SPACE')).toThrow()
  })
})

describe('identity directory', () => {
  it('rejects revoked, unknown, wrong algorithm, expired, wrong kind', () => {
    const principal = createIdentity('prn_example')
    const dir = new StaticIdentityDirectory([
      {
        keyId: 'k1',
        subjectId: principal.id,
        algorithm: 'Ed25519',
        publicKeyPemOrRaw: principal.publicKey,
        status: 'active',
        kind: 'human',
        issuer: 'hardalion-test',
        audience: 'adap-gateway',
        notAfter: EXPIRES,
      },
    ])
    const now = NOW
    expect(assertUsableKey(dir.lookup(principal.id), now, { expectedKind: 'human' }).keyId).toBe('k1')
    expect(() => assertUsableKey(undefined, now)).toThrow(AuthorityError)
    dir.put({
      keyId: 'k2',
      subjectId: 'revoked-user',
      algorithm: 'Ed25519',
      publicKeyPemOrRaw: principal.publicKey,
      status: 'revoked',
      kind: 'human',
    })
    expect(() => assertUsableKey(dir.lookup('revoked-user'), now)).toThrow(/revoked/)
    expect(() =>
      assertUsableKey(dir.lookup(principal.id), now, { expectedKind: 'workload' }),
    ).toThrow(/wrong identity kind/)
    expect(() =>
      assertUsableKey(dir.lookup(principal.id), now, { issuer: 'other' }),
    ).toThrow(/issuer/)
    expect(() =>
      assertUsableKey(dir.lookup(principal.id), now, { audience: 'other' }),
    ).toThrow(/audience/)
    expect(() =>
      assertUsableKey(dir.lookup(principal.id), new Date(Date.parse(EXPIRES) + 1000)),
    ).toThrow(/expired/)
    expect(() =>
      assertUsableKey(
        {
          keyId: 'bad',
          subjectId: 'x',
          algorithm: 'Ed25519',
          publicKeyPemOrRaw: principal.publicKey,
          status: 'active',
          kind: 'agent',
        },
        now,
        // @ts-expect-error algorithm confusion probe
        undefined,
      ),
    ).not.toThrow()
    // Algorithm confusion: non-Ed25519 rejected at put
    expect(() =>
      dir.put({
        keyId: 'rsa',
        subjectId: 'rsa-user',
        // @ts-expect-error intentional
        algorithm: 'RS256',
        publicKeyPemOrRaw: principal.publicKey,
        status: 'active',
        kind: 'human',
      }),
    ).toThrow(/unsupported algorithm/)
  })

  it('toAuthorityDirectory fails closed on missing subjects', () => {
    const dir = new StaticIdentityDirectory()
    expect(() => toAuthorityDirectory(dir, ['missing'], NOW)).toThrow(AuthorityError)
  })
})

describe('bypass attempts', () => {
  it('direct broker call without ADAP still cannot invent an unregistered route', async () => {
    const broker = new MemoryCredentialBroker()
    broker.registerRoute('apply', 'resource/*', 'tok', 'http://127.0.0.1:9/x')
    await expect(
      attemptDirectBrokerExecute(broker, 'admin_override', 'resource/example', {}),
    ).rejects.toThrow(/no credential handle/)
  })
})
