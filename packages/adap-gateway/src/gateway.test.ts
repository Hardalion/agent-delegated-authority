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
import { MemoryCredentialBroker, type CredentialBroker } from './credentials.js'
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
      expect(result.executionStatePersistence).toBe('not_configured')
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

describe('authorized action canonicality', () => {
  function countingBroker(): {
    broker: CredentialBroker
    calls: () => { resolves: number; executes: number }
  } {
    let resolves = 0
    let executes = 0
    return {
      broker: {
        async resolveHandle() {
          resolves += 1
          return 'hdl_test'
        },
        async execute(handle, request) {
          executes += 1
          return { status: 'completed', correlationId: request.correlationId, body: { handle } }
        },
      },
      calls: () => ({ resolves, executes }),
    }
  }

  async function run(action: string, policyAction: 'ALLOW' | 'BLOCK' = 'ALLOW') {
    const principal = createIdentity('prn_example')
    const agent = createIdentity('agt_personal')
    const signer = createIdentity('reference-runtime')
    const directory = new Map([
      [principal.id, principal.publicKey],
      [agent.id, agent.publicKey],
    ])
    const policy: Policy = {
      version: '1.0.0',
      policyName: 'action-form',
      targetAgents: ['*'],
      defaultAction: 'BLOCK',
      rules: [
        {
          ruleId: 'match_action',
          action: policyAction,
          condition: `tool.name == '${action}'`,
          alertSeverity: 'LOW',
        },
      ],
    }
    const uri = `action-form@${action}`
    const policyResolver = new ImmutablePolicyResolver()
    policyResolver.register(policy, uri)
    const root = signDelegation(
      {
        delegation_id: 'del_root',
        issuer: principal.id,
        subject: agent.id,
        capabilities: [{ action, target: 'resource/*', delegable: false }],
        constraints: { max_amount: 800 },
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      principal,
    )
    const intent = signIntent(
      {
        intent_id: `int_${action}`,
        actor: agent.id,
        delegation_chain: [root.delegation_id],
        action,
        target: 'resource/example',
        parameters: { amount: 10 },
        nonce: `nonce-${action.replace(/[^A-Za-z0-9._~-]/g, '-')}`,
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      agent,
    )
    const counted = countingBroker()
    const result = await executeAuthorized({
      chain: [root],
      intent,
      directory,
      policy,
      policyUri: uri,
      ledger: new NonceLedger(),
      signer,
      policyResolver,
      clock: new FixedClock(NOW),
      broker: counted.broker,
    })
    return { result, calls: counted.calls() }
  }

  it('blocks mixed-case, padded, and non-canonical actions before the broker', async () => {
    for (const action of ['Apply', 'apply ', 'Apply Now']) {
      const { result, calls } = await run(action)
      expect(result.decision).toBe('BLOCK')
      expect(result.executed).toBe(false)
      expect(result.receipt.execution?.executed).toBe(false)
      expect(calls.resolves).toBe(0)
      expect(calls.executes).toBe(0)
    }
  })

  it('executes an already canonical action once', async () => {
    const { result, calls } = await run('apply')
    expect(result.decision).toBe('ALLOW')
    expect(result.executed).toBe(true)
    expect(result.downstream?.status).toBe('completed')
    expect(calls.resolves).toBe(1)
    expect(calls.executes).toBe(1)
  })
})

describe('execution state persistence', () => {
  function setup() {
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
        intent_id: 'int_persist',
        actor: agent.id,
        delegation_chain: [root.delegation_id],
        action: 'apply',
        target: 'resource/example',
        parameters: { amount: 10 },
        nonce: 'nonce-persist',
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      agent,
    )
    let resolves = 0
    let executes = 0
    const broker: CredentialBroker = {
      async resolveHandle() {
        resolves += 1
        return 'hdl_persist'
      },
      async execute(_handle, request) {
        executes += 1
        return { status: 'completed', correlationId: request.correlationId, body: { ok: true } }
      },
    }
    return {
      principal,
      directory,
      root,
      intent,
      signer,
      policyResolver,
      broker,
      calls: () => ({ resolves, executes }),
    }
  }

  it('reports a failed state write after a successful downstream call and does not repeat it', async () => {
    const gate = setup()
    const events = new MemorySecurityEventSink()
    const ledger = new NonceLedger()
    let writes = 0
    const result = await executeAuthorized({
      chain: [gate.root],
      intent: gate.intent,
      directory: gate.directory,
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      ledger,
      signer: gate.signer,
      policyResolver: gate.policyResolver,
      clock: new FixedClock(NOW),
      broker: gate.broker,
      events,
      onExecutionState: async (state) => {
        writes += 1
        if (state !== 'started') throw new Error('disk full')
      },
    })
    expect(gate.calls()).toEqual({ resolves: 1, executes: 1 })
    expect(writes).toBe(2)
    expect(result.decision).toBe('ALLOW')
    expect(result.executed).toBe(true)
    expect(result.downstream?.status).toBe('completed')
    expect(result.executionStatePersistence).toBe('failed')
    expect(events.events.some((event) => event.type === 'storage.failure')).toBe(true)

    const retry = await executeAuthorized({
      chain: [gate.root],
      intent: gate.intent,
      directory: gate.directory,
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      ledger,
      signer: gate.signer,
      policyResolver: gate.policyResolver,
      clock: new FixedClock(NOW),
      broker: gate.broker,
      events,
      onExecutionState: async () => {
        throw new Error('disk full')
      },
    })
    expect(retry.decision).toBe('BLOCK')
    expect(retry.executed).toBe(false)
    expect(retry.executionStatePersistence).toBe('not_attempted')
    expect(gate.calls()).toEqual({ resolves: 1, executes: 1 })
  })

  it('does not call downstream when state persistence fails first', async () => {
    const gate = setup()
    const events = new MemorySecurityEventSink()
    const result = await executeAuthorized({
      chain: [gate.root],
      intent: gate.intent,
      directory: gate.directory,
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      ledger: new NonceLedger(),
      signer: gate.signer,
      policyResolver: gate.policyResolver,
      clock: new FixedClock(NOW),
      broker: gate.broker,
      events,
      onExecutionState: async () => {
        throw new Error('disk full')
      },
    })
    expect(gate.calls()).toEqual({ resolves: 0, executes: 0 })
    expect(result.decision).toBe('BLOCK')
    expect(result.executed).toBe(false)
    expect(result.executionStatePersistence).toBe('failed')
    expect(result.receipt.execution?.executed).toBe(false)
    expect(events.events.some((event) => event.type === 'storage.failure')).toBe(true)
  })

  it('does not treat a callback that merely returns as durable confirmation', async () => {
    const gate = setup()
    const result = await executeAuthorized({
      chain: [gate.root],
      intent: gate.intent,
      directory: gate.directory,
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      ledger: new NonceLedger(),
      signer: gate.signer,
      policyResolver: gate.policyResolver,
      clock: new FixedClock(NOW),
      broker: gate.broker,
      onExecutionState: async () => {},
    })
    expect(result.executed).toBe(true)
    expect(result.executionStatePersistence).toBe('callback_returned')
    expect(result.downstream?.status).toBe('completed')
  })

  it('reports confirmed only when every callback says the write is durable', async () => {
    const gate = setup()
    const result = await executeAuthorized({
      chain: [gate.root],
      intent: gate.intent,
      directory: gate.directory,
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      ledger: new NonceLedger(),
      signer: gate.signer,
      policyResolver: gate.policyResolver,
      clock: new FixedClock(NOW),
      broker: gate.broker,
      onExecutionState: async () => 'confirmed',
    })
    expect(result.executed).toBe(true)
    expect(result.executionStatePersistence).toBe('confirmed')
    expect(gate.calls()).toEqual({ resolves: 1, executes: 1 })
  })

  it('does not stay confirmed when a later callback does not confirm the write', async () => {
    const gate = setup()
    const result = await executeAuthorized({
      chain: [gate.root],
      intent: gate.intent,
      directory: gate.directory,
      policy: ALLOW_APPLY,
      policyUri: ALLOW_URI,
      ledger: new NonceLedger(),
      signer: gate.signer,
      policyResolver: gate.policyResolver,
      clock: new FixedClock(NOW),
      broker: gate.broker,
      onExecutionState: async (state) => (state === 'started' ? 'confirmed' : undefined),
    })
    expect(result.executed).toBe(true)
    expect(result.executionStatePersistence).toBe('callback_returned')
  })

  it('reports not_attempted when authorization blocks before the callback', async () => {
    const gate = setup()
    const blocked: Policy = {
      version: '1.0.0',
      policyName: 'block-apply',
      targetAgents: ['*'],
      defaultAction: 'BLOCK',
      rules: [
        { ruleId: 'never', action: 'BLOCK', condition: "tool.name == 'other'", alertSeverity: 'LOW' },
      ],
    }
    const uri = 'block-apply@1.0.0'
    gate.policyResolver.register(blocked, uri)
    let calls = 0
    const result = await executeAuthorized({
      chain: [gate.root],
      intent: gate.intent,
      directory: gate.directory,
      policy: blocked,
      policyUri: uri,
      ledger: new NonceLedger(),
      signer: gate.signer,
      policyResolver: gate.policyResolver,
      clock: new FixedClock(NOW),
      broker: gate.broker,
      onExecutionState: async () => {
        calls += 1
        return 'confirmed'
      },
    })
    expect(result.decision).toBe('BLOCK')
    expect(result.executed).toBe(false)
    expect(result.executionStatePersistence).toBe('not_attempted')
    expect(calls).toBe(0)
    expect(gate.calls()).toEqual({ resolves: 0, executes: 0 })
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
