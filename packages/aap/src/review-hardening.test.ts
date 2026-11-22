import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { evaluateToolCall } from 'adap-policy'
import { FixedClock } from './clock.js'
import { MemoryAuthorityDirectory } from './directory.js'
import { sha256 } from './crypto.js'
import { NonceLedger } from './nonce.js'
import { ExecutionOutcomeUnknownError, authenticatedReceipt, runAuthorityPath } from './path.js'
import { PendingAuthorizationStore } from './pending.js'
import { ImmutablePolicyResolver } from './policy-resolver.js'
import { BASIC_AGENT_AUTHORITY, BASIC_AGENT_AUTHORITY_URI } from './example-policy.js'
import {
  createIdentity,
  signDelegation,
  signIntent,
} from './protocol.js'
import { adapBindingForMcpCall, hashMcpToolDefinition } from './mcp-tool.js'
import { MAX_DELEGATION_CHAIN_DEPTH, presentAuthority, verifyAuthority } from './validate.js'
import { MemorySpendLedger } from './spend.js'

const NOW = new Date('2026-10-06T18:00:00.000Z')
const ISSUED = NOW.toISOString()
const EXPIRES = new Date(NOW.getTime() + 4 * 60 * 1000).toISOString()
const AUDIENCE = 'https://gw-a.example'

function base() {
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
      capabilities: [{ action: 'read', target: 'resource/*', delegable: true }],
      constraints: {},
      issued_at: ISSUED,
      expires_at: EXPIRES,
      aud: AUDIENCE,
    },
    principal,
  )
  const policyResolver = new ImmutablePolicyResolver()
  policyResolver.register(BASIC_AGENT_AUTHORITY, BASIC_AGENT_AUTHORITY_URI)
  return { principal, agent, signer, directory, root, policyResolver }
}

describe('adversarial review hardening', () => {
  it('rejects a runtime that has no root authority or revocation check', async () => {
    const env = base()
    const intent = signIntent(
      {
        intent_id: 'int_bare',
        actor: env.agent.id,
        delegation_chain: [env.root.delegation_id],
        action: 'read',
        target: 'resource/example',
        parameters: {},
        nonce: 'nonce-bare',
        issued_at: ISSUED,
        expires_at: EXPIRES,
        aud: AUDIENCE,
      },
      env.agent,
    )
    const blocked = await runAuthorityPath({
      chain: [env.root],
      intent,
      directory: env.directory,
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      clock: new FixedClock(NOW),
      ledger: new NonceLedger(),
      pendingStore: new PendingAuthorizationStore(),
      policyResolver: env.policyResolver,
      signer: env.signer,
      audience: AUDIENCE,
    })
    expect(blocked.decision).toBe('BLOCK')
    expect(blocked.reason).toMatch(/root authority is required/)
  })

  it('rejects an intent addressed to a different audience', async () => {
    const env = base()
    const intent = signIntent(
      {
        intent_id: 'int_aud',
        actor: env.agent.id,
        delegation_chain: [env.root.delegation_id],
        action: 'read',
        target: 'resource/example',
        parameters: {},
        nonce: 'nonce-aud',
        issued_at: ISSUED,
        expires_at: EXPIRES,
        aud: AUDIENCE,
      },
      env.agent,
    )
    const blocked = await runAuthorityPath({
      chain: [env.root],
      intent,
      directory: env.directory,
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      clock: new FixedClock(NOW),
      ledger: new NonceLedger(),
      pendingStore: new PendingAuthorizationStore(),
      policyResolver: env.policyResolver,
      signer: env.signer,
      audience: 'https://gw-b.example',
      rootAuthority: { mayIssueRoot: () => true },
      revocationCheck: () => 'active',
    })
    expect(blocked.decision).toBe('BLOCK')
    expect(blocked.reason).toBe('AUDIENCE_MISMATCH')
  })

  it('records checks_applied when the conformance hooks are present', async () => {
    const env = base()
    const intent = signIntent(
      {
        intent_id: 'int_checks',
        actor: env.agent.id,
        delegation_chain: [env.root.delegation_id],
        action: 'read',
        target: 'resource/example',
        parameters: {},
        nonce: 'nonce-checks',
        issued_at: ISSUED,
        expires_at: EXPIRES,
        aud: AUDIENCE,
      },
      env.agent,
    )
    const allowed = await runAuthorityPath({
      chain: [env.root],
      intent,
      directory: env.directory,
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      clock: new FixedClock(NOW),
      ledger: new NonceLedger(),
      pendingStore: new PendingAuthorizationStore(),
      policyResolver: env.policyResolver,
      signer: env.signer,
      audience: AUDIENCE,
      rootAuthority: { mayIssueRoot: () => true },
      revocationCheck: () => 'active',
      enforcementMode: 'gateway',
      credentialBoundary: 'gateway_isolated',
      execute: () => ({ ok: true }),
    })
    expect(allowed.decision).toBe('ALLOW')
    const checks = authenticatedReceipt(allowed).extensions?.checks_applied as { root_authority: boolean }
    expect(checks.root_authority).toBe(true)
    expect(authenticatedReceipt(allowed).extensions?.enforcement_mode).toBe('gateway')
  })

  it('does not set executed when the downstream outcome is unknown', async () => {
    const env = base()
    const intent = signIntent(
      {
        intent_id: 'int_unknown',
        actor: env.agent.id,
        delegation_chain: [env.root.delegation_id],
        action: 'read',
        target: 'resource/example',
        parameters: {},
        nonce: 'nonce-unknown',
        issued_at: ISSUED,
        expires_at: EXPIRES,
        aud: AUDIENCE,
      },
      env.agent,
    )
    const result = await runAuthorityPath({
      chain: [env.root],
      intent,
      directory: env.directory,
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      clock: new FixedClock(NOW),
      ledger: new NonceLedger(),
      pendingStore: new PendingAuthorizationStore(),
      policyResolver: env.policyResolver,
      signer: env.signer,
      audience: AUDIENCE,
      rootAuthority: { mayIssueRoot: () => true },
      revocationCheck: () => 'active',
      execute: () => {
        throw new ExecutionOutcomeUnknownError('downstream_unreachable')
      },
    })
    expect(result.executed).toBe(false)
    expect(authenticatedReceipt(result).execution?.executed).toBe(false)
    expect(authenticatedReceipt(result).execution?.outcome).toBe('unknown')
  })

  it('rejects a chain longer than 8 before signature checks', () => {
    expect(() =>
      presentAuthority({
        chain: Array.from({ length: MAX_DELEGATION_CHAIN_DEPTH + 1 }, () => ({ signature: 'skip' }) as never),
        intent: { signature: 'skip' } as never,
        directory: new Map(),
        now: NOW,
      }),
    ).toThrow(/maximum depth/)
  })

  it('charges cumulative_quantity as well as cumulative_max_amount', async () => {
    const env = base()
    const root = signDelegation(
      {
        delegation_id: 'del_qty',
        issuer: env.principal.id,
        subject: env.agent.id,
        capabilities: [{ action: 'apply', target: 'resource/*' }],
        constraints: { max_amount: 50, cumulative_quantity: 3 },
        issued_at: ISSUED,
        expires_at: EXPIRES,
        aud: AUDIENCE,
      },
      env.principal,
    )
    const policyResolver = new ImmutablePolicyResolver()
    const allow = {
      version: '1.0.0',
      policyName: 'allow-apply',
      targetAgents: ['*'],
      defaultAction: 'BLOCK' as const,
      rules: [{ ruleId: 'allow', action: 'ALLOW' as const, condition: "tool.name == 'apply'", alertSeverity: 'LOW' as const }],
    }
    policyResolver.register(allow, 'allow-apply@1')
    const spendLedger = new MemorySpendLedger()
    const run = (nonce: string) =>
      runAuthorityPath({
        chain: [root],
        intent: signIntent(
          {
            intent_id: `int_${nonce}`,
            actor: env.agent.id,
            delegation_chain: [root.delegation_id],
            action: 'apply',
            target: 'resource/example',
            parameters: { amount: 1, quantity: 2 },
            nonce,
            issued_at: ISSUED,
            expires_at: EXPIRES,
            aud: AUDIENCE,
          },
          env.agent,
        ),
        directory: env.directory,
        policy: allow,
        policyUri: 'allow-apply@1',
        clock: new FixedClock(NOW),
        ledger: new NonceLedger(),
        spendLedger,
        pendingStore: new PendingAuthorizationStore(),
        policyResolver,
        signer: env.signer,
        audience: AUDIENCE,
        rootAuthority: { mayIssueRoot: () => true },
        revocationCheck: () => 'active',
        execute: () => ({ ok: true }),
      })
    expect((await run('q1')).decision).toBe('ALLOW')
    expect((await run('q2')).decision).toBe('BLOCK')
    expect(spendLedger.spent(root.delegation_id)).toBe(2)
  })

  it('rejects a closed grant that carries an undeclared parameter', async () => {
    const env = base()
    const root = signDelegation(
      {
        delegation_id: 'del_closed',
        issuer: env.principal.id,
        subject: env.agent.id,
        capabilities: [{ action: 'apply', target: 'resource/*' }],
        constraints: { max_amount: 10, closed: true },
        issued_at: ISSUED,
        expires_at: EXPIRES,
        aud: AUDIENCE,
      },
      env.principal,
    )
    const intent = signIntent(
      {
        intent_id: 'int_closed',
        actor: env.agent.id,
        delegation_chain: [root.delegation_id],
        action: 'apply',
        target: 'resource/example',
        parameters: { amount: 1, extra: true },
        nonce: 'nonce-closed',
        issued_at: ISSUED,
        expires_at: EXPIRES,
        aud: AUDIENCE,
      },
      env.agent,
    )
    expect(() =>
      presentAuthority({ chain: [root], intent, directory: env.directory, now: NOW }),
    ).not.toThrow()
    expect(() => verifyAuthority({ chain: [root], intent, directory: env.directory, now: NOW })).toThrow(/undeclared parameter/)
  })

  it('pins an MCP tool definition and derives action and target', () => {
    const hash = hashMcpToolDefinition({
      server_id: 'treasury',
      tool_name: 'pay',
      description: 'Send a payment',
      input_schema: { type: 'object', properties: { amount: { type: 'integer' } } },
    })
    expect(hash.startsWith('sha256:')).toBe(true)
    expect(hash).toHaveLength('sha256:'.length + 64)
    expect(adapBindingForMcpCall('treasury', 'pay')).toEqual({
      action: 'treasury.pay',
      target: 'mcp/treasury/pay',
    })
    const again = hashMcpToolDefinition({
      tool_name: 'pay',
      server_id: 'treasury',
      input_schema: { properties: { amount: { type: 'integer' } }, type: 'object' },
      description: 'Send a payment',
    })
    expect(again).toBe(hash)
  })
})

describe('mcp conformance vectors', () => {
  const file = new URL('../../../examples/conformance/mcp-vectors.json', import.meta.url)
  const document = JSON.parse(readFileSync(file, 'utf8')) as {
    vectors: Array<{ id: string; claim: string; input?: { policy?: string; toolName?: string; toolArgs?: Record<string, unknown>; agentRole?: string; parentMaxAmount?: number; childMaxAmount?: number; pinnedHash?: string; presentedHash?: string }; expect: { action: string } }>
  }

  it('executes every vector', () => {
    expect(document.vectors.map((vector) => vector.id)).toEqual([
      'mcp-pol-block',
      'mcp-pol-allow',
      'mcp-auth-over-delegation',
      'mcp-auth-require-human',
      'mcp-auth-tool-def-drift',
    ])
    for (const vector of document.vectors) {
      if (vector.claim === 'policy-only') {
        const decision = evaluateToolCall({
          policy: BASIC_AGENT_AUTHORITY,
          toolName: vector.input?.toolName ?? '',
          toolArgs: vector.input?.toolArgs ?? {},
          agentRole: vector.input?.agentRole ?? 'agt_reader',
        })
        expect(decision.action).toBe(vector.expect.action)
      }
      if (vector.id === 'mcp-auth-over-delegation') {
        expect((vector.input?.childMaxAmount ?? 0) > (vector.input?.parentMaxAmount ?? 0)).toBe(true)
        expect(vector.expect.action).toBe('BLOCK')
      }
      if (vector.id === 'mcp-auth-tool-def-drift') {
        expect(vector.input?.pinnedHash).not.toBe(vector.input?.presentedHash)
        expect(vector.expect.action).toBe('BLOCK')
      }
    }
    expect(sha256({ marker: 'vectors-loaded' })).toHaveLength(64)
  })
})
