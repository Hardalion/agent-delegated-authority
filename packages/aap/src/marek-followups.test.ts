import { describe, expect, it } from 'vitest'
import { verifyAuthorizationReceipt } from 'adap-receipt'
import type { Policy } from 'adap-policy'
import { FixedClock } from './clock.js'
import { importPublicKey, sha256 } from './crypto.js'
import { MemoryAuthorityDirectory } from './directory.js'
import { NonceLedger } from './nonce.js'
import {
  ExecutionOutcomeUnknownError,
  authenticatedReceipt,
  runAuthorityPath,
  verifyProtocolReceipt,
} from './path.js'
import { PendingAuthorizationStore } from './pending.js'
import { ImmutablePolicyResolver } from './policy-resolver.js'
import { BASIC_AGENT_AUTHORITY, BASIC_AGENT_AUTHORITY_URI } from './example-policy.js'
import {
  createIdentity,
  signApproval,
  signDelegation,
  signIntent,
  unsignedDelegation,
  unsignedIntent,
} from './protocol.js'
import { adapBindingForMcpCall, hashMcpToolDefinition } from './mcp-tool.js'

const NOW = new Date('2026-10-06T18:00:00.000Z')
const ISSUED = NOW.toISOString()
const EXPIRES = new Date(NOW.getTime() + 4 * 60 * 1000).toISOString()
const AUDIENCE = 'https://gw-a.example'

const TOOL = {
  server_id: 'treasury',
  tool_name: 'pay',
  description: 'move funds',
  input_schema: { type: 'object', properties: { amount: { type: 'integer' } } },
}

function base(
  constraints: Record<string, string | number | boolean> = {},
  capabilities: { action: string; target: string; delegable: boolean }[] = [
    { action: 'read', target: 'resource/*', delegable: true },
  ],
) {
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
      capabilities,
      constraints,
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

function intentFor(
  env: ReturnType<typeof base>,
  nonce: string,
  action = 'read',
  target = 'resource/example',
) {
  return signIntent(
    {
      intent_id: `int_${nonce}`,
      actor: env.agent.id,
      delegation_chain: [env.root.delegation_id],
      action,
      target,
      parameters: {},
      nonce,
      issued_at: ISSUED,
      expires_at: EXPIRES,
      aud: AUDIENCE,
    },
    env.agent,
  )
}

function pathInput(
  env: ReturnType<typeof base>,
  nonce: string,
  extra: Record<string, unknown> = {},
  action = 'read',
  target = 'resource/example',
) {
  return {
    chain: [env.root],
    intent: intentFor(env, nonce, action, target),
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
    revocationCheck: () => 'active' as const,
    ...extra,
  }
}

describe('Marek follow-ups', () => {
  it('blocks a drifted MCP tool definition before dispatch and allows the pinned hash', async () => {
    const pin = hashMcpToolDefinition(TOOL)
    const drifted = hashMcpToolDefinition({ ...TOOL, description: 'move funds now' })
    expect(drifted).not.toBe(pin)
    expect(hashMcpToolDefinition({ ...TOOL, title: 'Pay' })).not.toBe(pin)

    let calls = 0
    const pinned = base({ tool_definition_hash: pin })
    const allowed = await runAuthorityPath({
      ...pathInput(pinned, 'nonce-pin-ok', { mcpToolDefinitionHash: pin }),
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(allowed.decision).toBe('ALLOW')
    expect(calls).toBe(1)
    expect(authenticatedReceipt(allowed).execution?.outcome).toBe('returned')

    calls = 0
    const driftedEnv = base({ tool_definition_hash: pin })
    const blocked = await runAuthorityPath({
      ...pathInput(driftedEnv, 'nonce-pin-drift', { mcpToolDefinitionHash: drifted }),
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(blocked.decision).toBe('BLOCK')
    expect(blocked.ruleId).toBe('tool_definition')
    expect(calls).toBe(0)
    expect(authenticatedReceipt(blocked).execution?.outcome).toBe('not_dispatched')

    const missing = await runAuthorityPath(pathInput(base({ tool_definition_hash: pin }), 'nonce-pin-missing'))
    expect(missing.decision).toBe('BLOCK')
    expect(missing.ruleId).toBe('tool_definition')
  })

  it('rejects a server id that would collide with a dotted tool name', () => {
    expect(adapBindingForMcpCall('treasury', 'repos.delete')).toEqual({
      action: 'treasury.repos.delete',
      target: 'mcp/treasury/repos.delete',
    })
    expect(() => adapBindingForMcpCall('gh.repos', 'delete')).toThrow(/server_id/)
  })

  it('records ALLOW and SYSTEM_ERROR when dispatch has begun and the outcome is unknown', async () => {
    const env = base()
    const cases = [
      {
        nonce: 'nonce-unknown',
        execute: () => {
          throw new ExecutionOutcomeUnknownError('downstream outcome unknown')
        },
      },
      {
        nonce: 'nonce-throw',
        execute: () => {
          throw new Error('downstream write may have started')
        },
      },
    ]
    for (const item of cases) {
      const result = await runAuthorityPath({
        ...pathInput(env, item.nonce),
        execute: item.execute,
      })
      expect(result.decision).toBe('ALLOW')
      expect(result.ruleId).toBe('read_allow')
      expect(result.executed).toBe(false)
      const receipt = authenticatedReceipt(result)
      expect(receipt.decision.action).toBe('ALLOW')
      expect(receipt.decision.failureMode).toBe('SYSTEM_ERROR')
      expect(receipt.execution?.outcome).toBe('unknown')
      expect(receipt.execution?.executed).toBe(false)
      expect(verifyProtocolReceipt(receipt, importPublicKey(env.signer.publicKey)).valid).toBe(true)
      const offline = verifyAuthorizationReceipt(receipt, {
        publicKeySpki: env.signer.publicKey,
      })
      expect(offline.valid).toBe(true)
      expect(offline.status).toBe('verified')
    }
  })

  it('blocks an authority-enforcing MCP call that omits the tool pin, including approval resume', async () => {
    const env = base({}, [{ action: 'treasury.pay', target: 'mcp/treasury/pay', delegable: true }])
    let calls = 0
    const direct = await runAuthorityPath({
      ...pathInput(env, 'nonce-mcp-missing', {}, 'treasury.pay', 'mcp/treasury/pay'),
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(direct.decision).toBe('BLOCK')
    expect(direct.ruleId).toBe('tool_definition')
    expect(calls).toBe(0)
    expect(authenticatedReceipt(direct).execution?.outcome).toBe('not_dispatched')

    const intent = intentFor(env, 'nonce-mcp-resume', 'treasury.pay', 'mcp/treasury/pay')
    const approval = signApproval(
      {
        intent_hash: sha256(unsignedIntent(intent)),
        approver_id: env.principal.id,
        approved_at: ISSUED,
        decision: 'APPROVE',
        agent_id: env.agent.id,
        delegation_chain_hash: sha256([unsignedDelegation(env.root)]),
        policy_content_hash: sha256(BASIC_AGENT_AUTHORITY),
        matched_rule_id: 'apply_needs_human',
        aud: AUDIENCE,
      },
      env.principal,
    )
    const resumed = await runAuthorityPath({
      ...pathInput(env, 'nonce-mcp-resume', { intent, approval }, 'treasury.pay', 'mcp/treasury/pay'),
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(resumed.decision).toBe('BLOCK')
    expect(resumed.ruleId).toBe('tool_definition')
    expect(calls).toBe(0)
    expect(authenticatedReceipt(resumed).execution?.outcome).toBe('not_dispatched')
  })

  it('rejects a hand-built MCP action and target with a bad server id before dispatch', async () => {
    const env = base()
    let calls = 0
    const dotted = await runAuthorityPath({
      ...pathInput(env, 'nonce-dot-server', {}, 'gh.repos.delete', 'mcp/gh.repos/delete'),
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(dotted.decision).toBe('BLOCK')
    expect(dotted.ruleId).toBe('mcp_binding')
    expect(dotted.reason).toMatch(/server_id/)
    expect(calls).toBe(0)
    expect(authenticatedReceipt(dotted).execution?.outcome).toBe('not_dispatched')

    const slashed = await runAuthorityPath({
      ...pathInput(env, 'nonce-slash-server', {}, 'gh.repos.delete', 'mcp/gh/repos/delete'),
      execute: () => {
        calls += 1
        return { ok: true }
      },
    })
    expect(slashed.decision).toBe('BLOCK')
    expect(slashed.ruleId).toBe('mcp_binding')
    expect(calls).toBe(0)
    expect(authenticatedReceipt(slashed).execution?.outcome).toBe('not_dispatched')
  })

  it('does not report verified for a dev opt-out receipt', async () => {
    const env = base()
    const result = await runAuthorityPath({
      ...pathInput(env, 'nonce-dev', {
        unsafeDevAllowUnconfiguredChecks: true,
        rootAuthority: undefined,
        revocationCheck: undefined,
        audience: undefined,
      }),
      execute: () => ({ ok: true }),
    })
    const receipt = authenticatedReceipt(result)
    const offline = verifyAuthorizationReceipt(receipt, {
      publicKeySpki: env.signer.publicKey,
    })
    expect(offline.valid).toBe(false)
    expect(offline.status).toBe('verified_nonconforming')
    expect(offline.failureReason).toBe('DEV_UNCONFIGURED_CHECKS')
    expect(verifyProtocolReceipt(receipt, importPublicKey(env.signer.publicKey)).valid).toBe(true)
  })

  it('exposes the authorized target to policy conditions', async () => {
    const policy: Policy = {
      version: '1.0.0',
      policyName: 'target-visible',
      targetAgents: ['*'],
      defaultAction: 'BLOCK',
      rules: [
        {
          ruleId: 'on_target',
          action: 'ALLOW',
          condition: "tool.target == 'resource/example'",
          alertSeverity: 'LOW',
        },
      ],
    }
    const env = base()
    const uri = 'target-visible@1'
    env.policyResolver.register(policy, uri)
    const allowed = await runAuthorityPath({
      ...pathInput(env, 'nonce-target'),
      policy,
      policyUri: uri,
      execute: () => ({ ok: true }),
    })
    expect(allowed.decision).toBe('ALLOW')
    expect(allowed.ruleId).toBe('on_target')
  })
})
