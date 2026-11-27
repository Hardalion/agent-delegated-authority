/**
 * The authority path validates intent.parameters against the pinned MCP
 * input_schema when the runtime presents the tool definition. Undeclared keys,
 * case/fold-variant keys, and type-mismatched values are BLOCK (parameter_schema)
 * and never reach the executor, so the authority view of the parameters and the
 * downstream executor's view cannot diverge. Omitting the definition preserves
 * the prior hash-pin-only behaviour.
 */
import { describe, expect, it } from 'vitest'
import type { Policy } from 'adap-policy'
import { FixedClock } from './clock.js'
import { MemoryAuthorityDirectory } from './directory.js'
import { adapBindingForMcpCall, hashMcpToolDefinition, type McpToolDefinition } from './mcp-tool.js'
import { NonceLedger } from './nonce.js'
import {
  authenticatedReceipt,
  runAuthorityPath,
  type ExecutionContext,
  type RunAuthorityPathInput,
} from './path.js'
import { PendingAuthorizationStore } from './pending.js'
import { ImmutablePolicyResolver } from './policy-resolver.js'
import { createIdentity, signDelegation, signIntent } from './protocol.js'

const NOW = new Date('2026-10-06T18:00:00.000Z')
const ISSUED = NOW.toISOString()
const EXPIRES = new Date(NOW.getTime() + 4 * 60 * 1000).toISOString()
const AUDIENCE = 'https://gw-mcp.example'
const POLICY_URI = 'mcp-lookup@1.0.0'

const POLICY: Policy = {
  version: '1.0.0',
  policyName: 'mcp-lookup',
  targetAgents: ['*'],
  defaultAction: 'BLOCK',
  rules: [{ ruleId: 'lookup_allow', action: 'ALLOW', condition: "tool.name == 'crm.lookup'", alertSeverity: 'LOW' }],
}

const LOOKUP: McpToolDefinition = {
  server_id: 'crm',
  tool_name: 'lookup',
  description: 'Look up a customer record by id',
  input_schema: {
    type: 'object',
    additionalProperties: false,
    required: ['customer_id'],
    properties: { customer_id: { type: 'string' } },
  },
}

function env() {
  const principal = createIdentity('prn_example')
  const agent = createIdentity('agt_example')
  const signer = createIdentity('reference-runtime')
  const directory = new MemoryAuthorityDirectory([
    { identityId: principal.id, kid: principal.kid, alg: 'Ed25519', publicKey: principal.publicKey, status: 'active', kind: 'human' },
    { identityId: agent.id, kid: agent.kid, alg: 'Ed25519', publicKey: agent.publicKey, status: 'active', kind: 'agent' },
  ])
  const call = adapBindingForMcpCall(LOOKUP.server_id, LOOKUP.tool_name)
  const root = signDelegation(
    {
      delegation_id: 'del_mcp_root',
      issuer: principal.id,
      subject: agent.id,
      capabilities: [{ action: call.action, target: call.target }],
      constraints: { tool_definition_hash: hashMcpToolDefinition(LOOKUP) },
      issued_at: ISSUED,
      expires_at: EXPIRES,
      aud: AUDIENCE,
    },
    principal,
  )
  const policyResolver = new ImmutablePolicyResolver()
  policyResolver.register(POLICY, POLICY_URI)
  return { call, principal, agent, signer, directory, root, policyResolver }
}

async function run(
  e: ReturnType<typeof env>,
  parameters: Readonly<Record<string, unknown>>,
  extra: Partial<RunAuthorityPathInput> = {},
) {
  const seen: ExecutionContext[] = []
  const intent = signIntent(
    {
      intent_id: 'int_poc',
      actor: e.agent.id,
      delegation_chain: [e.root.delegation_id],
      action: e.call.action,
      target: e.call.target,
      parameters,
      nonce: `nonce_${Math.random().toString(36).slice(2)}`,
      issued_at: ISSUED,
      expires_at: EXPIRES,
      aud: AUDIENCE,
    },
    e.agent,
  )
  const result = await runAuthorityPath({
    chain: [e.root],
    intent,
    directory: e.directory,
    policy: POLICY,
    policyUri: POLICY_URI,
    clock: new FixedClock(NOW),
    ledger: new NonceLedger(),
    pendingStore: new PendingAuthorizationStore(),
    policyResolver: e.policyResolver,
    signer: e.signer,
    audience: AUDIENCE,
    rootAuthority: { mayIssueRoot: () => true },
    revocationCheck: () => 'active',
    mcpToolDefinitionHash: hashMcpToolDefinition(LOOKUP),
    mcpToolDefinition: LOOKUP,
    execute: (ctx) => {
      seen.push(ctx)
      return { ok: true }
    },
    ...extra,
  })
  return { result, seen }
}

describe('authority path enforces the pinned input_schema on parameters', () => {
  it('allows a conforming bag and records checks_applied.parameter_schema', async () => {
    const e = env()
    const { result, seen } = await run(e, { customer_id: 'c_1' })
    expect(result.decision).toBe('ALLOW')
    expect(seen).toHaveLength(1)
    const checks = authenticatedReceipt(result).extensions?.checks_applied as { parameter_schema: boolean }
    expect(checks.parameter_schema).toBe(true)
  })

  it('BLOCKs an undeclared key and never dispatches', async () => {
    const e = env()
    const { result, seen } = await run(e, { customer_id: 'c_1', internal_override: true })
    expect(result.decision).toBe('BLOCK')
    expect(result.ruleId).toBe('parameter_schema')
    expect(seen).toHaveLength(0)
  })

  it('BLOCKs a case/fold-variant of a declared key', async () => {
    const e = env()
    const { result, seen } = await run(e, { customer_id: 'c_1', customer_ID: 'c_victim' })
    expect(result.decision).toBe('BLOCK')
    expect(result.ruleId).toBe('parameter_schema')
    expect(seen).toHaveLength(0)
  })

  it('BLOCKs an array where the schema declares a scalar', async () => {
    const e = env()
    const { result, seen } = await run(e, { customer_id: ['c_1', 'c_victim'] })
    expect(result.decision).toBe('BLOCK')
    expect(result.ruleId).toBe('parameter_schema')
    expect(seen).toHaveLength(0)
  })

  it('BLOCKs a presented definition whose hash does not match the pin', async () => {
    const e = env()
    const drifted: McpToolDefinition = { ...LOOKUP, description: 'changed' }
    const { result, seen } = await run(e, { customer_id: 'c_1' }, { mcpToolDefinition: drifted })
    expect(result.decision).toBe('BLOCK')
    expect(result.ruleId).toBe('tool_definition')
    expect(seen).toHaveLength(0)
  })

  it('preserves prior behaviour when no definition is presented (extra keys flow through)', async () => {
    const e = env()
    const { result, seen } = await run(
      e,
      { customer_id: 'c_1', customer_ID: 'c_victim', internal_override: true },
      { mcpToolDefinition: undefined },
    )
    expect(result.decision).toBe('ALLOW')
    expect(seen).toHaveLength(1)
    expect(seen[0]?.parameters).toMatchObject({ customer_ID: 'c_victim', internal_override: true })
    const checks = authenticatedReceipt(result).extensions?.checks_applied as { parameter_schema: boolean }
    expect(checks.parameter_schema).toBe(false)
  })
})
