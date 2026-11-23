import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import type { Policy } from 'adap-policy'
import { verifyAuthorizationReceipt, type AuthorizationReceiptV1 } from 'adap-receipt'
import { FixedClock } from './clock.js'
import { importPublicKey, sha256 } from './crypto.js'
import { MemoryAuthorityDirectory } from './directory.js'
import {
  adapBindingForMcpCall,
  hashMcpToolDefinition,
  verifyReceiptMcpToolBinding,
  type McpToolDefinition,
} from './mcp-tool.js'
import { NonceLedger } from './nonce.js'
import {
  authenticatedReceipt,
  runAuthorityPath,
  verifyProtocolReceipt,
  type ExecutionContext,
  type RunAuthorityPathInput,
} from './path.js'
import { PendingAuthorizationStore } from './pending.js'
import { ImmutablePolicyResolver } from './policy-resolver.js'
import { createIdentity, signApproval, signDelegation, signIntent, unsignedDelegation } from './protocol.js'

const NOW = new Date('2026-10-06T18:00:00.000Z')
const ISSUED = NOW.toISOString()
const EXPIRES = new Date(NOW.getTime() + 4 * 60 * 1000).toISOString()
const AUDIENCE = 'https://gw-mcp.example'
const POLICY_URI = 'mcp-tools@1.0.0'

const POLICY: Policy = {
  version: '1.0.0',
  policyName: 'mcp-tools',
  description: 'Synthetic MCP policy. lookup is allowed. pay waits for a person. pay over 100 is blocked.',
  targetAgents: ['*'],
  defaultAction: 'BLOCK',
  rules: [
    {
      ruleId: 'pay_over_cap',
      action: 'BLOCK',
      condition: "tool.name == 'treasury.pay' && args.amount > 100",
      alertSeverity: 'CRITICAL',
    },
    {
      ruleId: 'pay_needs_human',
      action: 'REQUIRE_HUMAN',
      condition: "tool.name == 'treasury.pay'",
      alertSeverity: 'MEDIUM',
    },
    {
      ruleId: 'lookup_allow',
      action: 'ALLOW',
      condition: "tool.name == 'crm.lookup'",
      alertSeverity: 'LOW',
    },
  ],
}

const LOOKUP: McpToolDefinition = {
  server_id: 'crm',
  tool_name: 'lookup',
  description: 'Look up a customer record by id',
  input_schema: { type: 'object', properties: { customer_id: { type: 'string' } } },
}

const PAY: McpToolDefinition = {
  server_id: 'treasury',
  tool_name: 'pay',
  description: 'Send a payment',
  input_schema: { type: 'object', properties: { amount: { type: 'integer' } } },
}

/** One grant per tool: `tool_definition_hash` is a delegation constraint, so it pins every capability in the grant. */
function base(tool: McpToolDefinition, pin: string = hashMcpToolDefinition(tool)) {
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
  const call = adapBindingForMcpCall(tool.server_id, tool.tool_name)
  const root = signDelegation(
    {
      delegation_id: 'del_mcp_root',
      issuer: principal.id,
      subject: agent.id,
      capabilities: [{ action: call.action, target: call.target }],
      constraints: { tool_definition_hash: pin },
      issued_at: ISSUED,
      expires_at: EXPIRES,
      aud: AUDIENCE,
    },
    principal,
  )
  const policyResolver = new ImmutablePolicyResolver()
  policyResolver.register(POLICY, POLICY_URI)
  return { tool, call, principal, agent, signer, directory, root, policyResolver }
}

type Env = ReturnType<typeof base>

function intentFor(env: Env, nonce: string, parameters: Readonly<Record<string, unknown>>) {
  return signIntent(
    {
      intent_id: `int_${nonce}`,
      actor: env.agent.id,
      delegation_chain: [env.root.delegation_id],
      action: env.call.action,
      target: env.call.target,
      parameters,
      nonce,
      issued_at: ISSUED,
      expires_at: EXPIRES,
      aud: AUDIENCE,
    },
    env.agent,
  )
}

async function run(
  env: Env,
  intent: ReturnType<typeof intentFor>,
  extra: Partial<RunAuthorityPathInput> = {},
) {
  const seen: ExecutionContext[] = []
  const result = await runAuthorityPath({
    chain: [env.root],
    intent,
    directory: env.directory,
    policy: POLICY,
    policyUri: POLICY_URI,
    clock: new FixedClock(NOW),
    ledger: new NonceLedger(),
    pendingStore: new PendingAuthorizationStore(),
    policyResolver: env.policyResolver,
    signer: env.signer,
    audience: AUDIENCE,
    rootAuthority: { mayIssueRoot: () => true },
    revocationCheck: () => 'active',
    mcpToolDefinitionHash: hashMcpToolDefinition(env.tool),
    execute: (ctx) => {
      seen.push(ctx)
      return { ok: true }
    },
    ...extra,
  })
  return { result, seen }
}

function verifiesWithIssuerKey(env: Env, receipt: AuthorizationReceiptV1): boolean {
  return verifyProtocolReceipt(receipt, importPublicKey(env.signer.publicKey)).valid
}

describe('receipt binds the MCP tool-definition hash', () => {
  it('binds the pinned hash on an ALLOW receipt and hands it to the executor', async () => {
    const env = base(LOOKUP)
    const { result, seen } = await run(env, intentFor(env, 'nonce-mcp-allow', { customer_id: 'c_1' }))

    expect(result.decision).toBe('ALLOW')
    expect(result.executed).toBe(true)
    const receipt = authenticatedReceipt(result)
    expect(receipt.execution?.toolDefinitionHash).toBe(hashMcpToolDefinition(LOOKUP))
    expect(verifiesWithIssuerKey(env, receipt)).toBe(true)
    expect(verifyReceiptMcpToolBinding(receipt, LOOKUP)).toEqual({ valid: true, errors: [] })

    expect(seen).toHaveLength(1)
    expect(seen[0]?.toolDefinitionHash).toBe(hashMcpToolDefinition(LOOKUP))
  })

  it('lets a verifier detect a definition that changed after the receipt was issued', async () => {
    const env = base(LOOKUP)
    const receipt = authenticatedReceipt(
      (await run(env, intentFor(env, 'nonce-mcp-later', { customer_id: 'c_1' }))).result,
    )
    const changed: McpToolDefinition = {
      ...LOOKUP,
      annotations: { destructiveHint: true },
    }
    expect(verifyReceiptMcpToolBinding(receipt, changed)).toEqual({
      valid: false,
      errors: ['receipt binds a different tool definition'],
    })
    expect(verifyReceiptMcpToolBinding(receipt, PAY).valid).toBe(false)
    expect(verifyReceiptMcpToolBinding(receipt, { ...LOOKUP, server_id: 'crm.v2' }).errors).toEqual([
      'tool definition is malformed or could not be canonicalized',
    ])
  })

  it('covers the hash with the content hash and the signature', async () => {
    const env = base(LOOKUP)
    const receipt = authenticatedReceipt(
      (await run(env, intentFor(env, 'nonce-mcp-tamper', { customer_id: 'c_1' }))).result,
    )
    const swapped: AuthorizationReceiptV1 = {
      ...receipt,
      execution: {
        ...receipt.execution!,
        toolDefinitionHash: hashMcpToolDefinition({ ...LOOKUP, description: 'swapped' }),
      },
    }
    expect(verifyAuthorizationReceipt(swapped).contentHashOk).toBe(false)
    expect(verifiesWithIssuerKey(env, swapped)).toBe(false)
  })

  it('binds the hash on BLOCK and REQUIRE_HUMAN receipts, and on the receipt after approval', async () => {
    const env = base(PAY)

    const blocked = await run(env, intentFor(env, 'nonce-mcp-block', { amount: 300 }))
    expect(blocked.result.decision).toBe('BLOCK')
    expect(blocked.result.ruleId).toBe('pay_over_cap')
    expect(blocked.seen).toHaveLength(0)
    const blockedReceipt = authenticatedReceipt(blocked.result)
    expect(blockedReceipt.execution?.toolDefinitionHash).toBe(hashMcpToolDefinition(PAY))
    expect(verifiesWithIssuerKey(env, blockedReceipt)).toBe(true)

    const ledger = new NonceLedger()
    const pendingStore = new PendingAuthorizationStore()
    const intent = intentFor(env, 'nonce-mcp-human', { amount: 40 })
    const paused = await run(env, intent, { ledger, pendingStore })
    expect(paused.result.decision).toBe('REQUIRE_HUMAN')
    expect(paused.seen).toHaveLength(0)
    const pausedReceipt = authenticatedReceipt(paused.result)
    expect(pausedReceipt.execution?.toolDefinitionHash).toBe(hashMcpToolDefinition(PAY))
    expect(verifiesWithIssuerKey(env, pausedReceipt)).toBe(true)

    const approval = signApproval(
      {
        intent_hash: paused.result.intentHash,
        approver_id: env.principal.id,
        approved_at: ISSUED,
        decision: 'APPROVE',
        agent_id: env.agent.id,
        delegation_chain_hash: sha256([env.root].map(unsignedDelegation)),
        policy_content_hash: paused.result.policyHash,
        matched_rule_id: paused.result.ruleId,
        aud: AUDIENCE,
      },
      env.principal,
    )
    const resumed = await run(env, intent, { ledger, pendingStore, approval })
    expect(resumed.result.decision).toBe('ALLOW')
    expect(resumed.seen).toHaveLength(1)
    expect(resumed.seen[0]?.toolDefinitionHash).toBe(hashMcpToolDefinition(PAY))
    const resumedReceipt = authenticatedReceipt(resumed.result)
    expect(resumedReceipt.human?.status).toBe('approved')
    expect(resumedReceipt.execution?.toolDefinitionHash).toBe(pausedReceipt.execution?.toolDefinitionHash)
    expect(verifiesWithIssuerKey(env, resumedReceipt)).toBe(true)
    expect(verifyReceiptMcpToolBinding(resumedReceipt, PAY).valid).toBe(true)
  })

  it('records the presented hash when it does not match the pin', async () => {
    const env = base(PAY)
    const drifted: McpToolDefinition = { ...PAY, description: 'Send a payment to any account' }
    const { result, seen } = await run(env, intentFor(env, 'nonce-mcp-drift', { amount: 40 }), {
      mcpToolDefinitionHash: hashMcpToolDefinition(drifted),
    })

    expect(result.decision).toBe('BLOCK')
    expect(result.ruleId).toBe('tool_definition')
    expect(seen).toHaveLength(0)
    const receipt = authenticatedReceipt(result)
    expect(receipt.execution?.executed).toBe(false)
    expect(receipt.execution?.toolDefinitionHash).toBe(hashMcpToolDefinition(drifted))
    expect(verifiesWithIssuerKey(env, receipt)).toBe(true)
    // The signed record shows which definition the runtime was about to call.
    expect(verifyReceiptMcpToolBinding(receipt, PAY).valid).toBe(false)
    expect(verifyReceiptMcpToolBinding(receipt, drifted).valid).toBe(true)
  })

  it('does not bind a malformed runtime hash and still emits a valid receipt', async () => {
    const env = base(LOOKUP)
    const pin = hashMcpToolDefinition(LOOKUP)
    for (const [index, mcpToolDefinitionHash] of [
      pin.slice('sha256:'.length),
      pin.toUpperCase(),
      `${pin}0`,
      '',
    ].entries()) {
      const { result, seen } = await run(env, intentFor(env, `nonce-mcp-bad-${index}`, { customer_id: 'c_1' }), {
        mcpToolDefinitionHash,
      })
      expect(result.decision).toBe('BLOCK')
      expect(result.ruleId).toBe('tool_definition')
      expect(seen).toHaveLength(0)
      const receipt = authenticatedReceipt(result)
      expect(receipt.execution).not.toHaveProperty('toolDefinitionHash')
      expect(verifiesWithIssuerKey(env, receipt)).toBe(true)
    }
  })

  it('binds only on calls the path pin-checks', async () => {
    const env = base(LOOKUP)
    const pin = hashMcpToolDefinition(LOOKUP)
    const policy: Policy = {
      ...POLICY,
      rules: [{ ruleId: 'read_allow', action: 'ALLOW', condition: "tool.name == 'read'", alertSeverity: 'LOW' }],
    }
    const policyResolver = new ImmutablePolicyResolver()
    policyResolver.register(policy, 'plain-read@1.0.0')

    const readUnder = async (nonce: string, constraints: Record<string, string>, mcpToolDefinitionHash?: string) => {
      const grant = signDelegation(
        {
          delegation_id: `del_${nonce}`,
          issuer: env.principal.id,
          subject: env.agent.id,
          capabilities: [{ action: 'read', target: 'resource/*' }],
          constraints,
          issued_at: ISSUED,
          expires_at: EXPIRES,
          aud: AUDIENCE,
        },
        env.principal,
      )
      const intent = signIntent(
        {
          intent_id: `int_${nonce}`,
          actor: env.agent.id,
          delegation_chain: [grant.delegation_id],
          action: 'read',
          target: 'resource/example',
          parameters: {},
          nonce,
          issued_at: ISSUED,
          expires_at: EXPIRES,
          aud: AUDIENCE,
        },
        env.agent,
      )
      return run({ ...env, root: grant }, intent, {
        policy,
        policyUri: 'plain-read@1.0.0',
        policyResolver,
        mcpToolDefinitionHash,
      })
    }

    // No runtime hash: the receipt is unchanged.
    const plain = await readUnder('nonce-plain', {})
    expect(plain.result.decision).toBe('ALLOW')
    expect(authenticatedReceipt(plain.result).execution).not.toHaveProperty('toolDefinitionHash')
    expect(plain.seen[0]).not.toHaveProperty('toolDefinitionHash')
    expect(verifyReceiptMcpToolBinding(authenticatedReceipt(plain.result), LOOKUP).errors).toContain(
      'receipt does not bind a tool definition',
    )

    // A hash on a call nothing pin-checks is not presented as if it had been checked.
    const unchecked = await readUnder('nonce-unchecked', {}, pin)
    expect(unchecked.result.decision).toBe('ALLOW')
    expect(authenticatedReceipt(unchecked.result).execution).not.toHaveProperty('toolDefinitionHash')
    expect(unchecked.seen[0]).not.toHaveProperty('toolDefinitionHash')

    // A non-MCP grant that sets a pin is pin-checked, so the receipt binds it.
    const pinned = await readUnder('nonce-pinned', { tool_definition_hash: pin }, pin)
    expect(pinned.result.decision).toBe('ALLOW')
    const receipt = authenticatedReceipt(pinned.result)
    expect(receipt.execution?.toolDefinitionHash).toBe(pin)
    expect(pinned.seen[0]?.toolDefinitionHash).toBe(pin)
    expect(verifiesWithIssuerKey(env, receipt)).toBe(true)
  })
})

describe('mcp tool-definition hash vector', () => {
  it('matches the language-independent vector', () => {
    const file = new URL('../../../examples/conformance/mcp-vectors.json', import.meta.url)
    const document = JSON.parse(readFileSync(file, 'utf8')) as {
      vectors: Array<{
        id: string
        input?: { toolDefinition?: McpToolDefinition }
        expect: { toolDefinitionHash?: string; adapAction?: string; adapTarget?: string }
      }>
    }
    const vector = document.vectors.find((item) => item.id === 'mcp-receipt-tool-def-binding')
    expect(vector?.input?.toolDefinition).toBeDefined()
    const definition = vector!.input!.toolDefinition!
    expect(hashMcpToolDefinition(definition)).toBe(vector!.expect.toolDefinitionHash)
    const binding = adapBindingForMcpCall(definition.server_id, definition.tool_name)
    expect(binding.action).toBe(vector!.expect.adapAction)
    expect(binding.target).toBe(vector!.expect.adapTarget)
  })
})
