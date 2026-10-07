import { NonceLedger } from './nonce.js'
import { runAuthorityPath, type ExecutionContext, type ProtocolResult } from './path.js'
import { BASIC_AGENT_AUTHORITY, BASIC_AGENT_AUTHORITY_URI } from './example-policy.js'
import {
  createIdentity,
  signApproval,
  signDelegation,
  signIntent,
  type Constraints,
  type SignedDelegation,
} from './protocol.js'

export const DEMO_NOW = new Date('2026-10-06T18:00:00.000Z')

export interface AgentToAgentDemo {
  readonly root: SignedDelegation
  readonly toAgentB: SignedDelegation
  readonly agentBView: {
    readonly delegationSubject: string
    readonly capabilities: readonly string[]
  }
  readonly read: ProtocolResult
  readonly agentBApply: ProtocolResult
  readonly redelegatedApply: ProtocolResult
  readonly overCap: ProtocolResult
  readonly applyPending: ProtocolResult
  readonly apply: ProtocolResult
  readonly replay: ProtocolResult
  readonly executionCount: number
  readonly contexts: readonly ExecutionContext[]
  readonly signerPublicKey: string
}

const CONSTRAINTS: Constraints = { max_amount: 500 }

/**
 * Reference walkthrough. Not normative.
 * Principal → Agent A → Agent B → authorized action → receipt.
 * Agent B may read. Apply stays with Agent A and waits for the principal.
 */
export async function runAgentToAgentDemo(input?: { readonly now?: Date }): Promise<AgentToAgentDemo> {
  const now = input?.now ?? DEMO_NOW
  const issued = now.toISOString()
  const parentExpiry = new Date(now.getTime() + 15 * 60 * 1000).toISOString()
  const childExpiry = new Date(now.getTime() + 10 * 60 * 1000).toISOString()

  const principal = createIdentity('prn_example')
  const agentA = createIdentity('agt_a')
  const agentB = createIdentity('agt_b')
  const signer = createIdentity('reference-runtime')
  const directory = new Map(
    [principal, agentA, agentB, signer].map((identity) => [identity.id, identity.publicKey])
  )
  const ledger = new NonceLedger()
  const contexts: ExecutionContext[] = []
  let executionCount = 0

  const root = signDelegation(
    {
      delegation_id: 'del_root',
      issuer: principal.id,
      subject: agentA.id,
      capabilities: [
        { action: 'read', target: 'resource/*' },
        { action: 'apply', target: 'resource/*', delegable: false },
      ],
      constraints: CONSTRAINTS,
      issued_at: issued,
      expires_at: parentExpiry,
    },
    principal
  )
  const toAgentB = signDelegation(
    {
      delegation_id: 'del_b',
      issuer: agentA.id,
      subject: agentB.id,
      capabilities: [{ action: 'read', target: 'resource/example' }],
      constraints: CONSTRAINTS,
      issued_at: issued,
      expires_at: childExpiry,
      parent_delegation_id: root.delegation_id,
    },
    agentA
  )

  const read = await runAuthorityPath({
    chain: [root, toAgentB],
    intent: signIntent(
      {
        intent_id: 'int_read',
        actor: agentB.id,
        delegation_chain: [root.delegation_id, toAgentB.delegation_id],
        action: 'read',
        target: 'resource/example',
        parameters: {},
        nonce: 'nonce_read',
        issued_at: issued,
        expires_at: childExpiry,
      },
      agentB
    ),
    directory,
    policy: BASIC_AGENT_AUTHORITY,
    policyUri: BASIC_AGENT_AUTHORITY_URI,
    now,
    ledger,
    signer,
    execute: (ctx) => {
      executionCount += 1
      contexts.push(ctx)
      return { resource: ctx.target }
    },
  })

  const agentBApply = await run(applyIntent(agentB.id, [root.delegation_id, toAgentB.delegation_id], 'nonce_b_apply', 420), [
    root,
    toAgentB,
  ])

  const passedCommit = signDelegation(
    {
      delegation_id: 'del_passed_apply',
      issuer: agentA.id,
      subject: agentB.id,
      capabilities: [{ action: 'apply', target: 'resource/example' }],
      constraints: CONSTRAINTS,
      issued_at: issued,
      expires_at: childExpiry,
      parent_delegation_id: root.delegation_id,
    },
    agentA
  )
  const redelegatedApply = await run(
    applyIntent(agentB.id, [root.delegation_id, passedCommit.delegation_id], 'nonce_passed', 420),
    [root, passedCommit]
  )

  const overCap = await run(applyIntent(agentA.id, [root.delegation_id], 'nonce_over', 610), [root])

  const applyBody = applyIntent(agentA.id, [root.delegation_id], 'nonce_apply', 420)
  const applyPending = await run(applyBody, [root])
  const apply = await runAuthorityPath({
    chain: [root],
    intent: applyBody,
    directory,
    policy: BASIC_AGENT_AUTHORITY,
    policyUri: BASIC_AGENT_AUTHORITY_URI,
    now,
    ledger,
    signer,
    approval: signApproval(
      {
        intent_hash: applyPending.intentHash,
        approver_id: principal.id,
        approved_at: issued,
        decision: 'APPROVE',
      },
      principal
    ),
    execute: (ctx) => {
      executionCount += 1
      contexts.push(ctx)
      if (ctx.actor !== agentA.id) throw new Error('executor actor mismatch')
      return { ref: 'act-example', amount: ctx.parameters.amount }
    },
  })
  const replay = await run(applyBody, [root])

  return {
    root,
    toAgentB,
    agentBView: {
      delegationSubject: toAgentB.subject,
      capabilities: toAgentB.capabilities.map((capability) => capability.action),
    },
    read,
    agentBApply,
    redelegatedApply,
    overCap,
    applyPending,
    apply,
    replay,
    executionCount,
    contexts,
    signerPublicKey: signer.publicKey,
  }

  function applyIntent(actor: string, chain: string[], nonce: string, amount: number) {
    const signerForActor = actor === agentA.id ? agentA : agentB
    return signIntent(
      {
        intent_id: `int_${nonce}`,
        actor,
        delegation_chain: chain,
        action: 'apply',
        target: 'resource/example',
        parameters: { amount },
        nonce,
        issued_at: issued,
        expires_at: actor === agentA.id ? parentExpiry : childExpiry,
      },
      signerForActor
    )
  }

  function run(intent: ReturnType<typeof signIntent>, chain: SignedDelegation[]) {
    return runAuthorityPath({
      chain,
      intent,
      directory,
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      now,
      ledger,
      signer,
    })
  }
}
