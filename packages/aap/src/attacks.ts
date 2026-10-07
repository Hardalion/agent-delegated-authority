import type { Policy } from 'adap-policy'
import { sha256, importPublicKey } from './crypto.js'
import { INJECTION_NOTE } from './launch-proof.js'
import { NonceLedger } from './nonce.js'
import { verifyProtocolReceipt, runAuthorityPath, type ProtocolResult } from './path.js'
import {
  createIdentity,
  signApproval,
  signDelegation,
  signIntent,
  type Identity,
  type SignedDelegation,
  type SignedIntent,
} from './protocol.js'
import { DEMO_NOW } from './agents.js'

const POLICY_URI = 'book-flight@1.0.0'

const POLICY: Policy = {
  version: '1.0.0',
  policyName: 'book-flight',
  description: 'Synthetic. purchase waits for a person. Search is allowed. The bound is the delegation.',
  targetAgents: ['*'],
  defaultAction: 'BLOCK',
  rules: [
    {
      ruleId: 'block_over_cap',
      action: 'BLOCK',
      condition: "tool.name == 'purchase' && args.amount > 500",
      alertSeverity: 'CRITICAL',
    },
    {
      ruleId: 'purchase_needs_human',
      action: 'REQUIRE_HUMAN',
      condition: "tool.name == 'purchase'",
      alertSeverity: 'MEDIUM',
    },
    {
      ruleId: 'search_allow',
      action: 'ALLOW',
      condition: "tool.name == 'search'",
      alertSeverity: 'LOW',
    },
  ],
}

export interface AttackCase {
  readonly id: string
  readonly number: string
  readonly title: string
  readonly narrative: readonly string[]
  readonly expected: string
  readonly decision: string
  readonly reason: string
  readonly executed: boolean
  readonly receiptVerified: boolean
  readonly executorCalls: number
  readonly policyHashMatches: boolean
  readonly intentHashMatches: boolean
  readonly closing?: string
}

export async function runAttacks(): Promise<readonly AttackCase[]> {
  return [
    await overDelegation(),
    await privilegeEscalation(),
    await promptInjection(),
    await replay(),
    await expiredDelegation(),
    await postApprovalMutation(),
  ]
}

export function formatAttack(attack: AttackCase): string {
  const lines = [
    `ATTACK #${attack.number}`,
    attack.title,
    '',
    ...attack.narrative,
    '',
    'EXPECTED',
    attack.expected,
    '',
    'ADAP DECISION',
    attack.decision,
    `reason: ${attack.reason}`,
    '',
    'EXECUTION',
    attack.executed ? 'CALLED' : 'NOT CALLED',
    '',
    'RECEIPT',
    attack.receiptVerified ? 'VERIFIED' : 'NOT VERIFIED',
  ]
  if (attack.closing) lines.push('', attack.closing)
  return lines.join('\n')
}

export function formatAttacks(attacks: readonly AttackCase[]): string {
  return attacks.map(formatAttack).join('\n\n')
}

function bounds(maxAmount: number) {
  return {
    max_amount: maxAmount,
    currency: 'EUR',
    purpose: 'book_flight',
    route: 'ATH-LON',
  }
}

function spend(amount: number, extra?: Readonly<Record<string, unknown>>) {
  return { amount, currency: 'EUR', purpose: 'book_flight', route: 'ATH-LON', ...extra }
}

function euro(amount: number): string {
  return `€${new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 }).format(amount)}`
}

interface Cast {
  readonly principal: Identity
  readonly agentA: Identity
  readonly agentB: Identity
  readonly signer: Identity
  readonly directory: Map<string, string>
  readonly issued: string
  readonly parentExpiry: string
  readonly childExpiry: string
}

function cast(): Cast {
  const principal = createIdentity('prn_alex')
  const agentA = createIdentity('agt_a')
  const agentB = createIdentity('agt_b')
  const signer = createIdentity('reference-runtime')
  return {
    principal,
    agentA,
    agentB,
    signer,
    directory: new Map([principal, agentA, agentB, signer].map((identity) => [identity.id, identity.publicKey])),
    issued: DEMO_NOW.toISOString(),
    parentExpiry: new Date(DEMO_NOW.getTime() + 15 * 60 * 1000).toISOString(),
    childExpiry: new Date(DEMO_NOW.getTime() + 10 * 60 * 1000).toISOString(),
  }
}

function rootGrant(actors: Cast, purchaseDelegable: boolean): SignedDelegation {
  return signDelegation(
    {
      delegation_id: 'del_root',
      issuer: actors.principal.id,
      subject: actors.agentA.id,
      capabilities: [
        { action: 'search', target: 'airline/*' },
        { action: 'purchase', target: 'airline/*', delegable: purchaseDelegable },
      ],
      constraints: bounds(500),
      issued_at: actors.issued,
      expires_at: actors.parentExpiry,
    },
    actors.principal
  )
}

function makeIntent(
  actor: Identity,
  chain: readonly string[],
  nonce: string,
  action: string,
  parameters: Readonly<Record<string, unknown>>,
  expiresAt: string,
  issued: string
): SignedIntent {
  return signIntent(
    {
      intent_id: `int_${nonce}`,
      actor: actor.id,
      delegation_chain: chain,
      action,
      target: 'airline/example',
      parameters,
      nonce,
      issued_at: issued,
      expires_at: expiresAt,
    },
    actor
  )
}

async function executeCase(input: {
  readonly actors: Cast
  readonly chain: readonly SignedDelegation[]
  readonly intent: SignedIntent
  readonly now?: Date
  readonly ledger?: NonceLedger
  readonly approval?: ReturnType<typeof signApproval>
  readonly execute: () => unknown
}): Promise<{ readonly result: ProtocolResult; readonly calls: number }> {
  let calls = 0
  const result = await runAuthorityPath({
    chain: input.chain,
    intent: input.intent,
    directory: input.actors.directory,
    policy: POLICY,
    policyUri: POLICY_URI,
    now: input.now ?? DEMO_NOW,
    ledger: input.ledger ?? new NonceLedger(),
    signer: input.actors.signer,
    approval: input.approval,
    execute: () => {
      calls += 1
      return input.execute()
    },
  })
  return { result, calls }
}

function settle(
  id: string,
  number: string,
  title: string,
  narrative: readonly string[],
  expected: string,
  result: ProtocolResult,
  actors: Cast,
  executorCalls: number,
  intent: SignedIntent,
  closing?: string
): AttackCase {
  const verified = verifyProtocolReceipt(result.receipt, importPublicKey(actors.signer.publicKey)).valid
  return {
    id,
    number,
    title,
    narrative,
    expected,
    decision: result.decision,
    reason: result.reason,
    executed: result.executed,
    receiptVerified: verified,
    executorCalls,
    policyHashMatches: result.receipt.policy.contentHash === sha256(POLICY),
    intentHashMatches: result.receipt.execution?.intentHash === sha256(unsignedIntentOf(intent)),
    closing,
  }
}

function unsignedIntentOf(intent: SignedIntent): Omit<SignedIntent, 'signature'> {
  const { signature: _signature, ...payload } = intent
  return payload
}

async function overDelegation(): Promise<AttackCase> {
  const actors = cast()
  const root = rootGrant(actors, false)
  const raised = signDelegation(
    {
      delegation_id: 'del_raised',
      issuer: actors.agentA.id,
      subject: actors.agentB.id,
      capabilities: [{ action: 'search', target: 'airline/example' }],
      constraints: bounds(1200),
      issued_at: actors.issued,
      expires_at: actors.childExpiry,
      parent_delegation_id: root.delegation_id,
    },
    actors.agentA
  )
  const intent = makeIntent(
    actors.agentB,
    [root.delegation_id, raised.delegation_id],
    'nonce_raised',
    'search',
    { currency: 'EUR', purpose: 'book_flight', route: 'ATH-LON' },
    actors.childExpiry,
    actors.issued
  )
  const { result, calls } = await executeCase({
    actors,
    chain: [root, raised],
    intent,
    execute: () => ({ unexpected: true }),
  })
  return settle(
    '01-over-delegation',
    '01',
    'OVER-DELEGATION',
    [
      `Parent authority: ${euro(500)}`,
      `Agent B requests: ${euro(1200)}`,
    ],
    'The child grant is rejected. The executor is not called.',
    result,
    actors,
    calls,
    intent
  )
}

async function privilegeEscalation(): Promise<AttackCase> {
  const actors = cast()
  const root = rootGrant(actors, false)
  const passed = signDelegation(
    {
      delegation_id: 'del_priv',
      issuer: actors.agentA.id,
      subject: actors.agentB.id,
      capabilities: [{ action: 'purchase', target: 'airline/example' }],
      constraints: bounds(500),
      issued_at: actors.issued,
      expires_at: actors.childExpiry,
      parent_delegation_id: root.delegation_id,
    },
    actors.agentA
  )
  const intent = makeIntent(
    actors.agentB,
    [root.delegation_id, passed.delegation_id],
    'nonce_priv',
    'purchase',
    spend(100),
    actors.childExpiry,
    actors.issued
  )
  const { result, calls } = await executeCase({
    actors,
    chain: [root, passed],
    intent,
    execute: () => ({ unexpected: true }),
  })
  return settle(
    '02-privilege-escalation',
    '02',
    'PRIVILEGE ESCALATION',
    [
      'purchase is delegable: false on the parent grant.',
      'Agent A tries to pass purchase to Agent B.',
    ],
    'A non-delegable capability cannot be passed on. The executor is not called.',
    result,
    actors,
    calls,
    intent
  )
}

async function promptInjection(): Promise<AttackCase> {
  const actors = cast()
  const root = rootGrant(actors, false)
  const intent = makeIntent(
    actors.agentA,
    [root.delegation_id],
    'nonce_injection',
    'purchase',
    spend(1000, { note: INJECTION_NOTE }),
    actors.parentExpiry,
    actors.issued
  )
  const { result, calls } = await executeCase({
    actors,
    chain: [root],
    intent,
    execute: () => ({ unexpected: true }),
  })
  return settle(
    '03-prompt-injection',
    '03',
    'PROMPT INJECTION',
    [
      'Agent receives:',
      `"${INJECTION_NOTE}"`,
      '',
      `Intent: purchase ${euro(1000)}`,
    ],
    'Free text is not a constraint. The delegated maximum still applies. The executor is not called.',
    result,
    actors,
    calls,
    intent,
    'The model is not the authority boundary.'
  )
}

async function replay(): Promise<AttackCase> {
  const actors = cast()
  const root = rootGrant(actors, false)
  const intent = makeIntent(
    actors.agentA,
    [root.delegation_id],
    'nonce_replay',
    'search',
    { currency: 'EUR', purpose: 'book_flight', route: 'ATH-LON' },
    actors.parentExpiry,
    actors.issued
  )
  const ledger = new NonceLedger()
  const first = await executeCase({
    actors,
    chain: [root],
    intent,
    ledger,
    execute: () => ({ ref: 'search-1' }),
  })
  const second = await executeCase({
    actors,
    chain: [root],
    intent,
    ledger,
    execute: () => ({ ref: 'search-2' }),
  })
  return settle(
    '04-replay',
    '04',
    'REPLAY',
    [
      'The same signed intent is presented again after the nonce was consumed.',
      `First decision: ${first.result.decision}. Second decision: ${second.result.decision}.`,
    ],
    'A consumed nonce cannot authorize the action again. The second attempt does not call the executor.',
    second.result,
    actors,
    first.calls + second.calls,
    intent
  )
}

async function expiredDelegation(): Promise<AttackCase> {
  const actors = cast()
  const root = rootGrant(actors, false)
  const intent = makeIntent(
    actors.agentA,
    [root.delegation_id],
    'nonce_expired',
    'search',
    { currency: 'EUR', purpose: 'book_flight', route: 'ATH-LON' },
    actors.parentExpiry,
    actors.issued
  )
  const after = new Date(Date.parse(actors.parentExpiry) + 1000)
  const { result, calls } = await executeCase({
    actors,
    chain: [root],
    intent,
    now: after,
    execute: () => ({ unexpected: true }),
  })
  return settle(
    '05-expired-delegation',
    '05',
    'EXPIRED DELEGATION',
    ['The same grant is presented after expires_at.'],
    'Expired authority is rejected. The executor is not called.',
    result,
    actors,
    calls,
    intent
  )
}

async function postApprovalMutation(): Promise<AttackCase> {
  const actors = cast()
  const root = rootGrant(actors, false)
  const original = makeIntent(
    actors.agentA,
    [root.delegation_id],
    'nonce_original',
    'purchase',
    spend(420),
    actors.parentExpiry,
    actors.issued
  )
  const pending = await executeCase({
    actors,
    chain: [root],
    intent: original,
    execute: () => ({ unexpected: true }),
  })
  const approval = signApproval(
    {
      intent_hash: pending.result.intentHash,
      approver_id: actors.principal.id,
      approved_at: actors.issued,
      decision: 'APPROVE',
    },
    actors.principal
  )
  const mutated = makeIntent(
    actors.agentA,
    [root.delegation_id],
    'nonce_mutated',
    'purchase',
    spend(480),
    actors.parentExpiry,
    actors.issued
  )
  const { result, calls } = await executeCase({
    actors,
    chain: [root],
    intent: mutated,
    approval,
    execute: () => ({ unexpected: true }),
  })
  return settle(
    '06-post-approval-mutation',
    '06',
    'POST-APPROVAL MUTATION',
    [
      `The principal approved purchase ${euro(420)}.`,
      `The intent then changes to purchase ${euro(480)} and presents that approval.`,
    ],
    'An approval is bound to one intent hash. A changed intent does not execute.',
    result,
    actors,
    pending.calls + calls,
    mutated
  )
}
