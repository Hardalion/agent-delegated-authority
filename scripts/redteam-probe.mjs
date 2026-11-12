/**
 * Independent red-team probes. Not part of the product suite.
 * Imports the built reference implementation and prints PASS/FAIL per attack.
 */
import {
  createIdentity,
  signDelegation,
  signIntent,
  signApproval,
  unsignedDelegation,
} from '../packages/aap/dist/protocol.js'
import { sha256 } from '../packages/aap/dist/crypto.js'
import { NonceLedger } from '../packages/aap/dist/nonce.js'
import { PendingAuthorizationStore } from '../packages/aap/dist/pending.js'
import { ImmutablePolicyResolver } from '../packages/aap/dist/policy-resolver.js'
import { runAuthorityPath } from '../packages/aap/dist/path.js'
import { FixedClock } from '../packages/aap/dist/clock.js'
import { BASIC_AGENT_AUTHORITY, BASIC_AGENT_AUTHORITY_URI } from '../packages/aap/dist/example-policy.js'
import { evaluateToolCall } from '../packages/policy-engine/dist/index.js'
import { verifyAuthorizationReceipt, buildUnsignedAuthorizationReceipt, AUTHORIZATION_RECEIPT_KIND } from '../packages/audit-verify/dist/index.js'

const results = []
function record(id, severity, status, detail) {
  results.push({ id, severity, status, detail })
  console.log(`[${status}] ${id} (${severity}) ${detail}`)
}

const NOW = new Date('2026-10-06T18:00:00.000Z')
const ISSUED = NOW.toISOString()
const EXPIRES = new Date(NOW.getTime() + 15 * 60 * 1000).toISOString()

const ALLOW_APPLY = {
  version: '1.0.0',
  policyName: 'allow-apply',
  targetAgents: ['*'],
  defaultAction: 'BLOCK',
  rules: [{ ruleId: 'allow_apply', action: 'ALLOW', condition: "tool.name == 'apply'", alertSeverity: 'LOW' }],
}

function world(max = 500) {
  const principal = createIdentity('prn_example')
  const agent = createIdentity('agt_personal')
  const signer = createIdentity('reference-runtime')
  const directory = new Map([
    [principal.id, principal.publicKey],
    [agent.id, agent.publicKey],
  ])
  const root = signDelegation(
    {
      delegation_id: 'del_root',
      issuer: principal.id,
      subject: agent.id,
      capabilities: [{ action: 'apply', target: 'resource/example', delegable: false }],
      constraints: { max_amount: max },
      issued_at: ISSUED,
      expires_at: EXPIRES,
    },
    principal
  )
  return { principal, agent, signer, directory, root }
}

function baseIntent(agent, root, parameters, nonce = 'n-probe') {
  return {
    intent_id: `int_${nonce}`,
    actor: agent.id,
    delegation_chain: [root.delegation_id],
    action: 'apply',
    target: 'resource/example',
    parameters,
    nonce,
    issued_at: ISSUED,
    expires_at: EXPIRES,
  }
}

async function authorize(input) {
  const policyResolver = input.policyResolver ?? new ImmutablePolicyResolver()
  if (!input.policyResolver) policyResolver.register(input.policy, input.policyUri)
  return runAuthorityPath({ ...input, policyResolver })
}

// RT-01 nested mutation during the executor yield.
// The original PoC mutated meta.dest after authorization and before the executor read it.
// The barrier replaces the previous 10ms sleep so the yield is deterministic.
{
  const { agent, signer, directory, root } = world(500)
  const meta = { dest: 'legit' }
  const intent = signIntent(baseIntent(agent, root, { amount: 10, meta }, 'rt01'), agent)
  let observed = null
  let release
  let signalWaiting
  const hold = new Promise((resolve) => {
    release = resolve
  })
  const waiting = new Promise((resolve) => {
    signalWaiting = resolve
  })
  const pending = authorize({
    chain: [root],
    intent,
    directory,
    trustedRootIssuers: [principal.id],
    policy: ALLOW_APPLY,
    policyUri: 'allow-apply@1.0.0',
    clock: new FixedClock(NOW),
    ledger: new NonceLedger(),
    signer,
    execute: async (ctx) => {
      signalWaiting()
      await hold
      observed = ctx.parameters.meta.dest
      return { dest: observed }
    },
  })
  await waiting
  meta.dest = 'evil'
  release()
  const result = await pending
  const receiptDest = result.receipt?.intent?.argsRedacted?.meta?.dest
  const held =
    result.decision === 'ALLOW' &&
    result.executed === true &&
    observed === 'legit' &&
    receiptDest === 'legit'
  record(
    'RT-01',
    'high',
    observed === 'evil' ? 'REGRESSED' : held ? 'REMEDIATED' : 'FAILED',
    `observed=${observed} receiptDest=${receiptDest} decision=${result.decision} executed=${result.executed} authenticated=${result.authenticated}`
  )
}

// RT-02 getter flips after hash re-check
{
  const { agent, signer, directory, root } = world(500)
  let reads = 0
  const parameters = {}
  Object.defineProperty(parameters, 'amount', {
    enumerable: true,
    get() {
      reads += 1
      return reads < 4 ? 10 : 499
    },
  })
  const intent = signIntent(baseIntent(agent, root, parameters, 'rt02'), agent)
  let observed = null
  try {
    const result = await authorize({
      chain: [root],
      intent,
      directory,
      trustedRootIssuers: [principal.id],
      policy: ALLOW_APPLY,
      policyUri: 'allow-apply@1.0.0',
      clock: new FixedClock(NOW),
      ledger: new NonceLedger(),
      signer,
      execute: (ctx) => {
        observed = ctx.parameters.amount
        return { amount: observed }
      },
    })
    record(
      'RT-02',
      'high',
      observed !== 10 && result.executed ? 'CONFIRMED' : 'NOT_REPRO',
      `reads=${reads} observed=${observed} decision=${result.decision} executed=${result.executed}`
    )
  } catch (error) {
    record('RT-02', 'high', 'ERROR', `${error.name}: ${error.message} reads=${reads}`)
  }
}

// RT-03 nonce griefing before signature check
{
  const { agent, signer, directory, root } = world(800)
  const good = signIntent(baseIntent(agent, root, { amount: 10, note: 'example' }, 'rt03'), agent)
  const forged = { ...good, parameters: { amount: -1, note: 'example' }, signature: 'not-a-signature' }
  const ledger = new NonceLedger()
  const first = await authorize({
    chain: [root],
    intent: forged,
    directory,
    trustedRootIssuers: [principal.id],
    policy: BASIC_AGENT_AUTHORITY,
    policyUri: BASIC_AGENT_AUTHORITY_URI,
    clock: new FixedClock(NOW),
    ledger,
    pendingStore: new PendingAuthorizationStore(),
    signer,
    execute: () => ({ ok: true }),
  })
  const second = await authorize({
    chain: [root],
    intent: good,
    directory,
    trustedRootIssuers: [principal.id],
    policy: BASIC_AGENT_AUTHORITY,
    policyUri: BASIC_AGENT_AUTHORITY_URI,
    clock: new FixedClock(NOW),
    ledger,
    pendingStore: new PendingAuthorizationStore(),
    signer,
    execute: () => ({ ok: true }),
  })
  const held =
    first.authenticated === false &&
    first.receipt == null &&
    first.executed === false &&
    second.decision === 'REQUIRE_HUMAN' &&
    second.ruleId !== 'replay' &&
    second.authenticated === true
  record(
    'RT-03',
    'medium',
    second.ruleId === 'replay' ? 'REGRESSED' : held ? 'REMEDIATED' : 'FAILED',
    `forged authenticated=${first.authenticated} receipt=${first.receipt == null ? 'absent' : 'present'} ${first.decision}/${first.ruleId} (${first.reason}); legit follow-up=${second.decision}/${second.ruleId} (${second.reason})`
  )
}

// RT-04 NaN, Infinity, and a cycle must not escape the authority boundary.
{
  const { agent, signer, directory, root } = world(800)
  const good = signIntent(baseIntent(agent, root, { amount: 10 }, 'rt04'), agent)
  const cases = [
    ['NaN', { ...good, parameters: { amount: Number.NaN } }],
    ['+Infinity', { ...good, parameters: { amount: Number.POSITIVE_INFINITY } }],
    ['-Infinity', { ...good, parameters: { amount: Number.NEGATIVE_INFINITY } }],
  ]
  const cycle = { amount: 10 }
  cycle.self = cycle
  cases.push(['cycle', { ...good, parameters: cycle }])
  for (const [label, forged] of cases) {
    let threw = false
    let result
    let calls = 0
    try {
      result = await authorize({
        chain: [root],
        intent: forged,
        directory,
        trustedRootIssuers: [principal.id],
        policy: BASIC_AGENT_AUTHORITY,
        policyUri: BASIC_AGENT_AUTHORITY_URI,
        clock: new FixedClock(NOW),
        ledger: new NonceLedger(),
        signer,
        execute: () => {
          calls += 1
          return { ok: true }
        },
      })
    } catch (error) {
      threw = true
      result = { decision: 'THREW', reason: error instanceof Error ? error.message : String(error) }
    }
    const held =
      !threw &&
      result.decision === 'BLOCK' &&
      result.executed === false &&
      result.authenticated === false &&
      result.receipt == null &&
      calls === 0
    record(
      'RT-04',
      'medium',
      threw ? 'REGRESSED' : held ? 'REMEDIATED' : 'FAILED',
      `${label} threw=${threw} decision=${result.decision} authenticated=${result.authenticated} receipt=${result.receipt == null ? 'absent' : 'present'} executed=${result.executed} calls=${calls} reason=${result.reason}`
    )
  }
}

// RT-05 policy substitution without approval (original ADAP-001)
{
  const { agent, signer, directory, root } = world(800)
  const intent = signIntent(baseIntent(agent, root, { amount: 420, note: 'example' }, 'rt05'), agent)
  const ledger = new NonceLedger()
  const pendingStore = new PendingAuthorizationStore()
  const resolver = new ImmutablePolicyResolver()
  resolver.register(BASIC_AGENT_AUTHORITY, BASIC_AGENT_AUTHORITY_URI)
  let exec = 0
  const pending = await authorize({
    chain: [root],
    intent,
    directory,
    trustedRootIssuers: [principal.id],
    policy: BASIC_AGENT_AUTHORITY,
    policyUri: BASIC_AGENT_AUTHORITY_URI,
    clock: new FixedClock(NOW),
    ledger,
    pendingStore,
    policyResolver: resolver,
    signer,
    execute: () => {
      exec += 1
      return { ok: 1 }
    },
  })
  const sub = await authorize({
    chain: [root],
    intent,
    directory,
    trustedRootIssuers: [principal.id],
    policy: ALLOW_APPLY,
    policyUri: BASIC_AGENT_AUTHORITY_URI,
    clock: new FixedClock(NOW),
    ledger,
    pendingStore,
    policyResolver: resolver,
    signer,
    execute: () => {
      exec += 1
      return { ok: 1 }
    },
  })
  record(
    'RT-05',
    'high',
    pending.decision === 'REQUIRE_HUMAN' && sub.decision === 'BLOCK' && exec === 0 ? 'FIXED' : 'CONFIRMED',
    `pending=${pending.decision} sub=${sub.decision}/${sub.reason} exec=${exec}`
  )
}

// RT-06 caller clock must not revive an expired intent
{
  const { agent, signer, directory, root } = world(500)
  const expiredNow = new Date(Date.parse(EXPIRES) + 60_000)
  const blocked = await authorize({
    chain: [root],
    intent: signIntent(baseIntent(agent, root, { amount: 10 }, 'rt06-expired'), agent),
    directory,
    trustedRootIssuers: [principal.id],
    policy: ALLOW_APPLY,
    policyUri: 'allow-apply@1.0.0',
    clock: new FixedClock(expiredNow),
    ledger: new NonceLedger(),
    signer,
    execute: () => ({ ok: true }),
  })
  const revived = await authorize({
    chain: [root],
    intent: signIntent(baseIntent(agent, root, { amount: 10 }, 'rt06-caller'), agent),
    directory,
    trustedRootIssuers: [principal.id],
    policy: ALLOW_APPLY,
    policyUri: 'allow-apply@1.0.0',
    now: NOW,
    clock: new FixedClock(expiredNow),
    ledger: new NonceLedger(),
    signer,
    execute: () => ({ ok: true }),
  })
  const trusted = await authorize({
    chain: [root],
    intent: signIntent(baseIntent(agent, root, { amount: 10 }, 'rt06-trusted'), agent),
    directory,
    trustedRootIssuers: [principal.id],
    policy: ALLOW_APPLY,
    policyUri: 'allow-apply@1.0.0',
    clock: new FixedClock(NOW),
    ledger: new NonceLedger(),
    signer,
    execute: () => ({ ok: true }),
  })
  const held =
    blocked.decision === 'BLOCK' &&
    blocked.executed === false &&
    revived.executed === false &&
    revived.ruleId === 'clock' &&
    trusted.executed === true &&
    trusted.decision === 'ALLOW'
  record(
    'RT-06',
    'medium',
    held ? 'REMEDIATED' : revived.executed ? 'REGRESSED' : 'FAILED',
    `expired=${blocked.decision}/${blocked.ruleId}; caller-now executed=${revived.executed} rule=${revived.ruleId}; trusted executed=${trusted.executed}`
  )
}

// RT-07 object nonce
{
  const ledger = new NonceLedger()
  let rejected = false
  try {
    ledger.claimForExecution({ n: 'x' }, 'h')
  } catch {
    rejected = true
  }
  record('RT-07', 'high', rejected ? 'FIXED' : 'CONFIRMED', `object nonce rejected=${rejected}`)
}

// RT-08 omitted or unknown agentRole must not match
{
  const scoped = {
    version: '1',
    policyName: 'scoped-role',
    targetAgents: ['agt_only'],
    defaultAction: 'BLOCK',
    rules: [{ ruleId: 'r', action: 'ALLOW', condition: "tool.name == 'apply'", alertSeverity: 'LOW' }],
  }
  const cases = [
    ['omitted', undefined],
    ['empty', ''],
    ['null', null],
    ['unknown', 'agt_other'],
  ]
  const decisions = cases.map(([label, agentRole]) => {
    const decision = evaluateToolCall({ policy: scoped, toolName: 'apply', agentRole })
    return `${label}=${decision.action}/${decision.ruleId}`
  })
  const wildcard = evaluateToolCall({
    policy: { ...scoped, targetAgents: ['*'], defaultAction: 'ALLOW' },
    toolName: 'apply',
  })
  const legit = evaluateToolCall({ policy: scoped, toolName: 'apply', agentRole: 'agt_only' })
  const closed = decisions.every((line) => line.includes('BLOCK/agent_not_in_scope')) && wildcard.action === 'BLOCK'
  const held = closed && legit.action === 'ALLOW'
  record(
    'RT-08',
    'low',
    held ? 'REMEDIATED' : decisions.some((line) => line.endsWith('ALLOW/r')) || wildcard.action === 'ALLOW' ? 'REGRESSED' : 'FAILED',
    `${decisions.join(' ')}; wildcard=${wildcard.action}/${wildcard.ruleId}; legit=${legit.action}`
  )
}

// RT-09 contradictory receipt
{
  const forged = {
    v: 1,
    kind: 'adap.receipt',
    receiptId: 'r1',
    issuer: 'x',
    issuerKeyId: 'ed25519:deadbeefdeadbeefdeadbeefdeadbeef',
    decidedAt: '2026-10-06T18:00:00.000Z',
    intent: { toolName: 'apply', argsHash: 'a'.repeat(64) },
    identity: { agentId: 'agt', actorType: 'non_human_agent' },
    policy: {
      policyUri: 'p@1',
      policyName: 'basic-agent-authority',
      policyVersion: '1',
      ruleId: 'r',
      contentHash: 'b'.repeat(64),
    },
    decision: {
      action: 'BLOCK',
      outcome: 'allowed',
      reason: 'contradiction',
      alertSeverity: 'CRITICAL',
      matched: true,
    },
    integrity: { contentHash: 'c'.repeat(64) },
    signature: 'ab'.repeat(64),
    execution: { intentHash: 'd'.repeat(64), executed: true },
  }
  const result = verifyAuthorizationReceipt(forged)
  record(
    'RT-09',
    'medium',
    result.structureOk ? 'CONFIRMED' : 'FIXED',
    `structureOk=${result.structureOk} errors=${result.errors.slice(0, 2).join(' | ')}`
  )
}

// RT-10 dot-segment target under wildcard
{
  const principal = createIdentity('prn_example')
  const agent = createIdentity('agt_personal')
  const signer = createIdentity('reference-runtime')
  const directory = new Map([
    [principal.id, principal.publicKey],
    [agent.id, agent.publicKey],
  ])
  const root = signDelegation(
    {
      delegation_id: 'del_root',
      issuer: principal.id,
      subject: agent.id,
      capabilities: [{ action: 'apply', target: 'resource/*' }],
      constraints: { max_amount: 500 },
      issued_at: ISSUED,
      expires_at: EXPIRES,
    },
    principal
  )
  const intent = signIntent(
    {
      ...baseIntent(agent, root, { amount: 10 }, 'rt10'),
      target: 'resource/./vault',
    },
    agent
  )
  let executedTarget = null
  const result = await authorize({
    chain: [root],
    intent,
    directory,
    trustedRootIssuers: [principal.id],
    policy: ALLOW_APPLY,
    policyUri: 'allow-apply@1.0.0',
    clock: new FixedClock(NOW),
    ledger: new NonceLedger(),
    signer,
    execute: (ctx) => {
      executedTarget = ctx.target
      return { ok: true }
    },
  })
  record(
    'RT-10',
    'low',
    result.executed ? 'CONDITIONAL' : 'FIXED',
    `target resource/./vault decision=${result.decision} reason=${result.reason} executedTarget=${executedTarget}`
  )
}

// RT-11 failed execution then same nonce
{
  const { agent, signer, directory, root } = world(500)
  const intent = signIntent(baseIntent(agent, root, { amount: 10 }, 'rt11'), agent)
  const ledger = new NonceLedger()
  let calls = 0
  const first = await authorize({
    chain: [root],
    intent,
    directory,
    trustedRootIssuers: [principal.id],
    policy: ALLOW_APPLY,
    policyUri: 'allow-apply@1.0.0',
    clock: new FixedClock(NOW),
    ledger,
    signer,
    execute: () => {
      calls += 1
      throw new Error('downstream')
    },
  })
  const second = await authorize({
    chain: [root],
    intent,
    directory,
    trustedRootIssuers: [principal.id],
    policy: ALLOW_APPLY,
    policyUri: 'allow-apply@1.0.0',
    clock: new FixedClock(NOW),
    ledger,
    signer,
    execute: () => {
      calls += 1
      return { ok: true }
    },
  })
  record(
    'RT-11',
    'medium',
    first.executed === false && second.decision === 'BLOCK' && calls === 1 ? 'FIXED' : 'CONFIRMED',
    `first=${first.decision}/${first.executed} second=${second.decision}/${second.reason} calls=${calls}`
  )
}

// RT-12 approval replay onto a different intent hash with a fresh nonce
{
  const { principal, agent, signer, directory, root } = world(800)
  const ledger = new NonceLedger()
  const pendingStore = new PendingAuthorizationStore()
  const resolver = new ImmutablePolicyResolver()
  resolver.register(BASIC_AGENT_AUTHORITY, BASIC_AGENT_AUTHORITY_URI)
  const intent = signIntent(baseIntent(agent, root, { amount: 420, note: 'example' }, 'rt12a'), agent)
  const pending = await authorize({
    chain: [root],
    intent,
    directory,
    trustedRootIssuers: [principal.id],
    policy: BASIC_AGENT_AUTHORITY,
    policyUri: BASIC_AGENT_AUTHORITY_URI,
    clock: new FixedClock(NOW),
    ledger,
    pendingStore,
    policyResolver: resolver,
    signer,
  })
  const approval = signApproval(
    {
      intent_hash: pending.intentHash,
      approver_id: principal.id,
      approved_at: ISSUED,
      decision: 'APPROVE',
      agent_id: agent.id,
      delegation_chain_hash: sha256([unsignedDelegation(root)]),
      policy_content_hash: pending.policyHash,
      matched_rule_id: pending.ruleId,
    },
    principal
  )
  const other = signIntent(baseIntent(agent, root, { amount: 100, note: 'example' }, 'rt12b'), agent)
  let exec = 0
  const replay = await authorize({
    chain: [root],
    intent: other,
    directory,
    trustedRootIssuers: [principal.id],
    policy: BASIC_AGENT_AUTHORITY,
    policyUri: BASIC_AGENT_AUTHORITY_URI,
    clock: new FixedClock(NOW),
    ledger,
    pendingStore,
    policyResolver: resolver,
    signer,
    approval,
    execute: () => {
      exec += 1
      return { ok: 1 }
    },
  })
  record(
    'RT-12',
    'high',
    replay.executed || exec > 0 ? 'CONFIRMED' : 'FIXED',
    `replay decision=${replay.decision} rule=${replay.ruleId} reason=${replay.reason} exec=${exec}`
  )
}

void AUTHORIZATION_RECEIPT_KIND
void buildUnsignedAuthorizationReceipt

console.log('\n=== REDTEAM SUMMARY ===')
for (const row of results) console.log(`${row.status}\t${row.severity}\t${row.id}\t${row.detail}`)
