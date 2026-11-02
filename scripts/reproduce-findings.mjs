/**
 * One-shot reproduction of ADAP-001..011 against the local build.
 * Not a permanent test — deleted or kept as a diagnostic helper.
 */
import { createIdentity, signDelegation, signIntent } from '../packages/aap/dist/protocol.js'
import { FixedClock } from '../packages/aap/dist/clock.js'
import { NonceLedger } from '../packages/aap/dist/nonce.js'
import { PendingAuthorizationStore } from '../packages/aap/dist/pending.js'
import { ImmutablePolicyResolver } from '../packages/aap/dist/policy-resolver.js'
import { runAuthorityPath } from '../packages/aap/dist/path.js'
import { BASIC_AGENT_AUTHORITY, BASIC_AGENT_AUTHORITY_URI } from '../packages/aap/dist/example-policy.js'
import { canonicalJson } from '../packages/aap/dist/crypto.js'
import { assertIntentWithinDelegation, validateDelegationNarrowing } from '../packages/aap/dist/validate.js'
import { evaluateToolCall } from '../packages/policy-engine/dist/index.js'
import { verifyAuthorizationReceipt } from '../packages/audit-verify/dist/index.js'

const findings = []
function note(id, status, detail) {
  findings.push({ id, status, detail })
  console.log(`[${status}] ${id}: ${detail}`)
}

const NOW = new Date('2026-10-06T18:00:00.000Z')
const ISSUED = NOW.toISOString()
const EXPIRES = new Date(NOW.getTime() + 15 * 60 * 1000).toISOString()
const principal = createIdentity('prn_example')
const personal = createIdentity('agt_personal')
const signer = createIdentity('reference-runtime')
const directory = new Map([
  [principal.id, principal.publicKey],
  [personal.id, personal.publicKey],
])
const root = signDelegation(
  {
    delegation_id: 'del_root',
    issuer: principal.id,
    subject: personal.id,
    capabilities: [{ action: 'apply', target: 'resource/*', delegable: false }],
    constraints: { max_amount: 800 },
    issued_at: ISSUED,
    expires_at: EXPIRES,
  },
  principal
)
const intent = signIntent(
  {
    intent_id: 'int_x',
    actor: personal.id,
    delegation_chain: ['del_root'],
    action: 'apply',
    target: 'resource/example',
    parameters: { amount: 420, note: 'example' },
    nonce: 'n1',
    issued_at: ISSUED,
    expires_at: EXPIRES,
  },
  personal
)

// ADAP-001
{
  const ledger = new NonceLedger()
  const pendingStore = new PendingAuthorizationStore()
  const policyResolver = new ImmutablePolicyResolver()
  policyResolver.register(BASIC_AGENT_AUTHORITY, BASIC_AGENT_AUTHORITY_URI)
  let exec = 0
  const pending = await runAuthorityPath({
    chain: [root],
    intent,
    directory,
    policy: BASIC_AGENT_AUTHORITY,
    policyUri: BASIC_AGENT_AUTHORITY_URI,
    clock: new FixedClock(NOW),
    ledger,
    pendingStore,
    policyResolver,
    signer,
    execute: () => {
      exec += 1
      return { ok: 1 }
    },
  })
  const permissive = {
    version: '1.0.0',
    policyName: 'basic-agent-authority',
    description: 'substituted',
    targetAgents: ['*'],
    defaultAction: 'ALLOW',
    rules: [
      {
        ruleId: 'allow_all',
        action: 'ALLOW',
        condition: "tool.name == 'apply'",
        alertSeverity: 'LOW',
      },
    ],
  }
  const sub = await runAuthorityPath({
    chain: [root],
    intent,
    directory,
    policy: permissive,
    policyUri: BASIC_AGENT_AUTHORITY_URI,
    clock: new FixedClock(NOW),
    ledger,
    pendingStore,
    policyResolver,
    signer,
    execute: () => {
      exec += 1
      return { ok: 1 }
    },
  })
  if (pending.decision === 'REQUIRE_HUMAN' && sub.decision === 'ALLOW' && sub.executed && exec > 0) {
    note('ADAP-001', 'VULNERABLE', `policy substitution executed without approval (exec=${exec})`)
  } else {
    note(
      'ADAP-001',
      'FIXED',
      `pending=${pending.decision} sub=${sub.decision} exec=${exec} (substitution without approval blocked)`
    )
  }
}

// ADAP-002
{
  const ledger = new NonceLedger()
  const n1 = { value: 'same-nonce' }
  const n2 = JSON.parse(JSON.stringify(n1))
  let bypass = false
  try {
    ledger.claimForExecution(/** @type {any} */ (n1), 'hash')
    ledger.consume(/** @type {any} */ (n1), 'hash')
    ledger.claimForExecution(/** @type {any} */ (n2), 'hash')
    bypass = true
  } catch {
    bypass = false
  }
  note('ADAP-002', bypass ? 'VULNERABLE' : 'FIXED', bypass ? 'object nonce replay across JSON parse' : 'object nonce rejected')
}

// ADAP-003
{
  let nanBypass = false
  let infBypass = false
  try {
    assertIntentWithinDelegation(
      {
        intent_id: 'i',
        actor: personal.id,
        delegation_chain: ['del_root'],
        action: 'apply',
        target: 'resource/example',
        parameters: { amount: Number.NaN },
        nonce: 'n',
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      root
    )
    nanBypass = true
  } catch {
    /* rejected */
  }
  try {
    assertIntentWithinDelegation(
      {
        intent_id: 'i',
        actor: personal.id,
        delegation_chain: ['del_root'],
        action: 'apply',
        target: 'resource/example',
        parameters: { amount: Number.NEGATIVE_INFINITY },
        nonce: 'n',
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      root
    )
    infBypass = true
  } catch {
    /* rejected */
  }
  note(
    'ADAP-003',
    nanBypass || infBypass ? 'VULNERABLE' : 'FIXED',
    `NaN bypass=${nanBypass} -Infinity bypass=${infBypass}`
  )
}

// ADAP-004
{
  const raw = JSON.parse('{"b":1,"__proto__":{"polluted":true}}')
  let rejected = false
  try {
    canonicalJson(raw)
  } catch {
    rejected = true
  }
  note(
    'ADAP-004',
    rejected ? 'FIXED' : 'VULNERABLE',
    rejected ? 'dangerous __proto__ key rejected by canonicalJson' : 'canonicalJson accepted __proto__'
  )
}

// ADAP-005
{
  const parentConstraints = { max_amount: 100, currency: 'EUR' }
  const childConstraints = Object.create(parentConstraints)
  childConstraints.max_amount = 100
  const parent = {
    ...root,
    capabilities: [{ action: 'apply', target: 'resource/*', delegable: true }],
    constraints: parentConstraints,
  }
  const child = {
    ...root,
    delegation_id: 'del_c',
    issuer: personal.id,
    subject: 'agt_b',
    parent_delegation_id: 'del_root',
    capabilities: [{ action: 'apply', target: 'resource/example' }],
    constraints: childConstraints,
  }
  try {
    validateDelegationNarrowing(parent, child)
    note('ADAP-005', 'VULNERABLE', 'prototype-bearing child constraints accepted')
  } catch (e) {
    note('ADAP-005', 'FIXED', String(e.message))
  }
}

// ADAP-006
{
  const d = evaluateToolCall({
    policy: {
      version: '1',
      policyName: 'basic-agent-authority',
      targetAgents: ['agt_a'],
      rules: [{ ruleId: 'r', action: 'ALLOW', condition: "tool.name == 'read'", alertSeverity: 'LOW' }],
    },
    toolName: 'read',
    agentRole: '',
  })
  note(
    'ADAP-006',
    d.action === 'ALLOW' ? 'VULNERABLE' : 'FIXED',
    `empty agentRole → ${d.action} (${d.ruleId})`
  )
}

// ADAP-011
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
  note(
    'ADAP-011',
    result.structureOk !== false && !result.errors.some((e) => /outcome|execut|inconsistent/i.test(e))
      ? 'VULNERABLE'
      : 'FIXED',
    `structureOk=${result.structureOk} errors=${result.errors.join('; ') || 'none'}`
  )
}

console.log('\n=== SUMMARY ===')
for (const f of findings) console.log(`${f.id}\t${f.status}\t${f.detail}`)
