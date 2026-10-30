import { describe, expect, it } from 'vitest'
import { BASIC_AGENT_AUTHORITY, BASIC_AGENT_AUTHORITY_URI } from './example-policy.js'
import { NonceLedger } from './nonce.js'
import { runAuthorityPath, type ExecutionContext } from './path.js'
import {
  createIdentity,
  signApproval,
  signDelegation,
  signIntent,
  type SignedIntent,
} from './protocol.js'

const NOW = new Date('2026-10-06T18:00:00.000Z')
const ISSUED = NOW.toISOString()
const EXPIRES = new Date(NOW.getTime() + 15 * 60 * 1000).toISOString()

function harness(maxAmount: number) {
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
      constraints: { max_amount: maxAmount },
      issued_at: ISSUED,
      expires_at: EXPIRES,
    },
    principal
  )
  let executions = 0
  const contexts: ExecutionContext[] = []

  async function apply(amount: number, nonce: string, approval = false) {
    const intent: SignedIntent = signIntent(
      {
        intent_id: `int_${nonce}`,
        actor: personal.id,
        delegation_chain: [root.delegation_id],
        action: 'apply',
        target: 'resource/example',
        parameters: { amount, note: 'example' },
        nonce,
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      personal
    )
    const pending = await runAuthorityPath({
      chain: [root],
      intent,
      directory,
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      now: NOW,
      ledger: new NonceLedger(),
      signer,
      execute: (ctx) => {
        executions += 1
        contexts.push(ctx)
        return { ok: true }
      },
    })
    if (!approval) return pending
    return runAuthorityPath({
      chain: [root],
      intent,
      directory,
      policy: BASIC_AGENT_AUTHORITY,
      policyUri: BASIC_AGENT_AUTHORITY_URI,
      now: NOW,
      ledger: new NonceLedger(),
      signer,
      approval: signApproval(
        {
          intent_hash: pending.intentHash,
          approver_id: principal.id,
          approved_at: ISSUED,
          decision: 'APPROVE',
        },
        principal
      ),
      execute: (ctx) => {
        executions += 1
        contexts.push(ctx)
        return { ok: true }
      },
    })
  }

  return { apply, executions: () => executions, contexts }
}

describe('authority then policy', () => {
  it('blocks an amount the delegation allows when the policy caps it, and approval cannot override the block', async () => {
    const gate = harness(800)
    const blocked = await gate.apply(610, 'nonce-block', true)
    expect(blocked.decision).toBe('BLOCK')
    expect(blocked.ruleId).toBe('block_over_cap')
    expect(blocked.executed).toBe(false)
    expect(gate.executions()).toBe(0)
    expect(blocked.receipt.execution?.executed).toBe(false)
  })
})

describe('exclusive nonce claim before execution', () => {
  it('lets only one concurrent ALLOW with the same signed intent reach the executor', async () => {
    const principal = createIdentity('prn_example')
    const agent = createIdentity('agt_reader')
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
        capabilities: [{ action: 'read', target: 'resource/*' }],
        constraints: { max_amount: 500 },
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      principal
    )
    const intent = signIntent(
      {
        intent_id: 'int_concurrent',
        actor: agent.id,
        delegation_chain: [root.delegation_id],
        action: 'read',
        target: 'resource/example',
        parameters: {},
        nonce: 'nonce-concurrent',
        issued_at: ISSUED,
        expires_at: EXPIRES,
      },
      agent
    )
    const ledger = new NonceLedger()
    let releaseFirst!: () => void
    const hold = new Promise<void>((resolve) => {
      releaseFirst = resolve
    })
    let signalClaimed!: () => void
    const claimed = new Promise<void>((resolve) => {
      signalClaimed = resolve
    })
    let executions = 0

    const run = () =>
      runAuthorityPath({
        chain: [root],
        intent,
        directory,
        policy: BASIC_AGENT_AUTHORITY,
        policyUri: BASIC_AGENT_AUTHORITY_URI,
        now: NOW,
        ledger,
        signer,
        execute: async () => {
          executions += 1
          // claimForExecution already ran; now it is safe to start the racing caller.
          signalClaimed()
          await hold
          return { ok: true }
        },
      })

    const firstPromise = run()
    await claimed
    const second = await run()
    releaseFirst()
    const first = await firstPromise

    expect(first.decision).toBe('ALLOW')
    expect(first.executed).toBe(true)
    expect(second.decision).toBe('BLOCK')
    expect(second.reason).toBe('nonce_in_flight_or_used')
    expect(second.executed).toBe(false)
    expect(executions).toBe(1)
  })
})
