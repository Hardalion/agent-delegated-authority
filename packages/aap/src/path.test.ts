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
