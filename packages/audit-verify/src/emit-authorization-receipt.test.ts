import { describe, expect, it } from 'vitest'
import { verifyAuthorizationReceipt, verifyReceiptChain, type AuthorizationReceiptV1 } from './authorization-receipt.js'
import { emitAuthorizationReceiptFromDecision, hashToolArgs } from './emit-authorization-receipt.js'

function chainOf(length: number): AuthorizationReceiptV1[] {
  const receipts: AuthorizationReceiptV1[] = []
  for (let sequence = 0; sequence < length; sequence += 1) {
    receipts.push(
      emitAuthorizationReceiptFromDecision({
        agentId: 'agt_example',
        toolName: 'read',
        toolArgs: { sequence },
        decision: { action: 'ALLOW', ruleId: 'read_allow', reason: 'read', alertSeverity: 'LOW', matched: true },
        policyUri: 'basic-agent-authority@1.0.0',
        policyName: 'basic-agent-authority',
        policyVersion: '1.0.0',
        policyContentHash: 'c'.repeat(64),
        intentHash: sequence.toString(16).padStart(64, '0'),
        receiptId: `rcpt_${sequence}`,
        sequence,
        prevReceiptHash: receipts[sequence - 1]?.integrity.contentHash ?? null,
      })
    )
  }
  return receipts
}

describe('verifyReceiptChain', () => {
  it('accepts an intact chain', () => {
    expect(verifyReceiptChain(chainOf(4))).toEqual({ valid: true, errors: [] })
  })

  it('detects an omitted receipt', () => {
    const [a, , c, d] = chainOf(4)
    const result = verifyReceiptChain([a!, c!, d!])
    expect(result.valid).toBe(false)
    expect(result.errors.join(' ')).toMatch(/does not link|sequence/)
  })

  it('detects reordering', () => {
    const [a, b, c] = chainOf(3)
    expect(verifyReceiptChain([a!, c!, b!]).valid).toBe(false)
  })

  it('detects a rewritten link', () => {
    const chain = chainOf(3)
    const forged = { ...chain[1]!, prevReceiptHash: 'f'.repeat(64) }
    expect(verifyReceiptChain([chain[0]!, forged, chain[2]!]).valid).toBe(false)
  })

  it('does not detect a dropped tail on its own', () => {
    expect(verifyReceiptChain(chainOf(4).slice(0, 2)).valid).toBe(true)
  })
})

describe('emitAuthorizationReceipt', () => {
  it('emits a verifiable REQUIRE_HUMAN receipt for apply', () => {
    const receipt = emitAuthorizationReceiptFromDecision({
      agentId: 'agt_example',
      toolName: 'apply',
      toolArgs: { amount: 420 },
      decision: {
        action: 'REQUIRE_HUMAN',
        ruleId: 'apply_needs_human',
        reason: 'A person must approve this action',
        alertSeverity: 'MEDIUM',
        matched: true,
      },
      policyUri: 'basic-agent-authority@1.0.0',
      policyName: 'basic-agent-authority',
      policyVersion: '1.0.0',
      policyContentHash: 'c'.repeat(64),
      intentHash: 'd'.repeat(64),
      execution: { executed: false, targetSystem: 'resource/example', intentHash: 'd'.repeat(64) },
    })

    expect(receipt.decision.action).toBe('REQUIRE_HUMAN')
    expect(receipt.execution?.executed).toBe(false)
    expect(receipt.intent.argsHash).toBe(hashToolArgs({ amount: 420 }))
    expect(verifyAuthorizationReceipt(receipt).valid).toBe(true)
  })

  it('emits ALLOW with executed true', () => {
    const receipt = emitAuthorizationReceiptFromDecision({
      agentId: 'agt_example',
      toolName: 'read',
      toolArgs: {},
      decision: {
        action: 'ALLOW',
        ruleId: 'read_allow',
        reason: 'Example policy allows read',
        alertSeverity: 'LOW',
        matched: true,
      },
      policyUri: 'basic-agent-authority@1.0.0',
      policyName: 'basic-agent-authority',
      policyVersion: '1.0.0',
      policyContentHash: 'c'.repeat(64),
      intentHash: 'd'.repeat(64),
      execution: { executed: true, targetSystem: 'resource/example', intentHash: 'd'.repeat(64) },
    })

    expect(receipt.decision.outcome).toBe('allowed')
    expect(receipt.execution?.executed).toBe(true)
    expect(verifyAuthorizationReceipt(receipt).valid).toBe(true)
  })

  it('includes optional hash-chain fields in the signed content hash', () => {
    const first = emitAuthorizationReceiptFromDecision({
      agentId: 'agt_example',
      toolName: 'read',
      toolArgs: {},
      decision: {
        action: 'ALLOW',
        ruleId: 'read_allow',
        reason: 'Example policy allows read',
        alertSeverity: 'LOW',
        matched: true,
      },
      policyUri: 'basic-agent-authority@1.0.0',
      policyName: 'basic-agent-authority',
      policyVersion: '1.0.0',
      policyContentHash: 'c'.repeat(64),
      intentHash: 'd'.repeat(64),
      sequence: 0,
      prevReceiptHash: null,
      execution: { executed: true, targetSystem: 'resource/example', intentHash: 'd'.repeat(64) },
    })
    const second = emitAuthorizationReceiptFromDecision({
      agentId: 'agt_example',
      toolName: 'read',
      toolArgs: {},
      decision: {
        action: 'ALLOW',
        ruleId: 'read_allow',
        reason: 'Example policy allows read',
        alertSeverity: 'LOW',
        matched: true,
      },
      policyUri: 'basic-agent-authority@1.0.0',
      policyName: 'basic-agent-authority',
      policyVersion: '1.0.0',
      policyContentHash: 'c'.repeat(64),
      intentHash: 'e'.repeat(64),
      sequence: 1,
      prevReceiptHash: first.integrity.contentHash,
      execution: { executed: true, targetSystem: 'resource/example', intentHash: 'e'.repeat(64) },
    })

    expect(first.sequence).toBe(0)
    expect(first.prevReceiptHash).toBeNull()
    expect(second.sequence).toBe(1)
    expect(second.prevReceiptHash).toBe(first.integrity.contentHash)
    expect(verifyAuthorizationReceipt(first).valid).toBe(true)
    expect(verifyAuthorizationReceipt(second).valid).toBe(true)
  })
})
