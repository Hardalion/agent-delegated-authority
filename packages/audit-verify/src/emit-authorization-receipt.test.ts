import { describe, expect, it } from 'vitest'
import { verifyAuthorizationReceipt } from './authorization-receipt.js'
import { emitAuthorizationReceiptFromDecision, hashToolArgs } from './emit-authorization-receipt.js'

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
})
