import { describe, expect, it } from 'vitest'
import {
  AUTHORIZATION_RECEIPT_KIND,
  buildUnsignedAuthorizationReceipt,
  verifyAuthorizationReceipt,
} from './authorization-receipt.js'

const DUMMY_SIG = 'ab'.repeat(64)

function base(over: Record<string, unknown> = {}) {
  return {
    v: 1 as const,
    kind: AUTHORIZATION_RECEIPT_KIND,
    receiptId: 'rcpt_sem_1',
    issuer: 'reference-runtime',
    issuerKeyId: 'ed25519:demo-key-1',
    decidedAt: '2026-08-10T12:00:00.000Z',
    intent: { toolName: 'apply', argsHash: 'a'.repeat(64) },
    identity: { agentId: 'agt_example', actorType: 'non_human_agent' as const },
    policy: {
      policyUri: 'basic-agent-authority@1.0.0',
      policyName: 'basic-agent-authority',
      policyVersion: '1.0.0',
      ruleId: 'r',
      contentHash: 'c'.repeat(64),
    },
    decision: {
      action: 'ALLOW' as const,
      outcome: 'allowed' as const,
      reason: 'ok',
      alertSeverity: 'LOW' as const,
      matched: true,
    },
    execution: { intentHash: 'd'.repeat(64), executed: false },
    integrity: { contentHash: '' },
    ...over,
  }
}

describe('ADAP-011 receipt semantic invariants', () => {
  it('rejects BLOCK with outcome allowed', () => {
    const unsigned = buildUnsignedAuthorizationReceipt(
      base({
        decision: {
          action: 'BLOCK',
          outcome: 'allowed',
          reason: 'bad',
          alertSeverity: 'CRITICAL',
          matched: true,
        },
      }) as never
    )
    const result = verifyAuthorizationReceipt({ ...unsigned, signature: DUMMY_SIG })
    expect(result.structureOk).toBe(false)
    expect(result.errors.join(' ')).toMatch(/inconsistent/)
  })

  it('rejects executed=true on REQUIRE_HUMAN', () => {
    const unsigned = buildUnsignedAuthorizationReceipt(
      base({
        decision: {
          action: 'REQUIRE_HUMAN',
          outcome: 'pending_human',
          reason: 'need human',
          alertSeverity: 'MEDIUM',
          matched: true,
        },
        human: { required: true, status: 'pending' },
        execution: { intentHash: 'd'.repeat(64), executed: true },
      }) as never
    )
    const result = verifyAuthorizationReceipt({ ...unsigned, signature: DUMMY_SIG })
    expect(result.structureOk).toBe(false)
    expect(result.errors.join(' ')).toMatch(/executed/)
  })

  it('accepts an authorized dispatch whose executor did not return', () => {
    const unsigned = buildUnsignedAuthorizationReceipt(
      base({
        execution: { intentHash: 'd'.repeat(64), executed: false, outcome: 'unknown' },
      }) as never
    )
    const result = verifyAuthorizationReceipt({ ...unsigned, signature: DUMMY_SIG })
    expect(result.errors.join(' ')).not.toMatch(/unknown/)
    expect(result.structureOk).toBe(true)
  })

  it('rejects unknown outcome that claims executed=true or a BLOCK decision', () => {
    const claimed = buildUnsignedAuthorizationReceipt(
      base({
        execution: { intentHash: 'd'.repeat(64), executed: true, outcome: 'unknown' },
      }) as never
    )
    expect(verifyAuthorizationReceipt({ ...claimed, signature: DUMMY_SIG }).structureOk).toBe(false)
    const blocked = buildUnsignedAuthorizationReceipt(
      base({
        decision: {
          action: 'BLOCK',
          outcome: 'rejected',
          reason: 'no',
          alertSeverity: 'CRITICAL',
          matched: false,
        },
        execution: { intentHash: 'd'.repeat(64), executed: false, outcome: 'unknown' },
      }) as never
    )
    expect(verifyAuthorizationReceipt({ ...blocked, signature: DUMMY_SIG }).structureOk).toBe(false)
  })

  it('rejects ALLOW with human.status=pending', () => {
    const unsigned = buildUnsignedAuthorizationReceipt(
      base({
        human: { required: true, status: 'pending' },
      }) as never
    )
    const result = verifyAuthorizationReceipt({ ...unsigned, signature: DUMMY_SIG })
    expect(result.structureOk).toBe(false)
    expect(result.errors.join(' ')).toMatch(/pending/)
  })
})
