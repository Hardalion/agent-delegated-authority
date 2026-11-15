import { describe, expect, it } from 'vitest'
import {
  AUTHORIZATION_RECEIPT_KIND,
  buildUnsignedAuthorizationReceipt,
  verifyAuthorizationReceipt,
} from './authorization-receipt.js'

const DUMMY_SIG = 'cd'.repeat(64)

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

  it('rejects ALLOW with human.status=pending, declined, or escalated', () => {
    for (const status of ['pending', 'declined', 'escalated'] as const) {
      const unsigned = buildUnsignedAuthorizationReceipt(
        base({
          human: { required: true, status },
        }) as never
      )
      const result = verifyAuthorizationReceipt({ ...unsigned, signature: DUMMY_SIG })
      expect(result.structureOk).toBe(false)
      expect(result.errors.join(' ')).toMatch(new RegExp(status))
    }
  })

  it('verifyReceiptChain rejects mismatched issuer names and duplicate receiptIds', async () => {
    const { verifyReceiptChain } = await import('./authorization-receipt.js')
    const r0Unsigned = buildUnsignedAuthorizationReceipt(
      base({
        receiptId: 'rcpt_chain_0',
        issuer: 'runtime-a',
        sequence: 0,
        prevReceiptHash: null,
      }) as never
    )
    const r0 = { ...r0Unsigned, signature: DUMMY_SIG }

    const r1DifferentIssuerUnsigned = buildUnsignedAuthorizationReceipt(
      base({
        receiptId: 'rcpt_chain_1',
        issuer: 'runtime-b',
        sequence: 1,
        prevReceiptHash: r0.integrity.contentHash,
      }) as never
    )
    const r1DifferentIssuer = { ...r1DifferentIssuerUnsigned, signature: DUMMY_SIG }
    const issuerCheck = verifyReceiptChain([r0, r1DifferentIssuer])
    expect(issuerCheck.valid).toBe(false)
    expect(issuerCheck.errors.join(' ')).toMatch(/issuer differs/)

    const r1DupIdUnsigned = buildUnsignedAuthorizationReceipt(
      base({
        receiptId: 'rcpt_chain_0',
        issuer: 'runtime-a',
        sequence: 1,
        prevReceiptHash: r0.integrity.contentHash,
      }) as never
    )
    const r1DupId = { ...r1DupIdUnsigned, signature: DUMMY_SIG }
    const dupCheck = verifyReceiptChain([r0, r1DupId])
    expect(dupCheck.valid).toBe(false)
    expect(dupCheck.errors.join(' ')).toMatch(/duplicate receiptId/)
  })
})

