import { describe, expect, it } from 'vitest'
import {
  AUTHORIZATION_RECEIPT_KIND,
  buildUnsignedAuthorizationReceipt,
  verifyAuthorizationReceipt,
  type AuthorizationReceiptV1,
} from './authorization-receipt.js'
import { cliExitCode } from './cli.js'

describe('adap-receipt CLI exit', () => {
  it('exits non-zero when the signature was not checked', () => {
    const unsigned = buildUnsignedAuthorizationReceipt({
      v: 1,
      kind: AUTHORIZATION_RECEIPT_KIND,
      receiptId: 'rcpt_cli',
      issuer: 'reference-runtime',
      issuerKeyId: 'ed25519:test',
      decidedAt: '2026-10-06T18:00:00.000Z',
      intent: { toolName: 'read', argsHash: 'a'.repeat(64), argsRedacted: {} },
      identity: {
        agentId: 'agt_example',
        actorType: 'non_human_agent',
        principalId: 'prn_example',
      },
      policy: {
        policyUri: 'basic-agent-authority@1',
        policyName: 'basic-agent-authority',
        policyVersion: '1.0.0',
        ruleId: 'read_allow',
        contentHash: 'c'.repeat(64),
      },
      decision: {
        action: 'ALLOW',
        outcome: 'allowed',
        reason: 'ok',
        alertSeverity: 'LOW',
        matched: true,
        failureMode: 'NONE',
      },
      execution: { executed: false, intentHash: 'd'.repeat(64) },
      integrity: { contentHash: '' },
    })
    const receipt: AuthorizationReceiptV1 = { ...unsigned, signature: 'cd'.repeat(64) }
    const result = verifyAuthorizationReceipt(receipt)
    expect(result.signatureChecked).toBe(false)
    expect(result.status).toBe('integrity_only')
    expect(result.valid).toBe(false)
    expect(cliExitCode(result)).toBe(1)
  })
})
