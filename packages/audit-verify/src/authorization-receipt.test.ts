import { generateKeyPairSync, sign } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  AUTHORIZATION_RECEIPT_KIND,
  buildUnsignedAuthorizationReceipt,
  canonicalReceiptJson,
  contentHashOfUnsignedReceipt,
  normalizeAuthorizationOutcome,
  verifyAuthorizationReceipt,
  verifyReceiptSignature,
  type AuthorizationReceiptV1,
} from './authorization-receipt.js'

const DUMMY_SIG = 'ab'.repeat(64)

function sampleBody() {
  return {
    v: 1 as const,
    kind: AUTHORIZATION_RECEIPT_KIND,
    receiptId: 'rcpt_demo_block_1',
    issuer: 'reference-runtime',
    issuerKeyId: 'ed25519:demo-key-1',
    decidedAt: '2026-08-10T12:00:00.000Z',
    intent: {
      toolName: 'apply',
      argsHash: 'a'.repeat(64),
      argsRedacted: { amount: 420 },
    },
    identity: {
      agentId: 'agt_example',
      actorType: 'non_human_agent' as const,
      agentRole: 'operator',
      principalId: 'prn_example',
    },
    policy: {
      policyUri: 'basic-agent-authority@1.0.0',
      policyName: 'basic-agent-authority',
      policyVersion: '1.0.0',
      ruleId: 'apply_needs_human',
      contentHash: 'c'.repeat(64),
    },
    decision: {
      action: 'REQUIRE_HUMAN' as const,
      outcome: 'pending_human' as const,
      reason: 'A person must approve this action',
      alertSeverity: 'MEDIUM' as const,
      matched: true,
      failureMode: 'NONE' as const,
    },
    execution: {
      targetSystem: 'resource/example',
      executed: false,
      intentHash: 'd'.repeat(64),
    },
    human: {
      required: true,
      status: 'pending' as const,
    },
    integrity: {
      contentHash: '',
    },
  }
}

describe('authorization receipt', () => {
  it('builds content hash deterministically', () => {
    const unsigned = buildUnsignedAuthorizationReceipt(sampleBody())
    expect(unsigned.integrity.contentHash).toMatch(/^[0-9a-f]{64}$/)
    const again = contentHashOfUnsignedReceipt(sampleBody())
    expect(again).toBe(unsigned.integrity.contentHash)
  })

  it('verifies a well-formed receipt', () => {
    const unsigned = buildUnsignedAuthorizationReceipt(sampleBody())
    const receipt: AuthorizationReceiptV1 = {
      ...unsigned,
      signature: DUMMY_SIG,
    }
    const result = verifyAuthorizationReceipt(receipt)
    expect(result.structureOk).toBe(true)
    expect(result.contentHashOk).toBe(true)
    expect(result.valid).toBe(true)
    expect(result.errors).toEqual([])
  })

  it('rejects an authority subject that disagrees with the identity chain', () => {
    const unsigned = buildUnsignedAuthorizationReceipt({
      ...sampleBody(),
      identity: {
        ...sampleBody().identity,
        delegationChain: ['agt_a'],
      },
      authority: {
        principalId: 'prn_example',
        chain: [{ delegationId: 'del_root', subject: 'agt_other', hash: 'ab'.repeat(32) }],
      },
    })
    const result = verifyAuthorizationReceipt({ ...unsigned, signature: DUMMY_SIG })
    expect(result.structureOk).toBe(false)
    expect(result.valid).toBe(false)
  })

  it('rejects tampered reason', () => {
    const unsigned = buildUnsignedAuthorizationReceipt(sampleBody())
    const receipt: AuthorizationReceiptV1 = {
      ...unsigned,
      signature: DUMMY_SIG,
      decision: {
        ...unsigned.decision,
        reason: 'tampered',
      },
    }
    const result = verifyAuthorizationReceipt(receipt)
    expect(result.valid).toBe(false)
    expect(result.contentHashOk).toBe(false)
  })

  it('rejects invalid kind', () => {
    const unsigned = buildUnsignedAuthorizationReceipt(sampleBody())
    const result = verifyAuthorizationReceipt({
      ...unsigned,
      kind: 'wrong',
      signature: DUMMY_SIG,
    })
    expect(result.structureOk).toBe(false)
    expect(result.valid).toBe(false)
  })

  it('normalizes decision actions to outcomes', () => {
    expect(normalizeAuthorizationOutcome('ALLOW')).toBe('allowed')
    expect(normalizeAuthorizationOutcome('BLOCK')).toBe('rejected')
    expect(normalizeAuthorizationOutcome('REQUIRE_HUMAN')).toBe('pending_human')
    expect(normalizeAuthorizationOutcome('DEFER')).toBe('deferred')
  })

  it('canonical JSON sorts keys', () => {
    const a = canonicalReceiptJson({ b: 1, a: 2 })
    const b = canonicalReceiptJson({ a: 2, b: 1 })
    expect(a).toBe(b)
  })

  it('checks the Ed25519 signature only when the issuer public key is supplied', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519')
    const unsigned = buildUnsignedAuthorizationReceipt(sampleBody())
    const signature = sign(null, Buffer.from(canonicalReceiptJson(unsigned)), privateKey).toString('hex')
    const receipt: AuthorizationReceiptV1 = { ...unsigned, signature }
    const spki = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url')
    expect(verifyAuthorizationReceipt(receipt).valid).toBe(true)
    expect(verifyReceiptSignature(receipt, spki)).toBe(true)
    expect(verifyReceiptSignature({ ...receipt, signature: DUMMY_SIG }, spki)).toBe(false)
  })
})
