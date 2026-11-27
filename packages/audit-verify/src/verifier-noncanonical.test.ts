/**
 * The offline verifiers are called on untrusted receipts. A structurally valid
 * receipt can still carry content that is not canonical JSON (for example a lone
 * UTF-16 surrogate in a free-text field). The verifiers must fail closed with a
 * result object, never throw — otherwise a crafted receipt is an unhandled
 * exception in any consumer that does not wrap the call (including verifyReceiptChain).
 */
import { generateKeyPairSync, sign } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  AUTHORIZATION_RECEIPT_KIND,
  RECEIPT_CHECKPOINT_KIND,
  buildUnsignedAuthorizationReceipt,
  canonicalReceiptJson,
  verifyAuthorizationReceipt,
  verifyReceiptChain,
  verifyReceiptCheckpoint,
  verifyReceiptSignature,
  type AuthorizationReceiptV1,
  type ReceiptCheckpointV1,
} from './authorization-receipt.js'

const DUMMY_SIG = 'cd'.repeat(64)
const LONE_SURROGATE = 'approve\uD800now'

function sampleBody() {
  return {
    v: 1 as const,
    kind: AUTHORIZATION_RECEIPT_KIND,
    receiptId: 'rcpt_demo_block_1',
    issuer: 'reference-runtime',
    issuerKeyId: 'ed25519:demo-key-1',
    decidedAt: '2026-08-10T12:00:00.000Z',
    intent: { toolName: 'apply', argsHash: 'a'.repeat(64), argsRedacted: { amount: 420 } },
    identity: { agentId: 'agt_example', actorType: 'non_human_agent' as const, agentRole: 'operator', principalId: 'prn_example' },
    policy: { policyUri: 'basic@1.0.0', policyName: 'basic', policyVersion: '1.0.0', ruleId: 'apply_needs_human', contentHash: 'c'.repeat(64) },
    decision: { action: 'REQUIRE_HUMAN' as const, outcome: 'pending_human' as const, reason: 'A person must approve this action', alertSeverity: 'MEDIUM' as const, matched: true, failureMode: 'NONE' as const },
    execution: { targetSystem: 'resource/example', executed: false, intentHash: 'd'.repeat(64) },
    human: { required: true, status: 'pending' as const },
    integrity: { contentHash: '' },
  }
}

/** A structurally valid receipt whose decision.reason holds a lone surrogate. */
function noncanonicalReceipt(extra: Partial<AuthorizationReceiptV1> = {}): AuthorizationReceiptV1 {
  const unsigned = buildUnsignedAuthorizationReceipt(sampleBody())
  const receipt = { ...unsigned, signature: DUMMY_SIG, ...extra } as AuthorizationReceiptV1
  receipt.decision = { ...receipt.decision, reason: LONE_SURROGATE }
  return receipt
}

describe('receipt verifiers fail closed (never throw) on non-canonical content', () => {
  it('verifyAuthorizationReceipt returns invalid, does not throw (no public key)', () => {
    let result!: ReturnType<typeof verifyAuthorizationReceipt>
    expect(() => {
      result = verifyAuthorizationReceipt(noncanonicalReceipt())
    }).not.toThrow()
    expect(result.valid).toBe(false)
    expect(result.status).toBe('invalid')
    expect(result.errors.some((e) => e.includes('canonical'))).toBe(true)
  })

  it('verifyAuthorizationReceipt returns invalid, does not throw (with public key)', () => {
    const { publicKey } = generateKeyPairSync('ed25519')
    const spki = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url')
    expect(() => verifyAuthorizationReceipt(noncanonicalReceipt(), { publicKeySpki: spki })).not.toThrow()
    expect(verifyAuthorizationReceipt(noncanonicalReceipt(), { publicKeySpki: spki }).valid).toBe(false)
  })

  it('verifyReceiptSignature returns false, does not throw', () => {
    const { publicKey } = generateKeyPairSync('ed25519')
    const spki = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url')
    let ok: boolean | undefined
    expect(() => {
      ok = verifyReceiptSignature(noncanonicalReceipt(), spki)
    }).not.toThrow()
    expect(ok).toBe(false)
  })

  it('verifyReceiptChain returns invalid, does not throw when a receipt is non-canonical', () => {
    const receipt = noncanonicalReceipt({ sequence: 0, prevReceiptHash: null })
    let result!: ReturnType<typeof verifyReceiptChain>
    expect(() => {
      result = verifyReceiptChain([receipt])
    }).not.toThrow()
    expect(result.valid).toBe(false)
  })

  it('verifyReceiptCheckpoint returns invalid, does not throw on a non-canonical checkpoint', () => {
    const checkpoint = {
      v: 1,
      kind: RECEIPT_CHECKPOINT_KIND,
      issuer: LONE_SURROGATE,
      issuerKeyId: 'ed25519:demo-key-1',
      sequence: 0,
      contentHash: 'c'.repeat(64),
      signedAt: '2026-08-10T12:00:00.000Z',
      signature: DUMMY_SIG,
    } as ReceiptCheckpointV1
    const { publicKey } = generateKeyPairSync('ed25519')
    const spki = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url')
    let result!: ReturnType<typeof verifyReceiptCheckpoint>
    expect(() => {
      result = verifyReceiptCheckpoint(checkpoint, spki)
    }).not.toThrow()
    expect(result.valid).toBe(false)
  })

  it('still verifies a well-formed signed receipt (regression)', () => {
    const unsigned = buildUnsignedAuthorizationReceipt(sampleBody())
    const { publicKey, privateKey } = generateKeyPairSync('ed25519')
    const signature = sign(null, Buffer.from(canonicalReceiptJson(unsigned)), privateKey).toString('hex')
    const spki = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url')
    const result = verifyAuthorizationReceipt({ ...unsigned, signature }, { publicKeySpki: spki })
    expect(result.valid).toBe(true)
    expect(result.status).toBe('verified')
  })
})
