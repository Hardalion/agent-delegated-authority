import { generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  verifyAuthorizationReceipt,
  verifyReceiptChain,
  verifyReceiptSignature,
  type AuthorizationReceiptV1,
} from './authorization-receipt.js'
import {
  AuthorizationReceiptLog,
  DEMO_SIGNATURE_HEX,
  emitAuthorizationReceipt,
  emitAuthorizationReceiptFromDecision,
  generateReceiptKeyPair,
  hashToolArgs,
  signReceipt,
} from './emit-authorization-receipt.js'

function testSigner() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const publicKeySpki = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url')
  return { privateKey, publicKey, publicKeySpki }
}

function chainOf(length: number): { receipts: AuthorizationReceiptV1[]; publicKeySpki: string } {
  const { privateKey, publicKeySpki } = testSigner()
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
        issuer: 'reference-runtime',
        issuerKeyId: 'ed25519:test-key-1',
        signer: privateKey,
        sequence,
        prevReceiptHash: receipts[sequence - 1]?.integrity.contentHash ?? null,
        includeArgsUnredacted: true,
      })
    )
  }
  return { receipts, publicKeySpki }
}

describe('verifyReceiptChain', () => {
  it('accepts an intact chain', () => {
    const { receipts, publicKeySpki } = chainOf(4)
    expect(verifyReceiptChain(receipts, { publicKeySpki })).toEqual({ valid: true, errors: [] })
  })

  it('detects an omitted receipt', () => {
    const { receipts } = chainOf(4)
    const [a, , c, d] = receipts
    const result = verifyReceiptChain([a!, c!, d!])
    expect(result.valid).toBe(false)
    expect(result.errors.join(' ')).toMatch(/does not link|sequence/)
  })

  it('detects reordering', () => {
    const { receipts } = chainOf(3)
    const [a, b, c] = receipts
    expect(verifyReceiptChain([a!, c!, b!]).valid).toBe(false)
  })

  it('detects a rewritten link', () => {
    const { receipts } = chainOf(3)
    const forged = { ...receipts[1]!, prevReceiptHash: 'f'.repeat(64) }
    expect(verifyReceiptChain([receipts[0]!, forged, receipts[2]!]).valid).toBe(false)
  })

  it('does not detect a dropped tail on its own', () => {
    expect(verifyReceiptChain(chainOf(4).receipts.slice(0, 2)).valid).toBe(true)
  })
})

describe('emitAuthorizationReceipt', () => {
  it('emits a verifiable REQUIRE_HUMAN receipt for apply', () => {
    const { privateKey, publicKeySpki } = testSigner()
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
      issuer: 'reference-runtime',
      issuerKeyId: 'ed25519:test-key-1',
      signer: privateKey,
      argsRedactedAllowlist: ['amount'],
      execution: { executed: false, targetSystem: 'resource/example', intentHash: 'd'.repeat(64) },
    })

    expect(receipt.decision.action).toBe('REQUIRE_HUMAN')
    expect(receipt.execution?.executed).toBe(false)
    expect(receipt.intent.argsHash).toBe(hashToolArgs({ amount: 420 }))
    expect(receipt.intent.argsRedacted).toEqual({ amount: 420 })
    expect(verifyAuthorizationReceipt(receipt).valid).toBe(true)
    expect(verifyAuthorizationReceipt(receipt, { publicKeySpki }).valid).toBe(true)
    expect(verifyReceiptSignature(receipt, publicKeySpki)).toBe(true)
  })

  it('emits ALLOW with executed true', () => {
    const { privateKey } = testSigner()
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
      issuer: 'reference-runtime',
      issuerKeyId: 'ed25519:test-key-1',
      signer: privateKey,
      execution: { executed: true, targetSystem: 'resource/example', intentHash: 'd'.repeat(64) },
    })

    expect(receipt.decision.outcome).toBe('allowed')
    expect(receipt.execution?.executed).toBe(true)
    expect(verifyAuthorizationReceipt(receipt).valid).toBe(true)
  })

  it('includes optional hash-chain fields in the signed content hash', () => {
    const { privateKey } = testSigner()
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
      issuer: 'reference-runtime',
      issuerKeyId: 'ed25519:test-key-1',
      signer: privateKey,
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
      issuer: 'reference-runtime',
      issuerKeyId: 'ed25519:test-key-1',
      signer: privateKey,
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

  it('throws without signer, signatureHex, or demo', () => {
    expect(() =>
      emitAuthorizationReceipt({
        agentId: 'agt_example',
        toolName: 'read',
        toolArgs: {},
        action: 'ALLOW',
        ruleId: 'read_allow',
        reason: 'read',
        alertSeverity: 'LOW',
        matched: true,
        policyUri: 'basic-agent-authority@1.0.0',
        policyName: 'basic-agent-authority',
        policyVersion: '1.0.0',
        policyContentHash: 'c'.repeat(64),
        intentHash: 'd'.repeat(64),
        issuer: 'reference-runtime',
        issuerKeyId: 'ed25519:test-key-1',
      })
    ).toThrow(/requires signer/)
  })

  it('rejects demo placeholder as valid evidence', () => {
    const receipt = emitAuthorizationReceiptFromDecision({
      agentId: 'agt_example',
      toolName: 'read',
      toolArgs: { token: 'secret' },
      decision: { action: 'ALLOW', ruleId: 'read_allow', reason: 'read', alertSeverity: 'LOW', matched: true },
      policyUri: 'basic-agent-authority@1.0.0',
      policyName: 'basic-agent-authority',
      policyVersion: '1.0.0',
      policyContentHash: 'c'.repeat(64),
      intentHash: 'd'.repeat(64),
      demo: true,
    })
    expect(receipt.signature).toBe(DEMO_SIGNATURE_HEX)
    const result = verifyAuthorizationReceipt(receipt)
    expect(result.valid).toBe(false)
    expect(result.demoSignature).toBe(true)
    expect(result.contentHashOk).toBe(true)
    expect(result.structureOk).toBe(true)
    expect(result.signatureChecked).toBe(false)
    expect(result.errors.join(' ')).toMatch(/demo placeholder/)
  })

  it('redacts args by default and supports allowlist', () => {
    const { privateKey } = testSigner()
    const denied = emitAuthorizationReceipt({
      agentId: 'agt_example',
      toolName: 'apply',
      toolArgs: { amount: 10, apiKey: 'sk-secret', note: 'ok' },
      action: 'ALLOW',
      ruleId: 'r',
      reason: 'ok',
      alertSeverity: 'LOW',
      matched: true,
      policyUri: 'p@1.0.0',
      policyName: 'p',
      policyVersion: '1.0.0',
      policyContentHash: 'c'.repeat(64),
      intentHash: 'd'.repeat(64),
      issuer: 'reference-runtime',
      issuerKeyId: 'ed25519:test-key-1',
      signer: privateKey,
      execution: { executed: true, intentHash: 'd'.repeat(64) },
    })
    expect(denied.intent.argsRedacted).toEqual({})
    expect(denied.intent.argsHash).toBe(hashToolArgs({ amount: 10, apiKey: 'sk-secret', note: 'ok' }))

    const allowlisted = emitAuthorizationReceipt({
      agentId: 'agt_example',
      toolName: 'apply',
      toolArgs: { amount: 10, apiKey: 'sk-secret', note: 'ok' },
      action: 'ALLOW',
      ruleId: 'r',
      reason: 'ok',
      alertSeverity: 'LOW',
      matched: true,
      policyUri: 'p@1.0.0',
      policyName: 'p',
      policyVersion: '1.0.0',
      policyContentHash: 'c'.repeat(64),
      intentHash: 'd'.repeat(64),
      issuer: 'reference-runtime',
      issuerKeyId: 'ed25519:test-key-1',
      signer: privateKey,
      argsRedactedAllowlist: ['amount', 'note'],
      execution: { executed: true, intentHash: 'd'.repeat(64) },
    })
    expect(allowlisted.intent.argsRedacted).toEqual({ amount: 10, note: 'ok' })
  })

  it('generates collision-resistant receipt ids', () => {
    const { privateKey } = testSigner()
    const ids = new Set<string>()
    for (let i = 0; i < 40; i += 1) {
      const receipt = emitAuthorizationReceipt({
        agentId: 'agt_example',
        toolName: 'read',
        toolArgs: {},
        action: 'ALLOW',
        ruleId: 'r',
        reason: 'ok',
        alertSeverity: 'LOW',
        matched: true,
        policyUri: 'p@1.0.0',
        policyName: 'p',
        policyVersion: '1.0.0',
        policyContentHash: 'c'.repeat(64),
        intentHash: 'd'.repeat(64),
        issuer: 'reference-runtime',
        issuerKeyId: 'ed25519:test-key-1',
        signer: privateKey,
        decidedAt: '2026-01-01T00:00:00.000Z',
        execution: { executed: true, intentHash: 'd'.repeat(64) },
      })
      ids.add(receipt.receiptId)
    }
    expect(ids.size).toBe(40)
  })

  it('exports signReceipt and AuthorizationReceiptLog', () => {
    const { privateKey, publicKeySpki } = testSigner()
    const log = new AuthorizationReceiptLog({
      issuer: 'reference-runtime',
      issuerKeyId: 'ed25519:test-key-1',
      signer: privateKey,
    })
    const a = log.append({
      agentId: 'agt_example',
      toolName: 'read',
      toolArgs: {},
      action: 'ALLOW',
      ruleId: 'r',
      reason: 'ok',
      alertSeverity: 'LOW',
      matched: true,
      policyUri: 'p@1.0.0',
      policyName: 'p',
      policyVersion: '1.0.0',
      policyContentHash: 'c'.repeat(64),
      intentHash: 'a'.repeat(64),
      execution: { executed: true, intentHash: 'a'.repeat(64) },
    })
    const b = log.append({
      agentId: 'agt_example',
      toolName: 'read',
      toolArgs: {},
      action: 'ALLOW',
      ruleId: 'r',
      reason: 'ok',
      alertSeverity: 'LOW',
      matched: true,
      policyUri: 'p@1.0.0',
      policyName: 'p',
      policyVersion: '1.0.0',
      policyContentHash: 'c'.repeat(64),
      intentHash: 'b'.repeat(64),
      execution: { executed: true, intentHash: 'b'.repeat(64) },
    })
    expect(a.sequence).toBe(0)
    expect(b.sequence).toBe(1)
    expect(b.prevReceiptHash).toBe(a.integrity.contentHash)
    expect(verifyReceiptChain(log.list(), { publicKeySpki }).valid).toBe(true)

    const drafted = emitAuthorizationReceipt({
      agentId: 'agt_example',
      toolName: 'read',
      toolArgs: {},
      action: 'ALLOW',
      ruleId: 'r',
      reason: 'ok',
      alertSeverity: 'LOW',
      matched: true,
      policyUri: 'p@1.0.0',
      policyName: 'p',
      policyVersion: '1.0.0',
      policyContentHash: 'c'.repeat(64),
      intentHash: 'd'.repeat(64),
      issuer: 'reference-runtime',
      issuerKeyId: 'ed25519:test-key-1',
      demo: true,
      execution: { executed: true, intentHash: 'd'.repeat(64) },
    })
    const resigned = signReceipt(drafted, privateKey)
    expect(resigned.signature).not.toBe(DEMO_SIGNATURE_HEX)
    expect(verifyAuthorizationReceipt(resigned, { publicKeySpki }).valid).toBe(true)
    expect(generateReceiptKeyPair().privateKey.type).toBe('private')
  })
})
