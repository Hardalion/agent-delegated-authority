/**
 * Build an Authorization Receipt from a policy decision.
 * Production callers must supply `signer` or `signatureHex`. Demo placeholders never verify as valid.
 * Normative: ../../spec/authorization-receipt.md
 */

import { createPrivateKey, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import {
  AUTHORIZATION_RECEIPT_KIND,
  buildUnsignedAuthorizationReceipt,
  canonicalReceiptJson,
  normalizeAuthorizationOutcome,
  type AuthorizationAlertSeverity,
  type AuthorizationReceiptAction,
  type AuthorizationReceiptV1,
  type AuthorizationActorType,
  type ExecutionBinding,
  type AuthorityBinding,
  type HumanAttestation,
  type UnsignedAuthorizationReceipt,
} from './authorization-receipt.js'

/** Known demo placeholder. Verifiers reject it as cryptographically unverified. */
export const DEMO_SIGNATURE_HEX = 'ab'.repeat(64)

export type ReceiptSigner =
  | KeyObject
  | { readonly privateKey: KeyObject }
  | { readonly privateKeyPem: string }
  | ((unsignedCanonicalJson: string) => string)

export type EmitAuthorizationReceiptInput = {
  readonly agentId: string
  readonly toolName: string
  readonly toolArgs: Record<string, unknown>
  readonly action: AuthorizationReceiptAction
  readonly ruleId: string
  readonly reason: string
  readonly alertSeverity: AuthorizationAlertSeverity
  readonly matched: boolean
  readonly policyUri: string
  readonly policyName: string
  readonly policyVersion: string
  readonly policyContentHash: string
  readonly intentHash: string
  readonly receiptId?: string
  readonly issuer?: string
  readonly issuerKeyId?: string
  readonly agentRole?: string
  readonly principalId?: string
  readonly actorType?: AuthorizationActorType
  readonly delegationChain?: readonly string[]
  readonly authority?: AuthorityBinding
  readonly decidedAt?: string
  readonly execution?: ExecutionBinding
  readonly human?: HumanAttestation
  readonly failureMode?: 'NONE' | 'RULE_VIOLATION' | 'MAPPING_FAILED' | 'SYSTEM_ERROR'
  /** Optional position in an issuer receipt log. Covered by the content hash. */
  readonly sequence?: number
  /** SHA-256 content hash of the previous receipt, or null for the first in a chain. */
  readonly prevReceiptHash?: string | null
  /**
   * Ed25519 signature over canonical unsigned JSON (128 hex chars).
   * Required unless `signer` or `demo: true` is set.
   */
  readonly signatureHex?: string
  /**
   * Signs the unsigned receipt. Preferred over passing a precomputed `signatureHex`.
   */
  readonly signer?: ReceiptSigner
  /**
   * Explicit non-production mode. Emits a known placeholder signature that
   * `verifyAuthorizationReceipt` rejects. Do not ship demo receipts as evidence.
   */
  readonly demo?: boolean
  /**
   * Top-level tool-arg keys permitted in `intent.argsRedacted`.
   * Deny-by-default: omit or pass `[]` to emit an empty redacted object.
   */
  readonly argsRedactedAllowlist?: readonly string[]
  /**
   * Explicit opt-in to copy all tool args into `argsRedacted` (still shallow).
   * Prefer an allowlist in production.
   */
  readonly includeArgsUnredacted?: boolean
  /** Custom redaction. Wins over allowlist / includeArgsUnredacted. */
  readonly redactArgs?: (toolArgs: Record<string, unknown>) => Record<string, unknown>
}

function sha256HexUtf8(utf8: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(utf8)))
}

/** Stable args hash for receipt intent. Same canonical JSON as receipt signatures. */
export function hashToolArgs(toolArgs: Record<string, unknown>): string {
  return sha256HexUtf8(canonicalReceiptJson(toolArgs))
}

function redactToolArgs(
  toolArgs: Record<string, unknown>,
  input: Pick<
    EmitAuthorizationReceiptInput,
    'argsRedactedAllowlist' | 'includeArgsUnredacted' | 'redactArgs'
  >
): Record<string, unknown> {
  if (input.redactArgs) return input.redactArgs(toolArgs)
  if (input.includeArgsUnredacted === true) return { ...toolArgs }
  const allow = input.argsRedactedAllowlist
  if (!allow || allow.length === 0) return {}
  const out: Record<string, unknown> = {}
  for (const key of allow) {
    if (Object.prototype.hasOwnProperty.call(toolArgs, key)) {
      out[key] = toolArgs[key]
    }
  }
  return out
}

function resolveSignature(
  unsigned: UnsignedAuthorizationReceipt,
  input: Pick<EmitAuthorizationReceiptInput, 'signatureHex' | 'signer' | 'demo'>
): string {
  if (input.signer != null) {
    return signReceiptBytes(unsigned, input.signer)
  }
  if (typeof input.signatureHex === 'string' && input.signatureHex.length > 0) {
    if (!/^[0-9a-f]{128}$/i.test(input.signatureHex)) {
      throw new Error('signatureHex must be 64-byte Ed25519 hex (128 hex chars)')
    }
    return input.signatureHex.toLowerCase()
  }
  if (input.demo === true) {
    return DEMO_SIGNATURE_HEX
  }
  throw new Error(
    'emitAuthorizationReceipt requires signer, signatureHex, or demo: true (demo signatures never verify as valid)'
  )
}

/**
 * Sign an unsigned receipt body with Ed25519. Returns 128 lowercase hex chars.
 * Accepts a Node KeyObject, `{ privateKey }`, PEM wrapper, or custom signer fn.
 */
export function signReceiptBytes(
  unsigned: UnsignedAuthorizationReceipt | Omit<AuthorizationReceiptV1, 'signature'>,
  signer: ReceiptSigner
): string {
  const canonical = canonicalReceiptJson(unsigned)
  if (typeof signer === 'function') {
    const hex = signer(canonical)
    if (!/^[0-9a-f]{128}$/i.test(hex)) {
      throw new Error('custom receipt signer must return 128 hex chars')
    }
    return hex.toLowerCase()
  }
  const key =
    'privateKeyPem' in signer
      ? createPrivateKey(signer.privateKeyPem)
      : 'privateKey' in signer
        ? signer.privateKey
        : signer
  return sign(null, Buffer.from(canonical), key).toString('hex')
}

/** Attach an Ed25519 signature to a receipt (recomputes over the unsigned body). */
export function signReceipt(
  receipt: AuthorizationReceiptV1 | UnsignedAuthorizationReceipt,
  signer: ReceiptSigner
): AuthorizationReceiptV1 {
  const { signature: _ignored, ...unsigned } = receipt as AuthorizationReceiptV1
  return {
    ...(unsigned as UnsignedAuthorizationReceipt),
    signature: signReceiptBytes(unsigned as UnsignedAuthorizationReceipt, signer),
  }
}

export function isDemoSignatureHex(signature: string): boolean {
  return signature.toLowerCase() === DEMO_SIGNATURE_HEX
}

export function emitAuthorizationReceipt(
  input: EmitAuthorizationReceiptInput
): AuthorizationReceiptV1 {
  const decidedAt = input.decidedAt ?? new Date().toISOString()
  const receiptId =
    input.receiptId ??
    `rcpt_${sha256HexUtf8(
      `${input.toolName}:${decidedAt}:${input.agentId}:${bytesToHex(randomBytes(16))}`
    ).slice(0, 32)}`

  if (input.demo === true && (input.issuer == null || input.issuerKeyId == null)) {
    // Demo defaults are allowed only with explicit demo: true.
  }

  const outcome = normalizeAuthorizationOutcome(input.action)

  const executed = input.execution?.executed === true
  const human =
    input.human ??
    (input.action === 'REQUIRE_HUMAN'
      ? { required: true as const, status: 'pending' as const }
      : undefined)

  const issuer =
    input.issuer ?? (input.demo === true ? 'reference-runtime' : undefined)
  const issuerKeyId =
    input.issuerKeyId ?? (input.demo === true ? 'ed25519:demo-key-1' : undefined)
  if (issuer == null || issuerKeyId == null) {
    throw new Error('emitAuthorizationReceipt requires issuer and issuerKeyId (or demo: true)')
  }

  const unsigned = buildUnsignedAuthorizationReceipt({
    v: 1,
    kind: AUTHORIZATION_RECEIPT_KIND,
    receiptId,
    issuer,
    issuerKeyId,
    decidedAt,
    intent: {
      toolName: input.toolName,
      argsHash: hashToolArgs(input.toolArgs),
      argsRedacted: redactToolArgs(input.toolArgs, input),
    },
    identity: {
      agentId: input.agentId,
      actorType: input.actorType ?? 'non_human_agent',
      agentRole: input.agentRole,
      principalId: input.principalId,
      ...(input.delegationChain && input.delegationChain.length > 0
        ? { delegationChain: input.delegationChain }
        : {}),
    },
    ...(input.authority ? { authority: input.authority } : {}),
    policy: {
      policyUri: input.policyUri,
      policyName: input.policyName,
      policyVersion: input.policyVersion,
      ruleId: input.ruleId,
      contentHash: input.policyContentHash,
    },
    decision: {
      action: input.action,
      outcome,
      reason: input.reason,
      alertSeverity: input.alertSeverity,
      matched: input.matched,
      failureMode: input.failureMode ?? 'NONE',
    },
    execution: {
      ...input.execution,
      intentHash: input.intentHash,
      executed: executed,
      executedAt: executed ? (input.execution?.executedAt ?? decidedAt) : input.execution?.executedAt,
    },
    human,
    integrity: {
      contentHash: '',
    },
    ...(input.sequence != null ? { sequence: input.sequence } : {}),
    ...(input.prevReceiptHash !== undefined ? { prevReceiptHash: input.prevReceiptHash } : {}),
  })

  return {
    ...unsigned,
    signature: resolveSignature(unsigned, input),
  }
}

export type DecisionLike = {
  readonly action: AuthorizationReceiptAction
  readonly ruleId: string
  readonly reason: string
  readonly alertSeverity: AuthorizationAlertSeverity
  readonly matched: boolean
}

export function emitAuthorizationReceiptFromDecision(input: {
  readonly agentId: string
  readonly toolName: string
  readonly toolArgs: Record<string, unknown>
  readonly decision: DecisionLike
  readonly policyUri: string
  readonly policyName: string
  readonly policyVersion: string
  readonly policyContentHash: string
  readonly intentHash: string
  readonly agentRole?: string
  readonly principalId?: string
  readonly receiptId?: string
  readonly issuer?: string
  readonly issuerKeyId?: string
  readonly execution?: ExecutionBinding
  readonly human?: HumanAttestation
  readonly sequence?: number
  readonly prevReceiptHash?: string | null
  readonly signatureHex?: string
  readonly signer?: ReceiptSigner
  readonly demo?: boolean
  readonly argsRedactedAllowlist?: readonly string[]
  readonly includeArgsUnredacted?: boolean
  readonly redactArgs?: (toolArgs: Record<string, unknown>) => Record<string, unknown>
}): AuthorizationReceiptV1 {
  return emitAuthorizationReceipt({
    agentId: input.agentId,
    toolName: input.toolName,
    toolArgs: input.toolArgs,
    action: input.decision.action,
    ruleId: input.decision.ruleId,
    reason: input.decision.reason,
    alertSeverity: input.decision.alertSeverity,
    matched: input.decision.matched,
    policyUri: input.policyUri,
    policyName: input.policyName,
    policyVersion: input.policyVersion,
    policyContentHash: input.policyContentHash,
    intentHash: input.intentHash,
    agentRole: input.agentRole,
    principalId: input.principalId,
    receiptId: input.receiptId,
    issuer: input.issuer,
    issuerKeyId: input.issuerKeyId,
    execution: input.execution,
    human: input.human,
    sequence: input.sequence,
    prevReceiptHash: input.prevReceiptHash,
    signatureHex: input.signatureHex,
    signer: input.signer,
    demo: input.demo,
    argsRedactedAllowlist: input.argsRedactedAllowlist,
    includeArgsUnredacted: input.includeArgsUnredacted,
    redactArgs: input.redactArgs,
  })
}

/** Generate an ephemeral Ed25519 keypair for tests and demos. */
export function generateReceiptKeyPair(): { readonly publicKey: KeyObject; readonly privateKey: KeyObject } {
  return generateKeyPairSync('ed25519')
}

/**
 * In-memory issuer receipt log. Serializes appends and tracks the head so
 * concurrent callers do not fork `sequence` / `prevReceiptHash`.
 */
export class AuthorizationReceiptLog {
  private sequence = 0
  private prevReceiptHash: string | null = null
  private readonly receipts: AuthorizationReceiptV1[] = []

  constructor(
    private readonly options: {
      readonly issuer: string
      readonly issuerKeyId: string
      readonly signer: ReceiptSigner
    }
  ) {}

  get head(): { readonly sequence: number; readonly prevReceiptHash: string | null; readonly length: number } {
    return {
      sequence: this.sequence,
      prevReceiptHash: this.prevReceiptHash,
      length: this.receipts.length,
    }
  }

  list(): readonly AuthorizationReceiptV1[] {
    return [...this.receipts]
  }

  append(
    input: Omit<
      EmitAuthorizationReceiptInput,
      'issuer' | 'issuerKeyId' | 'signer' | 'signatureHex' | 'demo' | 'sequence' | 'prevReceiptHash'
    >
  ): AuthorizationReceiptV1 {
    const receipt = emitAuthorizationReceipt({
      ...input,
      issuer: this.options.issuer,
      issuerKeyId: this.options.issuerKeyId,
      signer: this.options.signer,
      sequence: this.sequence,
      prevReceiptHash: this.prevReceiptHash,
    })
    this.sequence += 1
    this.prevReceiptHash = receipt.integrity.contentHash
    this.receipts.push(receipt)
    return receipt
  }
}
