/**
 * Build an Authorization Receipt from a policy decision.
 * Callers replace the placeholder with a signature over canonical unsigned JSON.
 * The reference profile is Ed25519, hex, as documented in spec/authorization-receipt.md.
 */

import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import {
  AUTHORIZATION_RECEIPT_KIND,
  buildUnsignedAuthorizationReceipt,
  normalizeAuthorizationOutcome,
  type AuthorizationAlertSeverity,
  type AuthorizationReceiptAction,
  type AuthorizationReceiptV1,
  type AuthorizationActorType,
  type ExecutionBinding,
  type AuthorityBinding,
  type HumanAttestation,
} from './authorization-receipt.js'

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
  /** When set, used as signature (must be 128 hex chars). Default: demo placeholder. */
  readonly signatureHex?: string
}

const DEMO_SIGNATURE = 'ab'.repeat(64)

function sha256HexUtf8(utf8: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(utf8)))
}

/** Stable args hash for receipt intent (canonical key order). */
export function hashToolArgs(toolArgs: Record<string, unknown>): string {
  return sha256HexUtf8(JSON.stringify(sortKeys(toolArgs)))
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys)
  if (value != null && typeof value === 'object') {
    const record = value as Record<string, unknown>
    const sorted: Record<string, unknown> = {}
    for (const key of Object.keys(record).sort()) {
      sorted[key] = sortKeys(record[key])
    }
    return sorted
  }
  return value
}

function copyArgs(toolArgs: Record<string, unknown>): Record<string, unknown> {
  return { ...toolArgs }
}

export function emitAuthorizationReceipt(
  input: EmitAuthorizationReceiptInput
): AuthorizationReceiptV1 {
  const decidedAt = input.decidedAt ?? new Date().toISOString()
  const receiptId =
    input.receiptId ?? `rcpt_${sha256HexUtf8(`${input.toolName}:${decidedAt}`).slice(0, 24)}`

  const outcome = normalizeAuthorizationOutcome(input.action)

  const executed = input.execution?.executed === true
  const human =
    input.human ??
    (input.action === 'REQUIRE_HUMAN'
      ? { required: true as const, status: 'pending' as const }
      : undefined)

  const unsigned = buildUnsignedAuthorizationReceipt({
    v: 1,
    kind: AUTHORIZATION_RECEIPT_KIND,
    receiptId,
    issuer: input.issuer ?? 'reference-runtime',
    issuerKeyId: input.issuerKeyId ?? 'ed25519:demo-key-1',
    decidedAt,
    intent: {
      toolName: input.toolName,
      argsHash: hashToolArgs(input.toolArgs),
      argsRedacted: copyArgs(input.toolArgs),
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
  })

  return {
    ...unsigned,
    signature: input.signatureHex ?? DEMO_SIGNATURE,
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
  readonly issuerKeyId?: string
  readonly execution?: ExecutionBinding
  readonly human?: HumanAttestation
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
    issuerKeyId: input.issuerKeyId,
    execution: input.execution,
    human: input.human,
  })
}
