/**
 * Authorization Receipt for ADAP v0.1. Portable record of what was authorized and what the runtime reported.
 * Normative: ../../spec/authorization-receipt.md
 */

import { createPublicKey, verify as verifyEd25519 } from 'node:crypto'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex } from '@noble/hashes/utils.js'

export const AUTHORIZATION_RECEIPT_FORMAT_VERSION = 1 as const
export const AUTHORIZATION_RECEIPT_KIND = 'adap.receipt' as const

export type AuthorizationReceiptAction =
  | 'ALLOW'
  | 'BLOCK'
  | 'REQUIRE_HUMAN'
  | 'DEFER'
  | 'SIMULATE'

export type AuthorizationReceiptOutcome =
  | 'allowed'
  | 'rejected'
  | 'deferred'
  | 'pending_human'

export type AuthorizationAlertSeverity = 'LOW' | 'MEDIUM' | 'CRITICAL'

export type AuthorizationFailureMode =
  | 'NONE'
  | 'RULE_VIOLATION'
  | 'MAPPING_FAILED'
  | 'SYSTEM_ERROR'

export type AuthorizationActorType = 'non_human_agent' | 'human' | 'system'

export type HumanAttestationStatus = 'pending' | 'approved' | 'declined' | 'escalated'

export interface ActionIntent {
  readonly toolName: string
  readonly argsHash: string
  readonly argsRedacted?: Record<string, unknown>
  readonly actionClass?: string
}

export interface AgentIdentity {
  readonly agentId: string
  readonly actorType: AuthorizationActorType
  readonly agentRole?: string
  readonly principalId?: string
  /** Subjects only, parent to child. When `authority` is present, each entry must equal `authority.chain[i].subject`. */
  readonly delegationChain?: readonly string[]
}

/** One presented delegation, bound by the hash of its unsigned body. */
export interface AuthorityLink {
  readonly delegationId: string
  readonly subject: string
  readonly hash: string
}

/**
 * The authority chain the runtime presented.
 * Each `hash` is the reference-profile hash of that unsigned delegation.
 * The receipt signature covers these hashes. It does not, by itself, prove an external system performed the action.
 */
export interface AuthorityBinding {
  readonly principalId: string
  readonly chain: readonly AuthorityLink[]
}

export interface PolicyRef {
  readonly policyUri: string
  readonly policyName: string
  readonly policyVersion: string
  readonly ruleId: string
  /** SHA-256 of the policy document in canonical JSON. Not a hash of one file's raw bytes. */
  readonly contentHash: string
}

export interface AuthorizationDecision {
  readonly action: AuthorizationReceiptAction
  readonly outcome: AuthorizationReceiptOutcome
  readonly reason: string
  readonly alertSeverity: AuthorizationAlertSeverity
  readonly matched: boolean
  readonly failureMode?: AuthorizationFailureMode
}

export type ExecutionOutcome = 'not_dispatched' | 'returned' | 'unknown'

export interface ExecutionBinding {
  readonly targetSystem?: string
  readonly executed?: boolean
  readonly executedAt?: string
  /**
   * What this runtime knows. `unknown` means the executor was entered and did not
   * return. `executed: false` in that case is not a claim that no side effect occurred.
   * Absent on receipts issued before this field existed.
   */
  readonly outcome?: ExecutionOutcome
  /** Hash of the unsigned intent presented at the execution boundary. */
  readonly intentHash: string
}

export interface HumanAttestation {
  readonly required: boolean
  readonly status: HumanAttestationStatus
  readonly approverId?: string
  readonly decidedAt?: string
  readonly reason?: string
  readonly policyRef?: string
}

export interface ReceiptIntegrity {
  readonly contentHash: string
}

export interface AuthorizationReceiptV1 {
  readonly v: typeof AUTHORIZATION_RECEIPT_FORMAT_VERSION
  readonly kind: typeof AUTHORIZATION_RECEIPT_KIND
  readonly receiptId: string
  readonly issuer: string
  readonly issuerKeyId: string
  readonly decidedAt: string
  readonly intent: ActionIntent
  readonly identity: AgentIdentity
  readonly authority?: AuthorityBinding
  readonly policy: PolicyRef
  readonly decision: AuthorizationDecision
  readonly integrity: ReceiptIntegrity
  readonly signature: string
  readonly execution?: ExecutionBinding
  readonly human?: HumanAttestation
  /**
   * Optional hash-chain fields. When present, `prevReceiptHash` is the SHA-256
   * content hash of the prior receipt in the issuer's log (`null` for the first).
   * Covered by `integrity.contentHash` and `signature`.
   */
  readonly sequence?: number
  readonly prevReceiptHash?: string | null
  /** Implementation-specific metadata. Not interpreted by a conforming verifier. */
  readonly extensions?: Readonly<Record<string, unknown>>
}

export type UnsignedAuthorizationReceipt = Omit<AuthorizationReceiptV1, 'signature'>

export interface VerifyAuthorizationReceiptResult {
  readonly valid: boolean
  readonly contentHashOk: boolean
  readonly structureOk: boolean
  readonly errors: readonly string[]
  readonly contentHash?: string
}

const HEX64 = /^[0-9a-f]{64}$/
const HEX_SIG = /^[0-9a-f]{128}$/i
const ISO_DATETIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/

const ACTIONS = new Set<AuthorizationReceiptAction>([
  'ALLOW',
  'BLOCK',
  'REQUIRE_HUMAN',
  'DEFER',
  'SIMULATE',
])
const OUTCOMES = new Set<AuthorizationReceiptOutcome>([
  'allowed',
  'rejected',
  'deferred',
  'pending_human',
])
const SEVERITIES = new Set<AuthorizationAlertSeverity>(['LOW', 'MEDIUM', 'CRITICAL'])
const ACTORS = new Set<AuthorizationActorType>(['non_human_agent', 'human', 'system'])
const HUMAN_STATUS = new Set<HumanAttestationStatus>([
  'pending',
  'approved',
  'declined',
  'escalated',
])

/** Stable canonical JSON (sorted object keys, recursively). */
export function canonicalReceiptJson(value: unknown): string {
  return JSON.stringify(sortKeys(value))
}

const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys)
  if (value != null && typeof value === 'object') {
    const proto = Object.getPrototypeOf(value)
    if (proto !== Object.prototype && proto !== null) {
      throw new Error('canonicalReceiptJson rejects objects with a non-plain prototype')
    }
    const record = value as Record<string, unknown>
    const sorted: Record<string, unknown> = Object.create(null)
    for (const key of Object.keys(record).sort()) {
      if (DANGEROUS_KEYS.has(key)) {
        throw new Error(`canonicalReceiptJson rejects dangerous key: ${key}`)
      }
      sorted[key] = sortKeys(record[key])
    }
    return { ...sorted }
  }
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new Error('canonicalReceiptJson rejects non-finite numbers')
  }
  return value
}

function sha256Hex(utf8: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(utf8)))
}

/**
 * Content hash per spec §5: unsigned body with integrity.contentHash placeholder "".
 */
export function contentHashOfUnsignedReceipt(
  unsigned: Omit<UnsignedAuthorizationReceipt, 'integrity'> & {
    integrity: Omit<ReceiptIntegrity, 'contentHash'> & { contentHash?: string }
  }
): string {
  const withPlaceholder: UnsignedAuthorizationReceipt = {
    ...unsigned,
    integrity: {
      ...unsigned.integrity,
      contentHash: '',
    },
  }
  return sha256Hex(canonicalReceiptJson(withPlaceholder))
}

export function buildUnsignedAuthorizationReceipt(
  input: Omit<UnsignedAuthorizationReceipt, 'integrity'> & {
    integrity: Omit<ReceiptIntegrity, 'contentHash'> & { contentHash?: string }
  }
): UnsignedAuthorizationReceipt {
  const contentHash = contentHashOfUnsignedReceipt(input)
  return {
    ...input,
    integrity: {
      ...input.integrity,
      contentHash,
    },
  }
}

function requireString(
  errors: string[],
  path: string,
  value: unknown,
  max: number
): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > max) {
    errors.push(`${path} must be a non-empty string ≤${max}`)
    return false
  }
  return true
}

function validateStructure(receipt: unknown): string[] {
  const errors: string[] = []
  if (receipt == null || typeof receipt !== 'object') {
    return ['receipt must be an object']
  }
  const r = receipt as Record<string, unknown>

  if (r.v !== AUTHORIZATION_RECEIPT_FORMAT_VERSION) {
    errors.push(`v must be ${AUTHORIZATION_RECEIPT_FORMAT_VERSION}`)
  }
  if (r.kind !== AUTHORIZATION_RECEIPT_KIND) {
    errors.push(`kind must be ${AUTHORIZATION_RECEIPT_KIND}`)
  }
  requireString(errors, 'receiptId', r.receiptId, 128)
  requireString(errors, 'issuer', r.issuer, 256)
  requireString(errors, 'issuerKeyId', r.issuerKeyId, 256)
  if (!requireString(errors, 'decidedAt', r.decidedAt, 64) || !ISO_DATETIME.test(String(r.decidedAt))) {
    if (typeof r.decidedAt === 'string') errors.push('decidedAt must be ISO-8601 UTC')
  }
  if (!requireString(errors, 'signature', r.signature, 256) || !HEX_SIG.test(String(r.signature))) {
    if (typeof r.signature === 'string' && !HEX_SIG.test(r.signature)) {
      errors.push('signature must be 64-byte Ed25519 hex (128 hex chars)')
    }
  }

  const intent = r.intent as Record<string, unknown> | undefined
  if (!intent || typeof intent !== 'object') {
    errors.push('intent is required')
  } else {
    requireString(errors, 'intent.toolName', intent.toolName, 256)
    if (!requireString(errors, 'intent.argsHash', intent.argsHash, 64) || !HEX64.test(String(intent.argsHash))) {
      if (typeof intent.argsHash === 'string') errors.push('intent.argsHash must be 64 hex chars')
    }
  }

  const identity = r.identity as Record<string, unknown> | undefined
  if (!identity || typeof identity !== 'object') {
    errors.push('identity is required')
  } else {
    requireString(errors, 'identity.agentId', identity.agentId, 128)
    if (!ACTORS.has(identity.actorType as AuthorizationActorType)) {
      errors.push('identity.actorType invalid')
    }
  }

  if (r.authority != null) {
    const authority = r.authority as Record<string, unknown>
    if (authority == null || typeof authority !== 'object' || Array.isArray(authority)) {
      errors.push('authority must be an object')
    } else {
    requireString(errors, 'authority.principalId', authority.principalId, 128)
    const chain = authority.chain
    if (!Array.isArray(chain) || chain.length === 0) {
      errors.push('authority.chain must be a non-empty array')
    } else {
      chain.forEach((link, index) => {
        const item = link as Record<string, unknown>
        if (item == null || typeof item !== 'object') {
          errors.push(`authority.chain[${index}] must be an object`)
          return
        }
        requireString(errors, `authority.chain[${index}].delegationId`, item.delegationId, 128)
        requireString(errors, `authority.chain[${index}].subject`, item.subject, 128)
        if (!requireString(errors, `authority.chain[${index}].hash`, item.hash, 64) || !HEX64.test(String(item.hash))) {
          if (typeof item.hash === 'string') errors.push(`authority.chain[${index}].hash must be 64 hex chars`)
        }
      })
      const subjects = identity?.delegationChain
      if (Array.isArray(subjects)) {
        if (subjects.length !== chain.length) {
          errors.push('identity.delegationChain length must match authority.chain')
        } else {
          chain.forEach((link, index) => {
            const item = link as Record<string, unknown>
            if (item.subject !== subjects[index]) {
              errors.push(`identity.delegationChain[${index}] must equal authority.chain subject`)
            }
          })
        }
      }
      if (
        identity?.principalId != null &&
        authority.principalId != null &&
        identity.principalId !== authority.principalId
      ) {
        errors.push('identity.principalId must equal authority.principalId')
      }
    }
    }
  }

  const policy = r.policy as Record<string, unknown> | undefined
  if (!policy || typeof policy !== 'object') {
    errors.push('policy is required')
  } else {
    requireString(errors, 'policy.policyUri', policy.policyUri, 512)
    requireString(errors, 'policy.policyName', policy.policyName, 256)
    requireString(errors, 'policy.policyVersion', policy.policyVersion, 64)
    requireString(errors, 'policy.ruleId', policy.ruleId, 256)
    if (
      !requireString(errors, 'policy.contentHash', policy.contentHash, 64) ||
      !HEX64.test(String(policy.contentHash))
    ) {
      if (typeof policy.contentHash === 'string') {
        errors.push('policy.contentHash must be 64 hex chars')
      }
    }
  }

  const decision = r.decision as Record<string, unknown> | undefined
  if (!decision || typeof decision !== 'object') {
    errors.push('decision is required')
  } else {
    if (!ACTIONS.has(decision.action as AuthorizationReceiptAction)) {
      errors.push('decision.action invalid')
    }
    if (!OUTCOMES.has(decision.outcome as AuthorizationReceiptOutcome)) {
      errors.push('decision.outcome invalid')
    }
    requireString(errors, 'decision.reason', decision.reason, 2000)
    if (!SEVERITIES.has(decision.alertSeverity as AuthorizationAlertSeverity)) {
      errors.push('decision.alertSeverity invalid')
    }
    if (typeof decision.matched !== 'boolean') {
      errors.push('decision.matched must be boolean')
    }
  }

  const integrity = r.integrity as Record<string, unknown> | undefined
  if (!integrity || typeof integrity !== 'object') {
    errors.push('integrity is required')
  } else if (
    !requireString(errors, 'integrity.contentHash', integrity.contentHash, 64) ||
    !HEX64.test(String(integrity.contentHash))
  ) {
    if (typeof integrity.contentHash === 'string') {
      errors.push('integrity.contentHash must be 64 hex chars')
    }
  }

  if (r.execution != null) {
    const execution = r.execution as Record<string, unknown>
    if (
      !requireString(errors, 'execution.intentHash', execution.intentHash, 64) ||
      !HEX64.test(String(execution.intentHash))
    ) {
      if (typeof execution.intentHash === 'string') {
        errors.push('execution.intentHash must be 64 hex chars')
      }
    }
  }

  if (r.human != null) {
    const human = r.human as Record<string, unknown>
    if (typeof human.required !== 'boolean') errors.push('human.required must be boolean')
    if (!HUMAN_STATUS.has(human.status as HumanAttestationStatus)) {
      errors.push('human.status invalid')
    }
  }

  if (r.sequence != null) {
    if (typeof r.sequence !== 'number' || !Number.isInteger(r.sequence) || r.sequence < 0) {
      errors.push('sequence must be a non-negative integer')
    }
  }
  if (r.prevReceiptHash != null) {
    if (typeof r.prevReceiptHash !== 'string' || !HEX64.test(r.prevReceiptHash)) {
      errors.push('prevReceiptHash must be 64 hex chars or null')
    }
  }

  errors.push(...validateSemanticInvariants(r))

  return errors
}

/**
 * Cross-field semantic invariants. A structurally well-formed receipt can still be
 * contradictory (e.g. BLOCK + outcome allowed + executed true).
 */
function validateSemanticInvariants(r: Record<string, unknown>): string[] {
  const errors: string[] = []
  const decision = r.decision as Record<string, unknown> | undefined
  const execution = r.execution as Record<string, unknown> | undefined
  const human = r.human as Record<string, unknown> | undefined
  if (!decision || typeof decision !== 'object') return errors

  const action = decision.action as AuthorizationReceiptAction
  const outcome = decision.outcome as AuthorizationReceiptOutcome
  const expectedOutcome = normalizeAuthorizationOutcomeSafe(action)
  if (expectedOutcome && outcome !== expectedOutcome) {
    errors.push(`decision.outcome '${outcome}' is inconsistent with action '${action}'`)
  }

  const executed = execution?.executed === true
  if (executed) {
    if (action !== 'ALLOW') {
      errors.push('execution.executed=true is only valid with decision.action=ALLOW')
    }
    if (outcome === 'rejected' || outcome === 'pending_human' || outcome === 'deferred') {
      errors.push('execution.executed=true is inconsistent with a non-allowed outcome')
    }
    if (action === 'REQUIRE_HUMAN' && human?.status !== 'approved') {
      errors.push('REQUIRE_HUMAN execution requires human.status=approved')
    }
  }

  if (action === 'BLOCK' && executed) {
    errors.push('BLOCK receipts must not claim execution')
  }
  if (action === 'REQUIRE_HUMAN') {
    if (executed) errors.push('unresolved REQUIRE_HUMAN must not claim execution')
    if (human != null && human.required !== true) {
      errors.push('REQUIRE_HUMAN receipts must set human.required=true')
    }
    if (human?.status === 'approved' && outcome === 'pending_human' && !executed) {
      // Approved-but-not-yet-executed pause receipts are unusual; allow pending_human only when not approved.
    }
    if (!human) {
      errors.push('REQUIRE_HUMAN receipts must include human attestation')
    }
  }
  if (action === 'ALLOW' && human?.status === 'pending') {
    errors.push('ALLOW receipts must not claim human.status=pending')
  }
  if (action === 'DEFER' && executed) {
    errors.push('DEFER receipts must not claim execution')
  }
  if (action === 'SIMULATE' && executed) {
    errors.push('SIMULATE receipts must not claim live execution')
  }

  if (execution != null && typeof execution.executedAt === 'string' && execution.executed !== true) {
    errors.push('execution.executedAt requires execution.executed=true')
  }

  const knowledge = execution?.outcome
  if (knowledge != null && knowledge !== 'not_dispatched' && knowledge !== 'returned' && knowledge !== 'unknown') {
    errors.push('execution.outcome is invalid')
  }
  if (knowledge === 'unknown') {
    if (executed) errors.push('execution.outcome=unknown must not claim executed=true')
    if (action !== 'ALLOW') {
      errors.push('execution.outcome=unknown is only valid after an authorized dispatch')
    }
  }
  if (knowledge === 'not_dispatched' && executed) {
    errors.push('execution.outcome=not_dispatched must not claim executed=true')
  }
  if (knowledge === 'returned' && !executed) {
    errors.push('execution.outcome=returned requires executed=true')
  }

  return errors
}

function normalizeAuthorizationOutcomeSafe(
  action: AuthorizationReceiptAction
): AuthorizationReceiptOutcome | undefined {
  switch (action) {
    case 'ALLOW':
      return 'allowed'
    case 'BLOCK':
      return 'rejected'
    case 'REQUIRE_HUMAN':
      return 'pending_human'
    case 'DEFER':
      return 'deferred'
    case 'SIMULATE':
      return 'allowed'
    default:
      return undefined
  }
}

/** Ed25519 check of `signature` over the unsigned receipt. The argument is the issuer SPKI public key, base64url. */
export function verifyReceiptSignature(receipt: AuthorizationReceiptV1, publicKeySpki: string): boolean {
  const { signature, ...unsigned } = receipt
  if (!/^[0-9a-f]{128}$/i.test(signature)) return false
  const key = createPublicKey({
    key: Buffer.from(publicKeySpki.trim(), 'base64url'),
    type: 'spki',
    format: 'der',
  })
  return verifyEd25519(null, Buffer.from(canonicalReceiptJson(unsigned)), key, Buffer.from(signature, 'hex'))
}

/**
 * Offline structural + content-hash verification (no network).
 * Ed25519 verification is `verifyReceiptSignature`, and it requires the issuer public key.
 */
export function verifyAuthorizationReceipt(receipt: unknown): VerifyAuthorizationReceiptResult {
  const structureErrors = validateStructure(receipt)
  if (structureErrors.length > 0) {
    return {
      valid: false,
      contentHashOk: false,
      structureOk: false,
      errors: structureErrors,
    }
  }

  const r = receipt as AuthorizationReceiptV1
  const { signature: _sig, ...unsigned } = r
  const expected = contentHashOfUnsignedReceipt(unsigned)
  const contentHashOk = expected === r.integrity.contentHash
  const errors: string[] = []
  if (!contentHashOk) {
    errors.push('integrity.contentHash mismatch')
  }

  return {
    valid: contentHashOk,
    contentHashOk,
    structureOk: true,
    errors,
    contentHash: expected,
  }
}

export interface VerifyReceiptChainResult {
  readonly valid: boolean
  readonly errors: readonly string[]
}

/**
 * Walk an ordered receipt log. Each receipt must verify on its own, carry `sequence`
 * and `prevReceiptHash`, come from the same issuer, increase `sequence` by one, and
 * name the previous receipt's `integrity.contentHash`.
 *
 * Detects omission, insertion, and reordering inside the presented segment.
 * It cannot detect a dropped tail: the verifier needs the expected head from elsewhere.
 * Signatures are checked only when `publicKeySpki` is supplied.
 */
export function verifyReceiptChain(
  receipts: readonly AuthorizationReceiptV1[],
  options?: {
    /** Content hash the first receipt must link to. Default `null` (start of log). */
    readonly prevReceiptHash?: string | null
    readonly publicKeySpki?: string
  }
): VerifyReceiptChainResult {
  const errors: string[] = []
  if (receipts.length === 0) return { valid: false, errors: ['chain is empty'] }

  let expectedPrev: string | null = options?.prevReceiptHash ?? null
  let expectedSequence: number | undefined
  const issuer = receipts[0]?.issuerKeyId

  receipts.forEach((receipt, index) => {
    const single = verifyAuthorizationReceipt(receipt)
    if (!single.valid) errors.push(`receipt[${index}]: ${single.errors.join('; ')}`)
    if (options?.publicKeySpki && !verifyReceiptSignature(receipt, options.publicKeySpki)) {
      errors.push(`receipt[${index}]: ed25519 signature invalid`)
    }
    if (receipt.issuerKeyId !== issuer) errors.push(`receipt[${index}]: issuerKeyId differs from chain issuer`)
    if (typeof receipt.sequence !== 'number') {
      errors.push(`receipt[${index}]: sequence missing`)
    } else {
      if (expectedSequence !== undefined && receipt.sequence !== expectedSequence) {
        errors.push(`receipt[${index}]: sequence ${receipt.sequence}, expected ${expectedSequence}`)
      }
      expectedSequence = receipt.sequence + 1
    }
    if (receipt.prevReceiptHash === undefined) {
      errors.push(`receipt[${index}]: prevReceiptHash missing`)
    } else if (receipt.prevReceiptHash !== expectedPrev) {
      errors.push(`receipt[${index}]: prevReceiptHash does not link to the previous receipt`)
    }
    expectedPrev = receipt.integrity.contentHash
  })

  return { valid: errors.length === 0, errors }
}

/** Map a decision verb and enforcement flags to a receipt outcome. */
export function normalizeAuthorizationOutcome(
  action: AuthorizationReceiptAction
): AuthorizationReceiptOutcome {
  switch (action) {
    case 'ALLOW':
      return 'allowed'
    case 'BLOCK':
      return 'rejected'
    case 'REQUIRE_HUMAN':
      return 'pending_human'
    case 'DEFER':
      return 'deferred'
    case 'SIMULATE':
      return 'allowed'
    default: {
      const _exhaustive: never = action
      return _exhaustive
    }
  }
}
