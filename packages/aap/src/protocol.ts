import type { KeyObject } from 'node:crypto'
import { exportPublicKey, generateEd25519, publicKeyFingerprint, signObject } from './crypto.js'
import { assertValidIdentity } from './runtime-validate.js'
import {
  ADAP_SIGNED_VERSION,
  signEnvelope,
  type SignedEnvelope,
  type SignedObjectType,
} from './signed-object.js'

export type Decision = 'ALLOW' | 'REQUIRE_HUMAN' | 'BLOCK'

export interface Capability {
  readonly action: string
  readonly target?: string
  /** When false, the subject may use the capability and must not pass it on. */
  readonly delegable?: boolean
}

export type ConstraintValue = string | number | boolean

export interface Constraints {
  readonly [key: string]: ConstraintValue
}

export interface DelegationPayload {
  readonly delegation_id: string
  readonly issuer: string
  readonly subject: string
  readonly capabilities: readonly Capability[]
  readonly constraints: Constraints
  readonly issued_at: string
  readonly expires_at: string
  readonly parent_delegation_id?: string
}

/**
 * Flat signed delegation. Legacy objects omit adap/typ/alg/kid.
 * Versioned objects include those fields; the signature covers the envelope.
 */
export interface SignedDelegation extends DelegationPayload {
  readonly signature: string
  readonly adap?: typeof ADAP_SIGNED_VERSION
  readonly typ?: 'delegation'
  readonly alg?: 'Ed25519'
  readonly kid?: string
}

export interface IntentPayload {
  readonly intent_id: string
  readonly actor: string
  readonly delegation_chain: readonly string[]
  readonly action: string
  readonly target: string
  readonly parameters: Readonly<Record<string, unknown>>
  readonly nonce: string
  readonly issued_at: string
  readonly expires_at: string
}

export interface SignedIntent extends IntentPayload {
  readonly signature: string
  readonly adap?: typeof ADAP_SIGNED_VERSION
  readonly typ?: 'intent'
  readonly alg?: 'Ed25519'
  readonly kid?: string
}

/**
 * Human approval payload. Bound to the exact authorization context that produced
 * REQUIRE_HUMAN — not merely an intent hash.
 */
export interface HumanApprovalPayload {
  readonly intent_hash: string
  readonly approver_id: string
  readonly approved_at: string
  readonly decision: 'APPROVE' | 'DENY'
  readonly agent_id: string
  readonly delegation_chain_hash: string
  readonly policy_content_hash: string
  readonly matched_rule_id?: string
}

export interface HumanApproval extends HumanApprovalPayload {
  readonly signature: string
  readonly adap?: typeof ADAP_SIGNED_VERSION
  readonly typ?: 'approval'
  readonly alg?: 'Ed25519'
  readonly kid?: string
}

export interface DecisionRecord {
  readonly decision: Decision
  readonly intent_hash: string
  readonly delegation_hash: string
  readonly policy_hash: string
  readonly evaluated_at: string
}

export interface Identity {
  readonly id: string
  readonly publicKey: string
  readonly privateKey: KeyObject
  /** Default key id for versioned signatures. */
  readonly kid: string
}

export type SignProfile = 'legacy' | '0.2'

export function createIdentity(id: string): Identity {
  assertValidIdentity(id, 'identity.id')
  const keys = generateEd25519()
  const publicKey = exportPublicKey(keys.publicKey)
  return {
    id,
    publicKey,
    privateKey: keys.privateKey,
    kid: publicKeyFingerprint(publicKey),
  }
}

function flattenEnvelope<T extends object>(
  envelope: SignedEnvelope<T>,
  typ: SignedObjectType
): T & {
  readonly signature: string
  readonly adap: typeof ADAP_SIGNED_VERSION
  readonly typ: SignedObjectType
  readonly alg: 'Ed25519'
  readonly kid: string
} {
  return {
    ...envelope.payload,
    adap: envelope.adap,
    typ,
    alg: envelope.alg,
    kid: envelope.kid,
    signature: envelope.signature,
  }
}

export function signDelegation(
  payload: DelegationPayload,
  issuer: Identity,
  options?: { readonly profile?: SignProfile; readonly kid?: string }
): SignedDelegation {
  if (payload.issuer !== issuer.id) {
    throw new Error('delegation issuer does not match signing identity')
  }
  const profile = options?.profile ?? 'legacy'
  if (profile === 'legacy') {
    return { ...payload, signature: signObject(payload, issuer.privateKey) }
  }
  const kid = options?.kid ?? issuer.kid
  const envelope = signEnvelope(
    { typ: 'delegation', kid, payload },
    issuer.privateKey
  )
  return flattenEnvelope(envelope, 'delegation') as SignedDelegation
}

export function signIntent(
  payload: IntentPayload,
  actor: Identity,
  options?: { readonly profile?: SignProfile; readonly kid?: string }
): SignedIntent {
  if (payload.actor !== actor.id) {
    throw new Error('intent actor does not match signing identity')
  }
  const profile = options?.profile ?? 'legacy'
  if (profile === 'legacy') {
    return { ...payload, signature: signObject(payload, actor.privateKey) }
  }
  const kid = options?.kid ?? actor.kid
  const envelope = signEnvelope({ typ: 'intent', kid, payload }, actor.privateKey)
  return flattenEnvelope(envelope, 'intent') as SignedIntent
}

export function signApproval(
  payload: HumanApprovalPayload,
  principal: Identity,
  options?: { readonly profile?: SignProfile; readonly kid?: string }
): HumanApproval {
  if (payload.approver_id !== principal.id) {
    throw new Error('approver does not match signing identity')
  }
  if (payload.decision !== 'APPROVE' && payload.decision !== 'DENY') {
    throw new Error('approval decision must be APPROVE or DENY')
  }
  const profile = options?.profile ?? 'legacy'
  if (profile === 'legacy') {
    return { ...payload, signature: signObject(payload, principal.privateKey) }
  }
  const kid = options?.kid ?? principal.kid
  const envelope = signEnvelope({ typ: 'approval', kid, payload }, principal.privateKey)
  return flattenEnvelope(envelope, 'approval') as HumanApproval
}

export function unsignedDelegation(delegation: SignedDelegation): DelegationPayload {
  const {
    signature: _signature,
    adap: _adap,
    typ: _typ,
    alg: _alg,
    kid: _kid,
    ...payload
  } = delegation
  return payload
}

export function unsignedIntent(intent: SignedIntent): IntentPayload {
  const {
    signature: _signature,
    adap: _adap,
    typ: _typ,
    alg: _alg,
    kid: _kid,
    ...payload
  } = intent
  return payload
}

export function unsignedApproval(approval: HumanApproval): HumanApprovalPayload {
  const {
    signature: _signature,
    adap: _adap,
    typ: _typ,
    alg: _alg,
    kid: _kid,
    ...payload
  } = approval
  return payload
}

export function isVersionedSignedDelegation(value: SignedDelegation): boolean {
  return value.adap === ADAP_SIGNED_VERSION && value.typ === 'delegation' && value.kid != null
}

export function isVersionedSignedIntent(value: SignedIntent): boolean {
  return value.adap === ADAP_SIGNED_VERSION && value.typ === 'intent' && value.kid != null
}

export function isVersionedHumanApproval(value: HumanApproval): boolean {
  return value.adap === ADAP_SIGNED_VERSION && value.typ === 'approval' && value.kid != null
}
