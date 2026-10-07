import type { KeyObject } from 'node:crypto'
import { exportPublicKey, generateEd25519, signObject } from './crypto.js'

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

export interface SignedDelegation extends DelegationPayload {
  readonly signature: string
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
}

export interface HumanApprovalPayload {
  readonly intent_hash: string
  readonly approver_id: string
  readonly approved_at: string
  readonly decision: 'APPROVE'
}

export interface HumanApproval extends HumanApprovalPayload {
  readonly signature: string
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
}

export function createIdentity(id: string): Identity {
  const keys = generateEd25519()
  return { id, publicKey: exportPublicKey(keys.publicKey), privateKey: keys.privateKey }
}

export function signDelegation(payload: DelegationPayload, issuer: Identity): SignedDelegation {
  if (payload.issuer !== issuer.id) {
    throw new Error('delegation issuer does not match signing identity')
  }
  return { ...payload, signature: signObject(payload, issuer.privateKey) }
}

export function signIntent(payload: IntentPayload, actor: Identity): SignedIntent {
  if (payload.actor !== actor.id) {
    throw new Error('intent actor does not match signing identity')
  }
  return { ...payload, signature: signObject(payload, actor.privateKey) }
}

export function signApproval(payload: HumanApprovalPayload, principal: Identity): HumanApproval {
  if (payload.approver_id !== principal.id) {
    throw new Error('approver does not match signing identity')
  }
  return { ...payload, signature: signObject(payload, principal.privateKey) }
}

export function unsignedDelegation(delegation: SignedDelegation): DelegationPayload {
  const { signature: _signature, ...payload } = delegation
  return payload
}

export function unsignedIntent(intent: SignedIntent): IntentPayload {
  const { signature: _signature, ...payload } = intent
  return payload
}
