/**
 * Pending REQUIRE_HUMAN authorization context.
 *
 * Continuation must match this binding exactly. Caller-supplied policy objects are not
 * trusted for resume; the content hash and pin stored here are authoritative.
 *
 * In-memory: process-local only. Multi-process deployments need a shared atomic store.
 */

import { AuthorityError } from './errors.js'
import { assertValidIdentity, assertValidNonce } from './runtime-validate.js'

export type PendingApprovalState = 'pending' | 'approved' | 'consumed'

export interface PendingAuthorization {
  readonly intentHash: string
  readonly principalId: string
  readonly agentId: string
  readonly delegationChainHash: string
  readonly policyUri: string
  readonly policyContentHash: string
  readonly policyVersion: string
  readonly policyName: string
  readonly matchedRuleId: string
  readonly originalDecision: 'REQUIRE_HUMAN'
  readonly approvalState: PendingApprovalState
  readonly expiry: string
  readonly nonce: string
  /** Principal expected to approve. Set when the pending record is created. */
  readonly approverId: string
}

type MutablePending = {
  -readonly [K in keyof PendingAuthorization]: PendingAuthorization[K]
}

type MaybePromise<T> = T | Promise<T>

export interface PendingContinuation {
  readonly nonce: string
  readonly intentHash: string
  readonly principalId: string
  readonly agentId: string
  readonly delegationChainHash: string
  readonly policyUri: string
  readonly policyContentHash: string
  readonly policyVersion: string
  readonly policyName: string
  readonly approverId: string
  readonly now: Date
}

/**
 * What the authority path calls. A shared implementation must make `markApproved`
 * a conditional write from `pending` to `approved`. Single execution does not rest
 * on this store: the nonce claim is the gate.
 */
export interface PendingStore {
  put(record: PendingAuthorization): MaybePromise<void>
  get(nonce: string): MaybePromise<PendingAuthorization | undefined>
  requireContinuation(input: PendingContinuation): MaybePromise<PendingAuthorization>
  markApproved(nonce: string, intentHash: string): MaybePromise<void>
  consume(nonce: string, intentHash: string): MaybePromise<void>
}

export class PendingAuthorizationStore implements PendingStore {
  private readonly byNonce = new Map<string, MutablePending>()

  put(record: PendingAuthorization): void {
    const nonce = assertValidNonce(record.nonce)
    const existing = this.byNonce.get(nonce)
    if (existing) {
      if (
        existing.intentHash !== record.intentHash ||
        existing.approvalState !== 'pending' ||
        existing.policyContentHash !== record.policyContentHash
      ) {
        throw new AuthorityError('approval', 'pending authorization conflict for nonce', true)
      }
      return
    }
    this.byNonce.set(nonce, {
      ...record,
      nonce,
      approverId: assertValidIdentity(record.approverId, 'pending.approverId'),
      approvalState: 'pending',
    })
  }

  get(nonce: string): PendingAuthorization | undefined {
    const key = assertValidNonce(nonce)
    const record = this.byNonce.get(key)
    return record ? { ...record } : undefined
  }

  /**
   * Load and verify the continuation matches the original REQUIRE_HUMAN context.
   * Does not mark approved; call markApproved after a valid human approval.
   */
  requireContinuation(input: PendingContinuation): PendingAuthorization {
    const nonce = assertValidNonce(input.nonce)
    const record = this.byNonce.get(nonce)
    if (!record) {
      throw new AuthorityError('approval', 'no pending authorization for this nonce', true)
    }
    if (record.approvalState !== 'pending') {
      throw new AuthorityError('approval', 'pending authorization is not open', true)
    }
    if (Date.parse(record.expiry) <= input.now.getTime()) {
      throw new AuthorityError('approval', 'pending authorization expired', true)
    }
    const checks: Array<[unknown, unknown, string]> = [
      [record.intentHash, input.intentHash, 'intent hash'],
      [record.principalId, input.principalId, 'principal'],
      [record.agentId, input.agentId, 'agent'],
      [record.delegationChainHash, input.delegationChainHash, 'delegation chain'],
      [record.policyUri, input.policyUri, 'policy URI'],
      [record.policyContentHash, input.policyContentHash, 'policy content hash'],
      [record.policyVersion, input.policyVersion, 'policy version'],
      [record.policyName, input.policyName, 'policy name'],
      [record.approverId, input.approverId, 'approver'],
      [record.originalDecision, 'REQUIRE_HUMAN', 'original decision'],
    ]
    for (const [left, right, label] of checks) {
      if (left !== right) {
        throw new AuthorityError('approval', `continuation ${label} does not match pending context`, true)
      }
    }
    return { ...record }
  }

  markApproved(nonce: string, intentHash: string): void {
    const key = assertValidNonce(nonce)
    const record = this.byNonce.get(key)
    if (!record || record.intentHash !== intentHash || record.approvalState !== 'pending') {
      throw new AuthorityError('approval', 'cannot mark approval on this pending context', true)
    }
    record.approvalState = 'approved'
  }

  consume(nonce: string, intentHash: string): void {
    const key = assertValidNonce(nonce)
    const record = this.byNonce.get(key)
    if (record && record.intentHash === intentHash) {
      record.approvalState = 'consumed'
    }
  }
}
