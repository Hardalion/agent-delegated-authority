/**
 * Pending REQUIRE_HUMAN authorization context.
 *
 * Continuation must match this binding exactly. Caller-supplied policy objects are not
 * trusted for resume; the content hash and pin stored here are authoritative.
 *
 * Rows are keyed by `(actorId, nonce)`. Concurrent pending approvals per
 * `(principalId, agentId)` are capped (default 5).
 *
 * In-memory: process-local only. Multi-process deployments need a shared atomic store.
 */

import { AuthorityError } from './errors.js'
import { assertValidIdentity, assertValidNonce } from './runtime-validate.js'

export type PendingApprovalState = 'pending' | 'approved' | 'declined' | 'consumed' | 'expired'

export const DEFAULT_MAX_PENDING_APPROVALS = 5

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
  /** Principal expected to approve or deny. Set when the pending record is created. */
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

export interface PendingPutOptions {
  readonly maxPendingApprovals?: number
  readonly now?: Date
}

/**
 * What the authority path calls. A shared implementation must make `markApproved`
 * and `markDeclined` conditional writes from `pending`.
 */
export interface PendingStore {
  put(record: PendingAuthorization, options?: PendingPutOptions): MaybePromise<void>
  get(actorId: string, nonce: string): MaybePromise<PendingAuthorization | undefined>
  requireContinuation(input: PendingContinuation): MaybePromise<PendingAuthorization>
  markApproved(actorId: string, nonce: string, intentHash: string): MaybePromise<void>
  markDeclined(actorId: string, nonce: string, intentHash: string): MaybePromise<void>
  consume(actorId: string, nonce: string, intentHash: string): MaybePromise<void>
  countActivePending?(principalId: string, agentId: string, now?: Date): MaybePromise<number>
}

function storageKey(actorId: string, nonce: string): string {
  return `${assertValidIdentity(actorId, 'pending.agentId')}\0${assertValidNonce(nonce)}`
}

function isActivePending(record: PendingAuthorization, now: Date): boolean {
  if (record.approvalState !== 'pending') return false
  return Date.parse(record.expiry) > now.getTime()
}

export class PendingAuthorizationStore implements PendingStore {
  private readonly byKey = new Map<string, MutablePending>()

  constructor(private readonly defaults?: { readonly maxPendingApprovals?: number }) {}

  put(record: PendingAuthorization, options?: PendingPutOptions): void {
    const actorId = assertValidIdentity(record.agentId, 'pending.agentId')
    const nonce = assertValidNonce(record.nonce)
    const key = storageKey(actorId, nonce)
    const now = options?.now ?? new Date()
    const existing = this.byKey.get(key)
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

    const max =
      options?.maxPendingApprovals ??
      this.defaults?.maxPendingApprovals ??
      DEFAULT_MAX_PENDING_APPROVALS
    this.expireStale(record.principalId, record.agentId, now)
    const active = this.countActivePending(record.principalId, record.agentId, now)
    if (active >= max) {
      throw new AuthorityError('approval_queue_full', 'pending approval queue is full', true)
    }

    this.byKey.set(key, {
      ...record,
      nonce,
      agentId: actorId,
      approverId: assertValidIdentity(record.approverId, 'pending.approverId'),
      approvalState: 'pending',
    })
  }

  get(actorId: string, nonce: string): PendingAuthorization | undefined {
    const record = this.byKey.get(storageKey(actorId, nonce))
    return record ? { ...record } : undefined
  }

  countActivePending(principalId: string, agentId: string, now = new Date()): number {
    this.expireStale(principalId, agentId, now)
    let count = 0
    for (const record of this.byKey.values()) {
      if (
        record.principalId === principalId &&
        record.agentId === agentId &&
        isActivePending(record, now)
      ) {
        count += 1
      }
    }
    return count
  }

  private expireStale(principalId: string, agentId: string, now: Date): void {
    for (const record of this.byKey.values()) {
      if (
        record.principalId === principalId &&
        record.agentId === agentId &&
        record.approvalState === 'pending' &&
        Date.parse(record.expiry) <= now.getTime()
      ) {
        record.approvalState = 'expired'
      }
    }
  }

  /**
   * Load and verify the continuation matches the original REQUIRE_HUMAN context.
   * Does not mark approved; call markApproved / markDeclined after a valid decision.
   */
  requireContinuation(input: PendingContinuation): PendingAuthorization {
    const actorId = assertValidIdentity(input.agentId, 'pending.agentId')
    const nonce = assertValidNonce(input.nonce)
    const record = this.byKey.get(storageKey(actorId, nonce))
    if (!record) {
      throw new AuthorityError('approval', 'no pending authorization for this nonce', true)
    }
    if (record.approvalState === 'pending' && Date.parse(record.expiry) <= input.now.getTime()) {
      record.approvalState = 'expired'
    }
    if (record.approvalState !== 'pending') {
      throw new AuthorityError('approval', 'pending authorization is not open', true)
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

  markApproved(actorId: string, nonce: string, intentHash: string): void {
    const record = this.byKey.get(storageKey(actorId, nonce))
    if (!record || record.intentHash !== intentHash || record.approvalState !== 'pending') {
      throw new AuthorityError('approval', 'cannot mark approval on this pending context', true)
    }
    record.approvalState = 'approved'
  }

  markDeclined(actorId: string, nonce: string, intentHash: string): void {
    const record = this.byKey.get(storageKey(actorId, nonce))
    if (!record || record.intentHash !== intentHash || record.approvalState !== 'pending') {
      throw new AuthorityError('approval', 'cannot mark decline on this pending context', true)
    }
    record.approvalState = 'declined'
  }

  consume(actorId: string, nonce: string, intentHash: string): void {
    const record = this.byKey.get(storageKey(actorId, nonce))
    if (record && record.intentHash === intentHash) {
      record.approvalState = 'consumed'
    }
  }
}
