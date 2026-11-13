import { randomBytes } from 'node:crypto'
import { AuthorityError } from './errors.js'
import { assertValidIdentity, assertValidNonce } from './runtime-validate.js'

/**
 * Nonce state machine for single-use intents.
 *
 * Rows are keyed by `(actorId, nonce)`. The actor ID comes from the
 * cryptographically verified intent, never from an unauthenticated header.
 *
 * - `pending` — reserved for human approval, or exclusively claimed for execution
 * - `consumed` — terminal success (or a terminal BLOCK that retires the nonce)
 * - `failed` — executor threw; nonce is spent and cannot be retried with the same intent
 *
 * Every transition is a read followed by a compare-and-swap on the record version.
 * A lost race throws `nonce_in_flight_or_used` and does not execute.
 *
 * Newly generated nonces MUST contain at least 128 bits of CSPRNG entropy
 * (`generateSecureNonce`). Deterministic fixtures are test-only.
 */
export type NonceStatus = 'pending' | 'consumed' | 'failed'

export interface NonceRecord {
  readonly status: NonceStatus
  readonly intentHash: string
  readonly inFlight: boolean
  readonly actorId: string
}

export interface VersionedNonceRecord {
  readonly version: number
  readonly record: NonceRecord
}

/** Composite ledger key. */
export function nonceStorageKey(actorId: string, nonce: string): string {
  return `${assertValidIdentity(actorId, 'nonce.actorId')}\0${assertValidNonce(nonce)}`
}

/** Generate a nonce with ≥128 bits of cryptographically secure randomness. */
export function generateSecureNonce(): string {
  return `n_${randomBytes(16).toString('base64url')}`
}

/**
 * Synchronous adapter for an in-process store. `expectedVersion === 0` means the
 * (actor, nonce) pair must be absent. `compareAndSwap` returns false when the
 * stored version differs and must not apply a partial write.
 */
export interface AtomicNonceBackend {
  read(actorId: string, nonce: string): VersionedNonceRecord | undefined
  compareAndSwap(
    actorId: string,
    nonce: string,
    expectedVersion: number,
    record: NonceRecord
  ): boolean
}

/**
 * Adapter contract for a shared store (for example a SQL row with a version column).
 * Compare-and-swap must be atomic across every process that shares the store.
 */
export interface AsyncAtomicNonceBackend {
  read(actorId: string, nonce: string): Promise<VersionedNonceRecord | undefined>
  compareAndSwap(
    actorId: string,
    nonce: string,
    expectedVersion: number,
    record: NonceRecord
  ): Promise<boolean>
}

type MaybePromise<T> = T | Promise<T>

/** What the authority path calls. Sync and async stores both satisfy it. */
export interface NonceStore {
  assertUsable(actorId: string, nonce: unknown, intentHash: string): MaybePromise<'fresh' | 'pending'>
  reserve(actorId: string, nonce: unknown, intentHash: string): MaybePromise<void>
  claimForExecution(actorId: string, nonce: unknown, intentHash: string): MaybePromise<void>
  consume(actorId: string, nonce: unknown, intentHash: string): MaybePromise<void>
  fail(actorId: string, nonce: unknown, intentHash: string): MaybePromise<void>
}

type Transition =
  | { readonly kind: 'return' }
  | { readonly kind: 'throw'; readonly error: AuthorityError }
  | { readonly kind: 'write'; readonly record: NonceRecord }

type Operation = 'reserve' | 'claim' | 'consume' | 'fail'

const replay = (message: string): Transition => ({
  kind: 'throw',
  error: new AuthorityError('replay', message, true),
})

function usability(record: NonceRecord | undefined, actorId: string, intentHash: string): 'fresh' | 'pending' {
  if (!record) return 'fresh'
  if (record.actorId !== actorId) {
    throw new AuthorityError('replay', 'nonce actor mismatch', true)
  }
  if (record.intentHash !== intentHash) {
    throw new AuthorityError('replay', 'nonce already used', true)
  }
  if (record.status === 'consumed' || record.status === 'failed') {
    throw new AuthorityError('replay', 'nonce already used', true)
  }
  if (record.inFlight) {
    throw new AuthorityError('replay', 'nonce_in_flight_or_used', true)
  }
  return 'pending'
}

function transition(
  op: Operation,
  record: NonceRecord | undefined,
  actorId: string,
  intentHash: string
): Transition {
  if (record && record.actorId !== actorId) return replay('nonce actor mismatch')
  if (record && record.intentHash !== intentHash) return replay('nonce already used')
  switch (op) {
    case 'reserve':
      if (!record) {
        return { kind: 'write', record: { status: 'pending', intentHash, inFlight: false, actorId } }
      }
      if (record.status === 'pending' && !record.inFlight) return { kind: 'return' }
      return replay('nonce_in_flight_or_used')
    case 'claim':
      if (record && (record.status !== 'pending' || record.inFlight)) {
        return replay('nonce_in_flight_or_used')
      }
      return { kind: 'write', record: { status: 'pending', intentHash, inFlight: true, actorId } }
    case 'consume':
      if (record?.status === 'consumed') return { kind: 'return' }
      return { kind: 'write', record: { status: 'consumed', intentHash, inFlight: false, actorId } }
    case 'fail':
      return { kind: 'write', record: { status: 'failed', intentHash, inFlight: false, actorId } }
  }
}

/**
 * In-process backend. Synchronous compare-and-swap is atomic only on this object.
 * Two `NonceLedger` instances with distinct backends do not observe each other.
 */
export class MemoryAtomicNonceBackend implements AtomicNonceBackend {
  private readonly rows = new Map<string, { version: number; record: NonceRecord }>()
  /**
   * Test hook. Runs at most once, before the next compare-and-swap, so another
   * ledger sharing this backend can win the race deterministically.
   */
  beforeCompareAndSwap?: () => void
  private hookUsed = false

  read(actorId: string, nonce: string): VersionedNonceRecord | undefined {
    const row = this.rows.get(nonceStorageKey(actorId, nonce))
    return row ? { version: row.version, record: row.record } : undefined
  }

  compareAndSwap(
    actorId: string,
    nonce: string,
    expectedVersion: number,
    record: NonceRecord
  ): boolean {
    if (this.beforeCompareAndSwap && !this.hookUsed) {
      this.hookUsed = true
      const hook = this.beforeCompareAndSwap
      this.beforeCompareAndSwap = undefined
      hook()
    }
    const key = nonceStorageKey(actorId, nonce)
    const row = this.rows.get(key)
    const version = row?.version ?? 0
    if (version !== expectedVersion) return false
    if (record.actorId !== actorId) return false
    this.rows.set(key, { version: version + 1, record })
    return true
  }
}

export class NonceAuthority implements NonceStore {
  constructor(private readonly backend: AtomicNonceBackend) {}

  has(actorId: string, nonce: string): boolean {
    return this.backend.read(assertValidIdentity(actorId, 'nonce.actorId'), assertValidNonce(nonce)) != null
  }

  statusOf(actorId: string, nonce: string): NonceStatus | undefined {
    return this.backend.read(assertValidIdentity(actorId, 'nonce.actorId'), assertValidNonce(nonce))?.record
      .status
  }

  assertUsable(actorId: string, nonce: unknown, intentHash: string): 'fresh' | 'pending' {
    const actor = assertValidIdentity(actorId, 'nonce.actorId')
    return usability(this.backend.read(actor, assertValidNonce(nonce))?.record, actor, intentHash)
  }

  reserve(actorId: string, nonce: unknown, intentHash: string): void {
    this.mutate('reserve', actorId, nonce, intentHash)
  }

  claimForExecution(actorId: string, nonce: unknown, intentHash: string): void {
    this.mutate('claim', actorId, nonce, intentHash)
  }

  consume(actorId: string, nonce: unknown, intentHash: string): void {
    this.mutate('consume', actorId, nonce, intentHash)
  }

  fail(actorId: string, nonce: unknown, intentHash: string): void {
    this.mutate('fail', actorId, nonce, intentHash)
  }

  private mutate(op: Operation, actorId: string, nonce: unknown, intentHash: string): void {
    const actor = assertValidIdentity(actorId, 'nonce.actorId')
    const key = assertValidNonce(nonce)
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const current = this.backend.read(actor, key)
      const outcome = transition(op, current?.record, actor, intentHash)
      if (outcome.kind === 'return') return
      if (outcome.kind === 'throw') throw outcome.error
      if (this.backend.compareAndSwap(actor, key, current?.version ?? 0, outcome.record)) return
    }
    throw new AuthorityError('replay', 'nonce_in_flight_or_used', true)
  }
}

/** Process-local ledger. Not replay protection across processes. */
export class NonceLedger extends NonceAuthority {
  constructor(backend: AtomicNonceBackend = new MemoryAtomicNonceBackend()) {
    super(backend)
  }
}

/**
 * Ledger over a shared async store. Exclusion across processes holds only when the
 * backend meets the `AsyncAtomicNonceBackend` contract.
 */
export class SharedNonceLedger implements NonceStore {
  constructor(private readonly backend: AsyncAtomicNonceBackend) {}

  async statusOf(actorId: string, nonce: string): Promise<NonceStatus | undefined> {
    return (
      await this.backend.read(assertValidIdentity(actorId, 'nonce.actorId'), assertValidNonce(nonce))
    )?.record.status
  }

  async assertUsable(actorId: string, nonce: unknown, intentHash: string): Promise<'fresh' | 'pending'> {
    const actor = assertValidIdentity(actorId, 'nonce.actorId')
    return usability((await this.backend.read(actor, assertValidNonce(nonce)))?.record, actor, intentHash)
  }

  reserve(actorId: string, nonce: unknown, intentHash: string): Promise<void> {
    return this.mutate('reserve', actorId, nonce, intentHash)
  }

  claimForExecution(actorId: string, nonce: unknown, intentHash: string): Promise<void> {
    return this.mutate('claim', actorId, nonce, intentHash)
  }

  consume(actorId: string, nonce: unknown, intentHash: string): Promise<void> {
    return this.mutate('consume', actorId, nonce, intentHash)
  }

  fail(actorId: string, nonce: unknown, intentHash: string): Promise<void> {
    return this.mutate('fail', actorId, nonce, intentHash)
  }

  private async mutate(op: Operation, actorId: string, nonce: unknown, intentHash: string): Promise<void> {
    const actor = assertValidIdentity(actorId, 'nonce.actorId')
    const key = assertValidNonce(nonce)
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const current = await this.backend.read(actor, key)
      const outcome = transition(op, current?.record, actor, intentHash)
      if (outcome.kind === 'return') return
      if (outcome.kind === 'throw') throw outcome.error
      if (await this.backend.compareAndSwap(actor, key, current?.version ?? 0, outcome.record)) return
    }
    throw new AuthorityError('replay', 'nonce_in_flight_or_used', true)
  }
}
