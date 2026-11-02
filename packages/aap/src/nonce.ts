import { AuthorityError } from './errors.js'
import { assertValidNonce } from './runtime-validate.js'

/**
 * Nonce state machine for single-use intents.
 *
 * - `pending` — reserved for human approval, or exclusively claimed for execution
 * - `consumed` — terminal success (or a terminal BLOCK that retires the nonce)
 * - `failed` — executor threw; nonce is spent and cannot be retried with the same intent
 *
 * Every transition is a read followed by a compare-and-swap on the record version.
 * A lost race throws `nonce_in_flight_or_used` and does not execute.
 *
 * `NonceLedger` with its default backend is one process-local map. It is lost on
 * restart and is not replay protection across processes. Cross-process exclusion
 * needs an `AsyncAtomicNonceBackend` whose compare-and-swap is atomic in a shared
 * store, wrapped in `SharedNonceLedger`. This package does not ship such a store.
 */
export type NonceStatus = 'pending' | 'consumed' | 'failed'

export interface NonceRecord {
  readonly status: NonceStatus
  readonly intentHash: string
  readonly inFlight: boolean
}

export interface VersionedNonceRecord {
  readonly version: number
  readonly record: NonceRecord
}

/**
 * Synchronous adapter for an in-process store. `expectedVersion === 0` means the
 * nonce must be absent. `compareAndSwap` returns false when the stored version
 * differs and must not apply a partial write.
 */
export interface AtomicNonceBackend {
  read(nonce: string): VersionedNonceRecord | undefined
  compareAndSwap(nonce: string, expectedVersion: number, record: NonceRecord): boolean
}

/**
 * Adapter contract for a shared store (for example a SQL row with a version column,
 * or a key-value store with a conditional write).
 *
 * - `read` returns the current version and record, or `undefined` when absent.
 * - `compareAndSwap(nonce, 0, record)` succeeds only if no row exists.
 * - `compareAndSwap(nonce, v, record)` succeeds only if the stored version is `v`,
 *   and then stores `record` at version `v + 1`.
 * - A false return means no write happened. A rejected promise means the outcome is
 *   unknown; the authority path treats it as a failure and does not execute.
 * - The compare and the write are one atomic operation in the store, across every
 *   process that shares it. Without that, `SharedNonceLedger` gives no guarantee.
 * - Rows are never deleted while the intent could still be presented.
 */
export interface AsyncAtomicNonceBackend {
  read(nonce: string): Promise<VersionedNonceRecord | undefined>
  compareAndSwap(nonce: string, expectedVersion: number, record: NonceRecord): Promise<boolean>
}

type MaybePromise<T> = T | Promise<T>

/** What the authority path calls. Sync and async stores both satisfy it. */
export interface NonceStore {
  assertUsable(nonce: unknown, intentHash: string): MaybePromise<'fresh' | 'pending'>
  reserve(nonce: unknown, intentHash: string): MaybePromise<void>
  claimForExecution(nonce: unknown, intentHash: string): MaybePromise<void>
  consume(nonce: unknown, intentHash: string): MaybePromise<void>
  fail(nonce: unknown, intentHash: string): MaybePromise<void>
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

function usability(record: NonceRecord | undefined, intentHash: string): 'fresh' | 'pending' {
  if (!record) return 'fresh'
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

function transition(op: Operation, record: NonceRecord | undefined, intentHash: string): Transition {
  if (record && record.intentHash !== intentHash) return replay('nonce already used')
  switch (op) {
    case 'reserve':
      if (!record) return { kind: 'write', record: { status: 'pending', intentHash, inFlight: false } }
      if (record.status === 'pending' && !record.inFlight) return { kind: 'return' }
      return replay('nonce_in_flight_or_used')
    case 'claim':
      if (record && (record.status !== 'pending' || record.inFlight)) {
        return replay('nonce_in_flight_or_used')
      }
      return { kind: 'write', record: { status: 'pending', intentHash, inFlight: true } }
    case 'consume':
      if (record?.status === 'consumed') return { kind: 'return' }
      return { kind: 'write', record: { status: 'consumed', intentHash, inFlight: false } }
    case 'fail':
      return { kind: 'write', record: { status: 'failed', intentHash, inFlight: false } }
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

  read(nonce: string): VersionedNonceRecord | undefined {
    const row = this.rows.get(nonce)
    return row ? { version: row.version, record: row.record } : undefined
  }

  compareAndSwap(nonce: string, expectedVersion: number, record: NonceRecord): boolean {
    if (this.beforeCompareAndSwap && !this.hookUsed) {
      this.hookUsed = true
      const hook = this.beforeCompareAndSwap
      this.beforeCompareAndSwap = undefined
      hook()
    }
    const row = this.rows.get(nonce)
    const version = row?.version ?? 0
    if (version !== expectedVersion) return false
    this.rows.set(nonce, { version: version + 1, record })
    return true
  }
}

export class NonceAuthority implements NonceStore {
  constructor(private readonly backend: AtomicNonceBackend) {}

  has(nonce: string): boolean {
    return this.backend.read(assertValidNonce(nonce)) != null
  }

  statusOf(nonce: string): NonceStatus | undefined {
    return this.backend.read(assertValidNonce(nonce))?.record.status
  }

  assertUsable(nonce: unknown, intentHash: string): 'fresh' | 'pending' {
    return usability(this.backend.read(assertValidNonce(nonce))?.record, intentHash)
  }

  reserve(nonce: unknown, intentHash: string): void {
    this.mutate('reserve', nonce, intentHash)
  }

  claimForExecution(nonce: unknown, intentHash: string): void {
    this.mutate('claim', nonce, intentHash)
  }

  consume(nonce: unknown, intentHash: string): void {
    this.mutate('consume', nonce, intentHash)
  }

  fail(nonce: unknown, intentHash: string): void {
    this.mutate('fail', nonce, intentHash)
  }

  private mutate(op: Operation, nonce: unknown, intentHash: string): void {
    const key = assertValidNonce(nonce)
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const current = this.backend.read(key)
      const outcome = transition(op, current?.record, intentHash)
      if (outcome.kind === 'return') return
      if (outcome.kind === 'throw') throw outcome.error
      if (this.backend.compareAndSwap(key, current?.version ?? 0, outcome.record)) return
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

  async statusOf(nonce: string): Promise<NonceStatus | undefined> {
    return (await this.backend.read(assertValidNonce(nonce)))?.record.status
  }

  async assertUsable(nonce: unknown, intentHash: string): Promise<'fresh' | 'pending'> {
    return usability((await this.backend.read(assertValidNonce(nonce)))?.record, intentHash)
  }

  reserve(nonce: unknown, intentHash: string): Promise<void> {
    return this.mutate('reserve', nonce, intentHash)
  }

  claimForExecution(nonce: unknown, intentHash: string): Promise<void> {
    return this.mutate('claim', nonce, intentHash)
  }

  consume(nonce: unknown, intentHash: string): Promise<void> {
    return this.mutate('consume', nonce, intentHash)
  }

  fail(nonce: unknown, intentHash: string): Promise<void> {
    return this.mutate('fail', nonce, intentHash)
  }

  private async mutate(op: Operation, nonce: unknown, intentHash: string): Promise<void> {
    const key = assertValidNonce(nonce)
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const current = await this.backend.read(key)
      const outcome = transition(op, current?.record, intentHash)
      if (outcome.kind === 'return') return
      if (outcome.kind === 'throw') throw outcome.error
      if (await this.backend.compareAndSwap(key, current?.version ?? 0, outcome.record)) return
    }
    throw new AuthorityError('replay', 'nonce_in_flight_or_used', true)
  }
}
