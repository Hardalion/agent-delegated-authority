import { describe, expect, it } from 'vitest'
import { AuthorityError } from './errors.js'
import { generateSecureNonce, MemoryAtomicNonceBackend, NonceLedger } from './nonce.js'

const ACTOR_A = 'agt_a'
const ACTOR_B = 'agt_b'

describe('NonceLedger actor isolation', () => {
  it('blocks concurrent claim for the same actor and nonce', () => {
    const ledger = new NonceLedger()
    ledger.claimForExecution(ACTOR_A, 'n1', 'hash-a')
    expect(ledger.statusOf(ACTOR_A, 'n1')).toBe('pending')
    expect(() => ledger.claimForExecution(ACTOR_A, 'n1', 'hash-a')).toThrow(AuthorityError)
    try {
      ledger.claimForExecution(ACTOR_A, 'n1', 'hash-a')
    } catch (error) {
      expect(error).toBeInstanceOf(AuthorityError)
      expect((error as AuthorityError).message).toMatch(/nonce_in_flight_or_used/)
    }
  })

  it('allows reserve then claim then consume for one actor', () => {
    const ledger = new NonceLedger()
    ledger.reserve(ACTOR_A, 'n2', 'hash-b')
    expect(ledger.assertUsable(ACTOR_A, 'n2', 'hash-b')).toBe('pending')
    ledger.claimForExecution(ACTOR_A, 'n2', 'hash-b')
    ledger.consume(ACTOR_A, 'n2', 'hash-b')
    expect(ledger.statusOf(ACTOR_A, 'n2')).toBe('consumed')
    expect(() => ledger.assertUsable(ACTOR_A, 'n2', 'hash-b')).toThrow(/nonce already used/)
  })

  it('treats failed nonces as spent for that actor', () => {
    const ledger = new NonceLedger()
    ledger.claimForExecution(ACTOR_A, 'n3', 'hash-c')
    ledger.fail(ACTOR_A, 'n3', 'hash-c')
    expect(ledger.statusOf(ACTOR_A, 'n3')).toBe('failed')
    expect(() => ledger.claimForExecution(ACTOR_A, 'n3', 'hash-c')).toThrow(/nonce_in_flight_or_used/)
  })

  it('rejects assertUsable while in flight', () => {
    const ledger = new NonceLedger()
    ledger.claimForExecution(ACTOR_A, 'n4', 'hash-d')
    expect(() => ledger.assertUsable(ACTOR_A, 'n4', 'hash-d')).toThrow(/nonce_in_flight_or_used/)
  })

  it('isolates the same nonce string across actors (#20)', () => {
    const ledger = new NonceLedger()
    ledger.claimForExecution(ACTOR_A, 'shared-nonce', 'hash-a')
    ledger.consume(ACTOR_A, 'shared-nonce', 'hash-a')
    // Actor B may still use the same nonce string.
    expect(ledger.assertUsable(ACTOR_B, 'shared-nonce', 'hash-b')).toBe('fresh')
    ledger.claimForExecution(ACTOR_B, 'shared-nonce', 'hash-b')
    ledger.consume(ACTOR_B, 'shared-nonce', 'hash-b')
    expect(ledger.statusOf(ACTOR_B, 'shared-nonce')).toBe('consumed')
    expect(() => ledger.assertUsable(ACTOR_A, 'shared-nonce', 'hash-a')).toThrow(/nonce already used/)
  })

  it('does not let one actor consume another actor nonce', () => {
    const ledger = new NonceLedger()
    ledger.reserve(ACTOR_A, 'n-cross', 'hash-a')
    expect(() => ledger.consume(ACTOR_B, 'n-cross', 'hash-a')).not.toThrow()
    // B created its own row; A's pending remains.
    expect(ledger.assertUsable(ACTOR_A, 'n-cross', 'hash-a')).toBe('pending')
  })

  it('generates ≥128-bit CSPRNG nonces', () => {
    const a = generateSecureNonce()
    const b = generateSecureNonce()
    expect(a).toMatch(/^n_/)
    expect(a).not.toBe(b)
    // Prefix `n_` (2 chars) + base64url of 16 CSPRNG bytes (≥21 chars without padding).
    expect(a.length).toBeGreaterThanOrEqual(2 + 21)
    expect(Buffer.from(a.slice(2), 'base64url').length).toBeGreaterThanOrEqual(16)
  })

  it('loses a CAS race without dual execution', () => {
    const backend = new MemoryAtomicNonceBackend()
    const primary = new NonceLedger(backend)
    const rival = new NonceLedger(backend)
    backend.beforeCompareAndSwap = () => {
      rival.claimForExecution(ACTOR_A, 'race', 'hash-race')
    }
    expect(() => primary.claimForExecution(ACTOR_A, 'race', 'hash-race')).toThrow(/nonce_in_flight_or_used/)
  })
})
