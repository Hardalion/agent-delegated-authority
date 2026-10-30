import { describe, expect, it } from 'vitest'
import { AuthorityError } from './errors.js'
import { NonceLedger } from './nonce.js'

describe('NonceLedger state machine', () => {
  it('claims exclusively before execution; a second claim is blocked', () => {
    const ledger = new NonceLedger()
    ledger.claimForExecution('n1', 'hash-a')
    expect(ledger.statusOf('n1')).toBe('pending')
    expect(() => ledger.claimForExecution('n1', 'hash-a')).toThrow(AuthorityError)
    try {
      ledger.claimForExecution('n1', 'hash-a')
    } catch (error) {
      expect(error).toBeInstanceOf(AuthorityError)
      expect((error as AuthorityError).message).toBe('nonce_in_flight_or_used')
    }
  })

  it('allows human-wait pending to be claimed once, then consumes', () => {
    const ledger = new NonceLedger()
    ledger.reserve('n2', 'hash-b')
    expect(ledger.assertUsable('n2', 'hash-b')).toBe('pending')
    ledger.claimForExecution('n2', 'hash-b')
    ledger.consume('n2', 'hash-b')
    expect(ledger.statusOf('n2')).toBe('consumed')
    expect(() => ledger.assertUsable('n2', 'hash-b')).toThrow(/nonce already used/)
  })

  it('marks failed after an executor failure and rejects retry', () => {
    const ledger = new NonceLedger()
    ledger.claimForExecution('n3', 'hash-c')
    ledger.fail('n3', 'hash-c')
    expect(ledger.statusOf('n3')).toBe('failed')
    expect(() => ledger.claimForExecution('n3', 'hash-c')).toThrow(/nonce_in_flight_or_used/)
  })

  it('blocks assertUsable while a claim is in flight', () => {
    const ledger = new NonceLedger()
    ledger.claimForExecution('n4', 'hash-d')
    expect(() => ledger.assertUsable('n4', 'hash-d')).toThrow(/nonce_in_flight_or_used/)
  })
})
