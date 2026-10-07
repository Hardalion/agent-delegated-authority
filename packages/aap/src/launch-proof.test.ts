import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { formatLaunchProof, INJECTION_NOTE, runLaunchProof } from './launch-proof.js'

describe('launch proof', () => {
  it('approves a bounded action, rejects a raised grant, and ignores instruction text', async () => {
    const proof = await runLaunchProof()
    const printed = formatLaunchProof(proof)

    expect(proof.narrowedActions).toEqual(['search'])
    expect(proof.legitPending.decision).toBe('REQUIRE_HUMAN')
    expect(proof.legitPending.executed).toBe(false)
    expect(proof.legit.decision).toBe('ALLOW')
    expect(proof.legit.executed).toBe(true)
    expect(proof.legit.receipt.human?.status).toBe('approved')

    expect(proof.overDelegation.decision).toBe('BLOCK')
    expect(proof.overDelegation.ruleId).toBe('narrowing')
    expect(proof.overDelegation.reason).toBe('child raises max_amount')
    expect(proof.overDelegation.executed).toBe(false)

    expect(proof.injection.decision).toBe('BLOCK')
    expect(proof.injection.ruleId).toBe('constraint')
    expect(proof.injection.reason).toBe('amount exceeds delegated max_amount')
    expect(proof.injection.executed).toBe(false)
    expect(proof.injection.receipt.intent.argsRedacted).toMatchObject({ note: INJECTION_NOTE, amount: 1000 })

    expect(proof.narrowedRead.decision).toBe('ALLOW')
    expect(proof.narrowedRead.executed).toBe(true)
    expect(proof.executorCalls).toBe(2)
    expect(proof.legitReceiptVerified).toBe(true)
    expect(proof.overDelegationReceiptVerified).toBe(true)
    expect(proof.injectionReceiptVerified).toBe(true)

    expect(printed).toContain('child raises max_amount')
    expect(printed).toContain(INJECTION_NOTE)
    expect(printed).toContain('The model can change its mind.')
    expect(printed).toContain('The authority boundary cannot.')
    expect(printed).toContain('prn_alex')
    expect(printed).toContain('ATH-LON')
    expect(printed).toContain('✓ signature verified with the issuer public key')
    expect(printed).toContain('NOT CALLED')
    expect(printed).not.toContain('Athens')

    const readme = readFileSync(new URL('../../../README.md', import.meta.url), 'utf8').replace(/\r\n/g, '\n')
    expect(readme).toContain(printed)
  })
})