import { describe, expect, it } from 'vitest'
import { verifyProtocolReceipt, importPublicKey } from 'adap'
import { RESET_CONFIRM } from './guard.js'
import { DemoRuntime } from './runtime.js'

const FIXED = new Date('2026-11-01T12:00:00.000Z')

function runtime(env: { NODE_ENV?: string; ADAP_DEMO_ENV?: string; ADAP_PG_URL?: string } = {}) {
  return new DemoRuntime({
    now: () => FIXED,
    passphrase: 'treasury-demo',
    env: { NODE_ENV: 'demo', ADAP_DEMO_ENV: 'hackathon', ...env },
  })
}

describe('hackathon scenarios', () => {
  it('runs A, B, and C in order with one approved execution and no beneficiary change', async () => {
    const demo = runtime()
    const allow = await demo.runScenario('status')
    const allowCase = allow.cases[0]
    expect(allowCase?.decision).toBe('ALLOW')
    expect(allowCase?.ruleId).toBe('status_allow')
    expect(allowCase?.executed).toBe(true)
    expect(allowCase?.outcomeLabel).toBe('EXECUTED')
    expect(allowCase?.verification?.valid).toBe(true)
    expect(allowCase?.verification?.verifier).toBe('adap.verifyProtocolReceipt')
    expect(allow.sideEffects.statusReads).toBe(1)
    expect(allow.sideEffects.paymentsCreated).toBe(0)
    expect(allow.metrics.executed).toBe(1)

    const pending = await demo.runScenario('payment')
    const pendingCase = pending.cases[0]
    expect(pendingCase?.decision).toBe('REQUIRE_HUMAN')
    expect(pendingCase?.ruleId).toBe('create_needs_human')
    expect(pendingCase?.executed).toBe(false)
    expect(pendingCase?.outcomeLabel).toBe('NOT EXECUTED · AWAITING APPROVAL')
    expect(pending.pending).toHaveLength(1)
    expect(pending.sideEffects.paymentsCreated).toBe(0)
    expect(pending.railCalls.some((call) => call.action === 'create_payment')).toBe(false)

    const approved = await demo.approve(pendingCase?.nonce ?? '', 'treasury-demo')
    expect(approved.sideEffects.paymentsCreated).toBe(1)
    expect(approved.pending).toHaveLength(0)
    const executed = approved.cases.find((item) => item.executed)
    expect(executed?.decision).toBe('ALLOW')
    expect(executed?.outcomeLabel).toBe('EXECUTED')
    expect(executed?.verification?.valid).toBe(true)
    expect(executed?.approvalState).toBe('approved')
    const continued = approved.cases.find((item) => item.approvalState === 'approved' && !item.executed)
    expect(continued?.outcomeLabel).toBe('NOT EXECUTED · CONTINUED')

    await expect(demo.approve(pendingCase?.nonce ?? '', 'treasury-demo')).rejects.toThrow(/additional execution/i)
    expect(demo.publicState().sideEffects.paymentsCreated).toBe(1)

    const blocked = await demo.runScenario('beneficiary')
    const blockCase = blocked.cases[0]
    expect(blockCase?.decision).toBe('BLOCK')
    expect(blockCase?.ruleId).toBe('block_beneficiary')
    expect(blockCase?.executed).toBe(false)
    expect(blockCase?.outcomeLabel).toBe('NOT EXECUTED · BLOCKED')
    expect(blocked.sideEffects.beneficiaryChanges).toBe(0)
    expect(blocked.payments.find((payment) => payment.id === 'pay_seed_1001')?.beneficiary).toBe('vendor_northwind')
    expect(blocked.railCalls.some((call) => call.action === 'change_beneficiary')).toBe(false)
    expect(blockCase?.verification?.valid).toBe(true)
    expect(blocked.receiptChain?.valid).toBe(true)
    expect(blocked.timings.lastAuthorizationMs).toBeGreaterThanOrEqual(0)
    expect(blocked.timings.lastAuthorizationMs ?? 9999).toBeLessThan(2000)
  })

  it('blocks a payment above the hard cap with no create', async () => {
    const demo = runtime()
    const state = await demo.runScenario('hard-cap')
    expect(state.cases[0]?.ruleId).toBe('block_over_cap')
    expect(state.cases[0]?.executed).toBe(false)
    expect(state.sideEffects.paymentsCreated).toBe(0)
  })

  it('rejects approval before any execution and ignores a later approval', async () => {
    const demo = runtime()
    const pending = await demo.runScenario('payment', { nonce: 'n-reject-1' })
    const rejected = await demo.reject('n-reject-1', 'treasury-demo')
    expect(rejected.cases[0]?.outcomeLabel).toBe('NOT EXECUTED · REJECTED')
    expect(rejected.sideEffects.paymentsCreated).toBe(0)
    expect(rejected.pending).toHaveLength(0)
    await expect(demo.approve('n-reject-1', 'treasury-demo')).rejects.toThrow(/additional execution/)
    expect(demo.publicState().sideEffects.paymentsCreated).toBe(0)
    expect(pending.cases[0]?.decision).toBe('REQUIRE_HUMAN')
  })

  it('refuses the wrong passphrase without consuming the payment', async () => {
    const demo = runtime()
    await demo.runScenario('payment', { nonce: 'n-pass-1' })
    await expect(demo.approve('n-pass-1', 'wrong-passphrase')).rejects.toThrow(/passphrase/)
    expect(demo.publicState().pending).toHaveLength(1)
    expect(demo.publicState().sideEffects.paymentsCreated).toBe(0)
  })

  it('replays a duplicate intent without a second read', async () => {
    const demo = runtime()
    await demo.runScenario('status', { nonce: 'n-dup-1' })
    const second = await demo.runScenario('status', { nonce: 'n-dup-1' })
    expect(second.cases[0]?.decision).toBe('BLOCK')
    expect(second.cases[0]?.ruleId).toBe('replay')
    expect(second.cases[0]?.executed).toBe(false)
    expect(second.sideEffects.statusReads).toBe(1)
  })

  it('fails closed on signature, expiry, agent, target, policy, and amount boundaries', async () => {
    const demo = runtime()
    const bad = await demo.probeInvalidSignature()
    expect(bad.authenticated).toBe(false)
    expect(bad.executed).toBe(false)
    expect(bad.receipt).toBeNull()

    const expired = await demo.probeExpiredDelegation()
    expect(expired.executed).toBe(false)
    expect(expired.decision).toBe('BLOCK')
    expect(`${expired.ruleId} ${expired.reason}`).toMatch(/expired/i)

    const outsider = await demo.probeWrongAgent()
    expect(outsider.executed).toBe(false)
    expect(`${outsider.ruleId} ${outsider.reason}`).toMatch(/actor|delegate/i)

    const target = await demo.probeWrongTarget()
    expect(target.ruleId).toBe('capability')
    expect(target.executed).toBe(false)

    const substituted = await demo.probePolicySubstitution()
    expect(substituted.executed).toBe(false)
    expect(substituted.ruleId).toBe('policy')

    const autonomous = await demo.probeAmount(100_000, 'n-amt-100000')
    expect(autonomous.decision).toBe('ALLOW')
    expect(autonomous.executed).toBe(true)
    const human = await demo.probeAmount(100_001, 'n-amt-100001')
    expect(human.decision).toBe('REQUIRE_HUMAN')
    expect(human.executed).toBe(false)
    const cap = await demo.probeAmount(500_000, 'n-amt-500000')
    expect(cap.decision).toBe('REQUIRE_HUMAN')
    const over = await demo.probeAmount(500_001, 'n-amt-500001')
    expect(over.ruleId).toBe('block_over_cap')
    expect(over.executed).toBe(false)
    expect(demo.publicState().sideEffects.paymentsCreated).toBe(1)
  })

  it('executes one payment when the same approval is submitted twice', async () => {
    const demo = runtime()
    const result = await demo.probeParallelSameApproval()
    expect(result.created).toBe(1)
    expect(result.calls).toBe(1)
    expect(result.decisions.filter((decision) => decision === 'ALLOW')).toHaveLength(1)
  })

  it('reports OUTCOME UNKNOWN when the simulated rail does not return a result', async () => {
    const demo = runtime()
    demo.armDownstreamForTests('unknown')
    const state = await demo.runScenario('status')
    expect(state.cases[0]?.outcomeLabel).toBe('OUTCOME UNKNOWN')
    expect(state.cases[0]?.executed).toBe(false)
    expect(state.sideEffects.statusReads).toBe(0)
    const execution = state.cases[0]?.stages.find((stage) => stage.id === 'execution')
    expect(execution?.detail).toBe('OUTCOME UNKNOWN')
  })

  it('keeps a direct rail call from changing a beneficiary', () => {
    const demo = runtime()
    const attempt = demo.attemptUnauthorizedSideEffectForTests()
    expect(attempt.status).toBe('failed')
    expect(attempt.beneficiary).toBe('vendor_northwind')
  })

  it('exports evidence before reset and refuses reset outside the demo environment', async () => {
    const demo = runtime()
    await demo.runScenario('status')
    await expect(
      demo.reset({ confirm: 'no', passphrase: 'treasury-demo', acknowledgeExport: true }),
    ).rejects.toThrow(/confirmation/)
    expect(demo.publicState().cases).toHaveLength(1)
    const reset = await demo.reset({
      confirm: RESET_CONFIRM,
      passphrase: 'treasury-demo',
      acknowledgeExport: true,
    })
    expect(reset.evidence.cases).toHaveLength(1)
    expect(reset.state.cases).toHaveLength(0)
    expect(reset.state.payments.find((payment) => payment.id === 'pay_seed_1001')?.beneficiary).toBe('vendor_northwind')
    expect(JSON.stringify(reset.evidence)).not.toContain('PRIVATE KEY')

    const production = runtime({ NODE_ENV: 'production' })
    await production.runScenario('status')
    await expect(
      production.reset({ confirm: RESET_CONFIRM, passphrase: 'treasury-demo', acknowledgeExport: true }),
    ).rejects.toThrow(/production/)
    expect(production.publicState().cases).toHaveLength(1)

    const attached = runtime({ ADAP_PG_URL: 'postgresql://adap:adap@127.0.0.1:55432/adap' })
    await expect(
      attached.reset({ confirm: RESET_CONFIRM, passphrase: 'treasury-demo', acknowledgeExport: true }),
    ).rejects.toThrow(/ADAP_PG_URL/)
  })

  it('loses an in-memory approval across a process restart and does not execute it', async () => {
    const first = runtime()
    const pending = await first.runScenario('payment', { nonce: 'n-restart-1' })
    const nonce = pending.cases[0]?.nonce ?? ''
    const restarted = runtime()
    await expect(restarted.approve(nonce, 'treasury-demo')).rejects.toThrow(/No pending approval/)
    expect(restarted.publicState().sideEffects.paymentsCreated).toBe(0)
  })

  it('matches the HTTP verifier to verifyProtocolReceipt', async () => {
    const demo = runtime()
    const state = await demo.runScenario('status')
    const receipt = state.cases[0]?.receipt
    expect(receipt).toBeTruthy()
    const direct = verifyProtocolReceipt(receipt!, importPublicKey(demo.issuerPublicKey()))
    expect(demo.verifyReceipt(receipt).valid).toBe(direct.valid)
    const tampered = structuredClone(receipt)
    tampered!.signature = 'ab'.repeat(64)
    expect(demo.verifyReceipt(tampered).valid).toBe(false)
  })
})
