import { describe, expect, it } from 'vitest'
import { DemoBroker } from './broker.js'
import { createSimulatedRail } from './payments.js'
import { attemptDirectBrokerExecute } from 'adap-gateway'

describe('simulated payment rail', () => {
  it('creates a payment once for the same intent hash', () => {
    const rail = createSimulatedRail()
    const request = {
      action: 'create_payment',
      target: 'payments/outgoing',
      parameters: { amount: 100, currency: 'USD', beneficiary: 'vendor_acme', purpose: 'treasury.demo' },
      intentHash: 'a'.repeat(64),
      correlationId: 'corr_1',
    }
    const first = rail.payments.execute(rail.capability, request)
    const second = rail.payments.execute(rail.capability, request)
    expect(first.status).toBe('completed')
    expect(second.status).toBe('completed')
    expect(rail.payments.sideEffects().paymentsCreated).toBe(1)
    expect(rail.payments.sideEffects().duplicateSuppressions).toBe(1)
  })

  it('rejects a caller that does not hold the rail capability', () => {
    const rail = createSimulatedRail()
    const outcome = rail.payments.rejectUnauthorized({
      action: 'change_beneficiary',
      target: 'payments/pay_seed_1001',
      parameters: { beneficiary: 'vendor_unknown' },
      intentHash: 'forged',
      correlationId: 'corr_forged',
    })
    expect(outcome.status).toBe('failed')
    expect(rail.payments.list().find((payment) => payment.id === 'pay_seed_1001')?.beneficiary).toBe('vendor_northwind')
  })

  it('does not register a beneficiary route on the broker', async () => {
    const rail = createSimulatedRail()
    const broker = new DemoBroker(rail.payments, rail.capability)
    await expect(broker.resolveHandle('change_beneficiary', 'payments/pay_seed_1001')).rejects.toThrow(/no credential handle/)
    await expect(
      attemptDirectBrokerExecute(broker, 'change_beneficiary', 'payments/pay_seed_1001', { beneficiary: 'vendor_unknown' }),
    ).rejects.toThrow(/no credential handle/)
    expect(rail.payments.sideEffects().beneficiaryChanges).toBe(0)
  })
})
