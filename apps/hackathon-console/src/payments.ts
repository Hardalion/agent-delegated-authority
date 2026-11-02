import type { DownstreamOutcome, DownstreamRequest } from 'adap-gateway'

export interface SimPayment {
  readonly id: string
  readonly beneficiary: string
  readonly amount: number
  readonly currency: string
  readonly status: 'settled' | 'recorded'
  readonly reference: string
}

export interface RailCall {
  readonly action: string
  readonly target: string
  readonly intentHash: string
  readonly correlationId: string
  readonly outcome: 'completed' | 'failed' | 'unknown'
  readonly duplicate: boolean
  readonly at: string
}

export interface RailSideEffects {
  readonly statusReads: number
  readonly paymentsCreated: number
  readonly beneficiaryChanges: number
  readonly unauthorizedRejections: number
  readonly duplicateSuppressions: number
}

interface CompletedBody {
  readonly action: string
  readonly paymentId?: string
  readonly beneficiary?: string
  readonly amount?: number
  readonly currency?: string
  readonly status?: string
  readonly reference?: string
  readonly duplicate: boolean
  readonly simulated: true
}

/**
 * In-process simulated payment rail.
 * create_payment is idempotent for a repeated intent hash and non-idempotent across intent hashes.
 * get_payment_status is idempotent.
 * change_beneficiary is non-idempotent. The demo broker does not register that route.
 * There is no network call and no bank credential.
 */
export class SimulatedPaymentSystem {
  readonly #capability: symbol
  readonly #payments = new Map<string, SimPayment>()
  readonly #completed = new Map<string, CompletedBody>()
  readonly #calls: RailCall[] = []
  #statusReads = 0
  #paymentsCreated = 0
  #beneficiaryChanges = 0
  #unauthorizedRejections = 0
  #duplicateSuppressions = 0
  #arm: 'unknown' | 'failed' | null = null

  constructor(capability: symbol) {
    this.#capability = capability
    this.#payments.set('pay_seed_1001', {
      id: 'pay_seed_1001',
      beneficiary: 'vendor_northwind',
      amount: 15_000,
      currency: 'USD',
      status: 'settled',
      reference: 'SEED-1001',
    })
    this.#payments.set('pay_seed_1002', {
      id: 'pay_seed_1002',
      beneficiary: 'vendor_acme',
      amount: 42_000,
      currency: 'USD',
      status: 'settled',
      reference: 'SEED-1002',
    })
  }

  arm(mode: 'unknown' | 'failed' | null): void {
    this.#arm = mode
  }

  list(): SimPayment[] {
    return [...this.#payments.values()].map((payment) => ({ ...payment }))
  }

  calls(): RailCall[] {
    return this.#calls.map((call) => ({ ...call }))
  }

  sideEffects(): RailSideEffects {
    return {
      statusReads: this.#statusReads,
      paymentsCreated: this.#paymentsCreated,
      beneficiaryChanges: this.#beneficiaryChanges,
      unauthorizedRejections: this.#unauthorizedRejections,
      duplicateSuppressions: this.#duplicateSuppressions,
    }
  }

  /** Caller does not hold the in-process capability. */
  rejectUnauthorized(request: DownstreamRequest): DownstreamOutcome {
    return this.#finish(Symbol('unauthorized'), request)
  }

  execute(capability: symbol, request: DownstreamRequest): DownstreamOutcome {
    return this.#finish(capability, request)
  }

  #finish(capability: symbol, request: DownstreamRequest): DownstreamOutcome {
    if (capability !== this.#capability) {
      this.#unauthorizedRejections += 1
      this.#calls.push({
        action: request.action,
        target: request.target,
        intentHash: request.intentHash,
        correlationId: request.correlationId,
        outcome: 'failed',
        duplicate: false,
        at: new Date().toISOString(),
      })
      return {
        status: 'failed',
        correlationId: request.correlationId,
        error: 'unauthorized',
      }
    }

    if (this.#arm === 'unknown' || this.#arm === 'failed') {
      const mode = this.#arm
      this.#arm = null
      this.#calls.push({
        action: request.action,
        target: request.target,
        intentHash: request.intentHash,
        correlationId: request.correlationId,
        outcome: mode,
        duplicate: false,
        at: new Date().toISOString(),
      })
      if (mode === 'unknown') {
        return {
          status: 'unknown',
          correlationId: request.correlationId,
          error: 'simulated_downstream_timeout',
        }
      }
      return {
        status: 'failed',
        correlationId: request.correlationId,
        error: 'simulated_downstream_failure',
      }
    }

    const prior = this.#completed.get(request.intentHash)
    if (prior) {
      this.#duplicateSuppressions += 1
      this.#calls.push({
        action: request.action,
        target: request.target,
        intentHash: request.intentHash,
        correlationId: request.correlationId,
        outcome: 'completed',
        duplicate: true,
        at: new Date().toISOString(),
      })
      return {
        status: 'completed',
        correlationId: request.correlationId,
        body: { ...prior, duplicate: true },
      }
    }

    try {
      const body = this.#apply(request)
      this.#completed.set(request.intentHash, body)
      this.#calls.push({
        action: request.action,
        target: request.target,
        intentHash: request.intentHash,
        correlationId: request.correlationId,
        outcome: 'completed',
        duplicate: false,
        at: new Date().toISOString(),
      })
      return { status: 'completed', correlationId: request.correlationId, body }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'simulated_payment_failed'
      this.#calls.push({
        action: request.action,
        target: request.target,
        intentHash: request.intentHash,
        correlationId: request.correlationId,
        outcome: 'failed',
        duplicate: false,
        at: new Date().toISOString(),
      })
      return { status: 'failed', correlationId: request.correlationId, error: message }
    }
  }

  #apply(request: DownstreamRequest): CompletedBody {
    if (request.action === 'get_payment_status') {
      const id = paymentId(request.target)
      const payment = id ? this.#payments.get(id) : undefined
      if (!payment) throw new Error('payment_not_found')
      this.#statusReads += 1
      return {
        action: request.action,
        paymentId: payment.id,
        beneficiary: payment.beneficiary,
        amount: payment.amount,
        currency: payment.currency,
        status: payment.status,
        reference: payment.reference,
        duplicate: false,
        simulated: true,
      }
    }

    if (request.action === 'create_payment') {
      const amount = request.parameters.amount
      const currency = request.parameters.currency
      const beneficiary = request.parameters.beneficiary
      const reference = request.parameters.reference
      if (typeof amount !== 'number' || typeof currency !== 'string' || typeof beneficiary !== 'string') {
        throw new Error('payment_fields_required')
      }
      const id = `pay_${request.intentHash.slice(0, 12)}`
      const payment: SimPayment = {
        id,
        beneficiary,
        amount,
        currency,
        status: 'recorded',
        reference: typeof reference === 'string' ? reference : 'DEMO',
      }
      this.#payments.set(id, payment)
      this.#paymentsCreated += 1
      return {
        action: request.action,
        paymentId: id,
        beneficiary,
        amount,
        currency,
        status: 'recorded',
        reference: payment.reference,
        duplicate: false,
        simulated: true,
      }
    }

    if (request.action === 'change_beneficiary') {
      const id = paymentId(request.target)
      const payment = id ? this.#payments.get(id) : undefined
      const beneficiary = request.parameters.beneficiary
      if (!payment || typeof beneficiary !== 'string') throw new Error('beneficiary_change_rejected')
      this.#payments.set(payment.id, { ...payment, beneficiary })
      this.#beneficiaryChanges += 1
      return {
        action: request.action,
        paymentId: payment.id,
        beneficiary,
        duplicate: false,
        simulated: true,
      }
    }

    throw new Error('unsupported_simulated_action')
  }
}

function paymentId(target: string): string | null {
  const prefix = 'payments/'
  if (!target.startsWith(prefix)) return null
  const id = target.slice(prefix.length)
  if (!id || id.includes('/')) return null
  return id
}

export function createSimulatedRail(): {
  readonly capability: symbol
  readonly payments: SimulatedPaymentSystem
} {
  const capability = Symbol('hackathon-simulated-rail')
  return { capability, payments: new SimulatedPaymentSystem(capability) }
}
