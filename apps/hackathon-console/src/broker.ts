import type { CredentialBroker, DownstreamOutcome, DownstreamRequest } from 'adap-gateway'
import type { SimulatedPaymentSystem } from './payments.js'

/**
 * Process-local broker. The capability symbol never leaves this object.
 * Agents and the HTTP API do not receive it.
 * change_beneficiary is intentionally unregistered.
 */
export class DemoBroker implements CredentialBroker {
  readonly #payments: SimulatedPaymentSystem
  readonly #capability: symbol
  readonly #routes = new Map<string, string>([
    ['get_payment_status', 'payments/*'],
    ['create_payment', 'payments/*'],
  ])

  constructor(payments: SimulatedPaymentSystem, capability: symbol) {
    this.#payments = payments
    this.#capability = capability
  }

  listActions(): readonly string[] {
    return [...this.#routes.keys()]
  }

  async resolveHandle(action: string, target: string): Promise<string> {
    const pattern = this.#routes.get(action)
    if (!pattern || !matchTarget(pattern, target)) {
      throw new Error('no credential handle for authorized route')
    }
    return `hdl_${action}`
  }

  async execute(handle: string, request: DownstreamRequest): Promise<DownstreamOutcome> {
    const action = handle.startsWith('hdl_') ? handle.slice(4) : ''
    if (!this.#routes.has(action) || action !== request.action) {
      return { status: 'failed', correlationId: request.correlationId, error: 'unknown_handle' }
    }
    const pattern = this.#routes.get(action)
    if (!pattern || !matchTarget(pattern, request.target)) {
      return { status: 'failed', correlationId: request.correlationId, error: 'target_not_registered' }
    }
    return this.#payments.execute(this.#capability, request)
  }

  toJSON(): { readonly routes: readonly string[] } {
    return { routes: this.listActions() }
  }
}

function matchTarget(pattern: string, target: string): boolean {
  if (pattern.endsWith('/*')) {
    const prefix = pattern.slice(0, -1)
    const rest = target.slice(prefix.length)
    return target.startsWith(prefix) && rest.length > 0 && !rest.includes('/')
  }
  return pattern === target
}
