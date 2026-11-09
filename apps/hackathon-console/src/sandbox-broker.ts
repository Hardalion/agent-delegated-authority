import type { CredentialBroker, DownstreamOutcome, DownstreamRequest } from 'adap-gateway'
import type { RailCall, RailSideEffects, SimPayment } from './payments.js'
import { HttpSandboxAdapter, type SandboxPurchase, type SandboxVendor } from './adapters/http-sandbox.js'

const ROUTES = new Map<string, string>([
  ['get_payment_status', 'payments/*'],
  ['create_payment', 'payments/*'],
  ['update_vendor_account', 'vendors/*'],
  ['create_purchase_request', 'purchases/*'],
])

/**
 * Broker for the persistent sandbox. The sandbox token stays inside the adapter.
 */
export class SandboxBroker implements CredentialBroker {
  readonly #adapter: HttpSandboxAdapter
  #calls: RailCall[] = []
  #payments: SimPayment[] = []
  #vendors: SandboxVendor[] = []
  #purchases: SandboxPurchase[] = []
  #statusReads = 0
  #paymentsCreated = 0
  #vendorChanges = 0
  #purchasesCreated = 0
  #duplicates = 0
  #unauthorized = 0

  constructor(adapter: HttpSandboxAdapter) {
    this.#adapter = adapter
  }

  listActions(): readonly string[] {
    return [...ROUTES.keys()]
  }

  list(): SimPayment[] {
    return this.#payments.map((payment) => ({ ...payment }))
  }

  vendors(): SandboxVendor[] {
    return this.#vendors.map((vendor) => ({ ...vendor }))
  }

  purchases(): SandboxPurchase[] {
    return this.#purchases.map((purchase) => ({ ...purchase }))
  }

  calls(): RailCall[] {
    return this.#calls.map((call) => ({ ...call }))
  }

  sideEffects(): RailSideEffects {
    return {
      statusReads: this.#statusReads,
      paymentsCreated: this.#paymentsCreated,
      beneficiaryChanges: this.#vendorChanges,
      unauthorizedRejections: this.#unauthorized,
      duplicateSuppressions: this.#duplicates,
    }
  }

  async refresh(): Promise<void> {
    this.#payments = (await this.#adapter.listPayments()).map((payment) => ({
      id: payment.id,
      beneficiary: payment.beneficiary,
      amount: payment.amount,
      currency: payment.currency,
      status: payment.status === 'settled' ? 'settled' : 'recorded',
      reference: payment.reference,
    }))
    this.#vendors = await this.#adapter.listVendors()
    this.#purchases = await this.#adapter.listPurchases()
  }

  async resolveHandle(action: string, target: string): Promise<string> {
    const pattern = ROUTES.get(action)
    if (!pattern || !matchTarget(pattern, target)) throw new Error('no credential handle for authorized route')
    return `hdl_${action}`
  }

  async execute(handle: string, request: DownstreamRequest): Promise<DownstreamOutcome> {
    const action = handle.startsWith('hdl_') ? handle.slice(4) : ''
    if (!ROUTES.has(action) || action !== request.action) {
      this.#unauthorized += 1
      return { status: 'failed', correlationId: request.correlationId, error: 'unknown_handle' }
    }
    const result = await this.#adapter.execute(request)
    const duplicate = result.body != null && typeof result.body === 'object' && (result.body as { duplicate?: boolean }).duplicate === true
    this.#calls.push({
      action: request.action,
      target: request.target,
      intentHash: request.intentHash,
      correlationId: request.correlationId,
      outcome: result.status === 'completed' ? 'completed' : result.status === 'unknown' ? 'unknown' : 'failed',
      duplicate,
      at: new Date().toISOString(),
    })
    if (duplicate) this.#duplicates += 1
    if (result.status === 'completed' && !duplicate) {
      if (request.action === 'get_payment_status') this.#statusReads += 1
      if (request.action === 'create_payment') this.#paymentsCreated += 1
      if (request.action === 'update_vendor_account') this.#vendorChanges += 1
      if (request.action === 'create_purchase_request') this.#purchasesCreated += 1
    }
    if (result.status === 'completed') await this.refresh()
    return this.#adapter.toDownstream(result)
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
