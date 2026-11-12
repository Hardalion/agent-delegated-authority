import type { DownstreamOutcome, DownstreamRequest } from 'adap-gateway'

export interface AdapterRequest {
  readonly action: string
  readonly target: string
  readonly parameters: Readonly<Record<string, unknown>>
  readonly intentHash: string
  readonly correlationId: string
}

export type AdapterClassification =
  | 'completed'
  | 'rejected'
  | 'timeout_before_commit'
  | 'timeout_after_commit'
  | 'unavailable'
  | 'invalid'
  | 'unknown'

export interface AdapterResult {
  readonly status: 'completed' | 'failed' | 'unknown'
  readonly correlationId: string
  readonly resourceId?: string
  readonly body?: unknown
  readonly error?: string
  readonly classification: AdapterClassification
}

export interface SandboxCounters {
  readonly mutatingRequests: number
  readonly committedPayments: number
  readonly committedVendorChanges: number
  readonly committedPurchases: number
  readonly committed: number
}

export interface SandboxPayment {
  readonly id: string
  readonly beneficiary: string
  readonly amount: number
  readonly currency: string
  readonly status: string
  readonly reference: string
}

export interface SandboxVendor {
  readonly id: string
  readonly name: string
  readonly iban: string
}

export interface SandboxPurchase {
  readonly id: string
  readonly category: string
  readonly amount: number
  readonly title: string
  readonly status: string
}

/**
 * HTTP adapter for the local sandbox APIs.
 * A POST is never retried. A timeout after the request is sent is unknown until reconcile.
 */
export class HttpSandboxAdapter {
  readonly #base: URL
  readonly #token: string
  readonly #timeoutMs: number
  readonly #faults: boolean
  #fault: 'timeout-before' | 'timeout-after' | null = null

  constructor(options: { baseUrl: string; token: string; timeoutMs?: number; faults?: boolean }) {
    this.#base = assertSandboxBaseUrl(options.baseUrl)
    this.#token = options.token
    this.#timeoutMs = options.timeoutMs ?? 8_000
    this.#faults = options.faults === true
  }

  arm(mode: 'timeout-before' | 'timeout-after' | null): void {
    if (mode && !this.#faults) {
      throw new Error('sandbox fault injection is disabled')
    }
    this.#fault = mode
  }

  async validate(input: AdapterRequest): Promise<{ ok: true } | { ok: false; error: string }> {
    if (!/^[a-f0-9]{64}$/.test(input.intentHash)) return { ok: false, error: 'invalid_intent_hash' }
    if (input.action === 'create_payment' || input.action === 'create_purchase_request') {
      const amount = input.parameters.amount
      if (typeof amount !== 'number' || !Number.isInteger(amount) || amount <= 0) {
        return { ok: false, error: 'invalid_amount' }
      }
    }
    if (input.action === 'create_payment' && input.parameters.currency !== 'EUR') {
      return { ok: false, error: 'invalid_currency' }
    }
    if (input.action === 'update_vendor_account') {
      const iban = input.parameters.iban
      if (typeof iban !== 'string' || !/^[A-Z0-9]{15,34}$/.test(iban)) return { ok: false, error: 'invalid_iban' }
    }
    return { ok: true }
  }

  async healthCheck(): Promise<{ ok: boolean; detail: string }> {
    try {
      const response = await this.#send('GET', '/ready')
      if (!response.ok) return { ok: false, detail: 'sandbox is not ready' }
      return { ok: true, detail: 'sandbox ready' }
    } catch {
      return { ok: false, detail: 'sandbox is unreachable' }
    }
  }

  async execute(input: AdapterRequest): Promise<AdapterResult> {
    const validation = await this.validate(input)
    if (!validation.ok) {
      return {
        status: 'failed',
        correlationId: input.correlationId,
        error: validation.error,
        classification: 'invalid',
      }
    }
    const health = await this.healthCheck()
    if (!health.ok) {
      return {
        status: 'failed',
        correlationId: input.correlationId,
        error: 'downstream_unavailable',
        classification: 'unavailable',
      }
    }
    const faultMode = this.#fault
    try {
      const response = await this.#dispatch(input)
      const body = await response.json().catch(() => null)
      if (response.status === 503) {
        return {
          status: 'failed',
          correlationId: input.correlationId,
          error: 'downstream_unavailable',
          classification: 'unavailable',
        }
      }
      if (response.status >= 400) {
        return {
          status: 'failed',
          correlationId: input.correlationId,
          error: 'downstream_rejected',
          classification: 'rejected',
        }
      }
      const resourceId = resourceIdOf(body)
      return {
        status: 'completed',
        correlationId: input.correlationId,
        resourceId,
        body,
        classification: 'completed',
      }
    } catch (error) {
      if (isTimeout(error)) {
        return {
          status: 'unknown',
          correlationId: input.correlationId,
          error: 'downstream_timeout',
          classification:
            faultMode === 'timeout-before'
              ? 'timeout_before_commit'
              : faultMode === 'timeout-after'
                ? 'timeout_after_commit'
                : 'unknown',
        }
      }
      if (isConnectionRefused(error)) {
        return {
          status: 'failed',
          correlationId: input.correlationId,
          error: 'downstream_unavailable',
          classification: 'unavailable',
        }
      }
      return {
        status: 'unknown',
        correlationId: input.correlationId,
        error: 'downstream_uncertain',
        classification: 'unknown',
      }
    }
  }

  async getStatus(kind: 'payment' | 'vendor' | 'purchase' | 'reconcile', id: string): Promise<AdapterResult> {
    const path =
      kind === 'reconcile'
        ? `/v1/reconcile/${encodeURIComponent(id)}`
        : kind === 'payment'
          ? `/v1/payments/${encodeURIComponent(id)}`
          : kind === 'vendor'
            ? '/v1/vendors'
            : '/v1/purchases'
    try {
      const response = await this.#send('GET', path)
      const body = await response.json().catch(() => null)
      if (!response.ok) {
        return { status: 'failed', correlationId: id, error: 'status_unavailable', classification: 'rejected', body }
      }
      return { status: 'completed', correlationId: id, body, resourceId: resourceIdOf(body), classification: 'completed' }
    } catch (error) {
      if (isTimeout(error) || !isConnectionRefused(error)) {
        return { status: 'unknown', correlationId: id, error: 'status_uncertain', classification: 'unknown' }
      }
      return { status: 'failed', correlationId: id, error: 'downstream_unavailable', classification: 'unavailable' }
    }
  }

  async listPayments(): Promise<SandboxPayment[]> {
    const body = await this.#json('GET', '/v1/payments')
    return Array.isArray(body.payments) ? (body.payments as SandboxPayment[]) : []
  }

  async listVendors(): Promise<SandboxVendor[]> {
    const body = await this.#json('GET', '/v1/vendors')
    return Array.isArray(body.vendors) ? (body.vendors as SandboxVendor[]) : []
  }

  async listPurchases(): Promise<SandboxPurchase[]> {
    const body = await this.#json('GET', '/v1/purchases')
    return Array.isArray(body.purchases) ? (body.purchases as SandboxPurchase[]) : []
  }

  async counters(): Promise<SandboxCounters> {
    const body = await this.#json('GET', '/v1/meta')
    return {
      mutatingRequests: Number(body.mutatingRequests ?? 0),
      committedPayments: Number(body.committedPayments ?? 0),
      committedVendorChanges: Number(body.committedVendorChanges ?? 0),
      committedPurchases: Number(body.committedPurchases ?? 0),
      committed: Number(body.committed ?? 0),
    }
  }

  async reset(): Promise<void> {
    const response = await this.#send('POST', '/v1/admin/reset', { confirm: 'RESET SANDBOX DATA' })
    if (!response.ok) throw new Error('sandbox reset failed')
  }

  async setWrites(accept: boolean): Promise<void> {
    const response = await this.#send('POST', '/v1/admin/writes', { accept })
    if (!response.ok) throw new Error('sandbox write gate failed')
  }

  async close(): Promise<void> {
    this.#fault = null
  }

  toDownstream(result: AdapterResult): DownstreamOutcome {
    if (result.status === 'completed') {
      return { status: 'completed', correlationId: result.correlationId, body: result.body }
    }
    if (result.status === 'unknown') {
      return { status: 'unknown', correlationId: result.correlationId, error: result.error ?? 'downstream_timeout' }
    }
    return { status: 'failed', correlationId: result.correlationId, error: result.error ?? 'downstream_failed' }
  }

  async #dispatch(input: DownstreamRequest | AdapterRequest): Promise<Response> {
    if (input.action === 'get_payment_status') {
      const id = targetId(input.target, 'payments/')
      if (!id) throw new Error('invalid_target')
      return this.#send('GET', `/v1/payments/${encodeURIComponent(id)}`)
    }
    if (input.action === 'create_payment') {
      return this.#send('POST', '/v1/payments', {
        amount: input.parameters.amount,
        currency: input.parameters.currency,
        beneficiary: input.parameters.beneficiary,
        reference: input.parameters.reference,
        intentHash: input.intentHash,
      })
    }
    if (input.action === 'update_vendor_account') {
      const id = targetId(input.target, 'vendors/')
      if (!id) throw new Error('invalid_target')
      return this.#send('POST', `/v1/vendors/${encodeURIComponent(id)}/account`, {
        iban: input.parameters.iban,
        intentHash: input.intentHash,
      })
    }
    if (input.action === 'create_purchase_request') {
      return this.#send('POST', '/v1/purchases', {
        category: input.parameters.category,
        amount: input.parameters.amount,
        title: input.parameters.title,
        intentHash: input.intentHash,
      })
    }
    throw new Error('unsupported_action')
  }

  async #json(method: 'GET' | 'POST', path: string, body?: unknown): Promise<Record<string, unknown>> {
    const response = await this.#send(method, path, body)
    const parsed = await response.json().catch(() => null)
    return parsed != null && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : {}
  }

  #send(method: 'GET' | 'POST', path: string, body?: unknown): Promise<Response> {
    const headers: Record<string, string> = { authorization: `Bearer ${this.#token}` }
    if (body !== undefined) headers['content-type'] = 'application/json'
    if (this.#fault && method === 'POST' && path.startsWith('/v1/') && !path.startsWith('/v1/admin')) {
      headers['x-sandbox-fault'] = this.#fault
      this.#fault = null
    }
    return fetch(new URL(path, this.#base), {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: 'error',
      signal: AbortSignal.timeout(this.#timeoutMs),
    })
  }
}

export function assertSandboxBaseUrl(value: string): URL {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    throw new Error('sandbox URL is invalid')
  }
  if (url.username || url.password || url.search || url.hash) throw new Error('sandbox URL is invalid')
  if (url.protocol === 'http:') {
    const loopback = url.hostname === '127.0.0.1' || url.hostname === 'localhost' || url.hostname === '::1'
    const privateService = /^[a-z0-9-]{1,63}$/.test(url.hostname)
    if (!loopback && !privateService) throw new Error('sandbox HTTP URL must be loopback or a private service name')
  } else if (url.protocol !== 'https:') {
    throw new Error('sandbox URL scheme is not allowed')
  }
  if (url.hostname === '169.254.169.254' || url.hostname === 'metadata' || url.hostname.endsWith('.local')) {
    throw new Error('sandbox URL host is not allowed')
  }
  return url
}

function targetId(target: string, prefix: string): string | null {
  if (!target.startsWith(prefix)) return null
  const id = target.slice(prefix.length)
  if (!/^[A-Za-z0-9_-]+$/.test(id)) return null
  return id
}

function resourceIdOf(body: unknown): string | undefined {
  if (body == null || typeof body !== 'object') return undefined
  const record = body as { resourceId?: unknown; id?: unknown }
  if (typeof record.resourceId === 'string') return record.resourceId
  if (typeof record.id === 'string') return record.id
  return undefined
}

function isTimeout(error: unknown): boolean {
  return error instanceof Error && (error.name === 'TimeoutError' || error.name === 'AbortError')
}

function isConnectionRefused(error: unknown): boolean {
  const cause = error instanceof Error ? (error.cause as { code?: string } | undefined) : undefined
  return cause?.code === 'ECONNREFUSED' || (error instanceof Error && error.message.includes('ECONNREFUSED'))
}
