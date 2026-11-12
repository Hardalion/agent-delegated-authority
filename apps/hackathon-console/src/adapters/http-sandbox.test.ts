import { afterEach, describe, expect, it, vi } from 'vitest'
import { HttpSandboxAdapter } from './http-sandbox.js'

afterEach(() => {
  vi.restoreAllMocks()
})

function timeoutError(): Error {
  const error = new Error('aborted')
  error.name = 'TimeoutError'
  return error
}

describe('HttpSandboxAdapter timeout classification', () => {
  it('labels timeout-before faults as timeout_before_commit after the fault is consumed', async () => {
    const adapter = new HttpSandboxAdapter({
      baseUrl: 'http://127.0.0.1:9',
      token: 'sandbox-token-test-0123456789',
      timeoutMs: 50,
      faults: true,
    })
    adapter.arm('timeout-before')
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input)
      if (url.endsWith('/ready')) {
        return new Response(JSON.stringify({ ready: true }), { status: 200 })
      }
      const headers = new Headers(init?.headers)
      expect(headers.get('x-sandbox-fault')).toBe('timeout-before')
      throw timeoutError()
    })
    const result = await adapter.execute({
      action: 'create_payment',
      target: 'payments/outgoing',
      parameters: { amount: 12000, currency: 'EUR', beneficiary: 'vendor_acme', purpose: 'treasury.sandbox' },
      intentHash: 'a'.repeat(64),
      correlationId: 'corr-before',
    })
    expect(result.status).toBe('unknown')
    expect(result.classification).toBe('timeout_before_commit')
  })

  it('labels timeout-after faults as timeout_after_commit', async () => {
    const adapter = new HttpSandboxAdapter({
      baseUrl: 'http://127.0.0.1:9',
      token: 'sandbox-token-test-0123456789',
      timeoutMs: 50,
      faults: true,
    })
    adapter.arm('timeout-after')
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.endsWith('/ready')) {
        return new Response(JSON.stringify({ ready: true }), { status: 200 })
      }
      throw timeoutError()
    })
    const result = await adapter.execute({
      action: 'create_payment',
      target: 'payments/outgoing',
      parameters: { amount: 12000, currency: 'EUR', beneficiary: 'vendor_acme', purpose: 'treasury.sandbox' },
      intentHash: 'b'.repeat(64),
      correlationId: 'corr-after',
    })
    expect(result.status).toBe('unknown')
    expect(result.classification).toBe('timeout_after_commit')
  })

  it('labels real timeouts without a fault as unknown', async () => {
    const adapter = new HttpSandboxAdapter({
      baseUrl: 'http://127.0.0.1:9',
      token: 'sandbox-token-test-0123456789',
      timeoutMs: 50,
    })
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input)
      if (url.endsWith('/ready')) {
        return new Response(JSON.stringify({ ready: true }), { status: 200 })
      }
      throw timeoutError()
    })
    const result = await adapter.execute({
      action: 'create_payment',
      target: 'payments/outgoing',
      parameters: { amount: 12000, currency: 'EUR', beneficiary: 'vendor_acme', purpose: 'treasury.sandbox' },
      intentHash: 'c'.repeat(64),
      correlationId: 'corr-real',
    })
    expect(result.status).toBe('unknown')
    expect(result.classification).toBe('unknown')
  })
})
