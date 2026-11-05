import { afterEach, describe, expect, it, vi } from 'vitest'
import { VaultCredentialBroker } from './vault-broker.js'

const VAULT_URL = 'https://vault.internal/v1/secret/data/adap/rail'
const WRITE_PREFIX = 'https://payments.internal/api/write'
const RAIL_TOKEN = 'test-rail-token-123456'

function vaultResponse(writeUrl: string): Response {
  return new Response(JSON.stringify({
    data: { data: { token: RAIL_TOKEN, writeUrl } },
  }), { status: 200, headers: { 'content-type': 'application/json' } })
}

function broker(): VaultCredentialBroker {
  return new VaultCredentialBroker({
    address: 'https://vault.internal',
    token: 'vault-test-token',
    secretPath: 'secret/data/adap/rail',
    writeUrlPrefix: WRITE_PREFIX,
  })
}

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('VaultCredentialBroker downstream URL validation', () => {
  it('rejects a hostname that only textually starts with the configured host', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      vaultResponse('https://payments.internal.attacker.example/api/write'),
    )
    vi.stubGlobal('fetch', fetchMock)

    await expect(broker().resolveHandle('apply', 'resource/123'))
      .rejects.toThrow('downstream url rejected')

    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it.each([
    'http://payments.internal/api/write',
    'https://user:pass@payments.internal/api/write',
    'https://payments.internal/api/write-evil',
    'https://payments.internal/api/write?redirect=https://attacker.example',
    'https://payments.internal/api/write#fragment',
    'https://payments.internal.evil/api/write',
  ])('rejects unsafe or out-of-scope URL: %s', async (writeUrl) => {
    const fetchMock = vi.fn().mockResolvedValue(vaultResponse(writeUrl))
    vi.stubGlobal('fetch', fetchMock)

    await expect(broker().resolveHandle('apply', 'resource/123'))
      .rejects.toThrow('downstream url rejected')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('accepts a URL inside the configured HTTPS origin and path scope', async () => {
    const fetchMock = vi.fn().mockResolvedValue(vaultResponse(
      'https://PAYMENTS.internal:443/api/write/v2',
    ))
    vi.stubGlobal('fetch', fetchMock)

    await expect(broker().resolveHandle('apply', 'resource/123'))
      .resolves.toBe('vault:secret/data/adap/rail')
  })

  it('disables redirects on credential-bearing downstream writes', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(vaultResponse('https://payments.internal/api/write'))
      .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }))
    vi.stubGlobal('fetch', fetchMock)

    const outcome = await broker().execute('vault:secret/data/adap/rail', {
      action: 'apply',
      target: 'resource/123',
      parameters: {},
      intentHash: 'intent-hash',
      correlationId: 'correlation-id',
    })

    expect(outcome.status).toBe('completed')
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(fetchMock.mock.calls[1]?.[1]).toMatchObject({ redirect: 'error' })
  })

  it('disables redirects on credential-bearing lookup requests', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(vaultResponse('https://payments.internal/api/write'))
      .mockResolvedValueOnce(new Response(JSON.stringify({ found: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(broker().lookup('intent-hash')).resolves.toEqual({ found: true })
    expect(fetchMock.mock.calls[1]?.[1]).toMatchObject({ redirect: 'error' })
  })
})
