import { classifyHttpStatus, type CredentialBroker, type DownstreamOutcome, type DownstreamRequest, type SecretHandle } from './credentials.js'

interface RailSecret {
  readonly token: string
  readonly writeUrl: string
}

export interface VaultCredentialBrokerOptions {
  readonly address: string
  readonly token: string
  /** Vault KV v2 data path, for example `secret/data/adap/rail`. */
  readonly secretPath: string
  /** HTTPS URL whose origin and path scope constrain the downstream write URL. */
  readonly writeUrlPrefix: string
  readonly timeoutMs?: number
}

/**
 * Reads the rail credential from Vault on each call. The token is not returned
 * to the caller and is not included in errors.
 */
export class VaultCredentialBroker implements CredentialBroker {
  constructor(private readonly options: VaultCredentialBrokerOptions) {}

  async resolveHandle(action: string, target: string): Promise<SecretHandle> {
    if (action !== 'apply') {
      throw new Error('no credential handle for authorized route')
    }
    if (!target.startsWith('resource/')) {
      throw new Error('no credential handle for authorized route')
    }
    await this.readSecret()
    return `vault:${this.options.secretPath}`
  }

  async execute(handle: SecretHandle, request: DownstreamRequest): Promise<DownstreamOutcome> {
    if (handle !== `vault:${this.options.secretPath}`) {
      return { status: 'failed', correlationId: request.correlationId, error: 'unknown_handle' }
    }
    const secret = await this.readSecret()
    try {
      const res = await fetch(secret.writeUrl, {
        method: 'POST',
        redirect: 'error',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${secret.token}`,
          'x-adap-intent-hash': request.intentHash,
          'x-adap-correlation-id': request.correlationId,
        },
        body: JSON.stringify({
          action: request.action,
          target: request.target,
          parameters: request.parameters,
          intentHash: request.intentHash,
        }),
        signal: AbortSignal.timeout(this.options.timeoutMs ?? 10_000),
      })
      const classified = classifyHttpStatus(res.status)
      if (classified === 'accepted') {
        return { status: 'accepted', correlationId: request.correlationId }
      }
      if (classified === 'failed' || classified === 'unknown') {
        return {
          status: classified,
          correlationId: request.correlationId,
          error: `downstream_http_${res.status}`,
        }
      }
      const body = await res.json().catch(() => null)
      return { status: 'completed', correlationId: request.correlationId, body }
    } catch {
      return { status: 'unknown', correlationId: request.correlationId, error: 'downstream_unreachable' }
    }
  }

  /** Read-only reconciliation. Does not POST. */
  async lookup(intentHash: string): Promise<{ readonly found: boolean }> {
    const secret = await this.readSecret()
    const url = new URL('/ledger', secret.writeUrl)
    url.searchParams.set('intentHash', intentHash)
    const res = await fetch(url, {
      redirect: 'error',
      headers: { authorization: `Bearer ${secret.token}` },
      signal: AbortSignal.timeout(this.options.timeoutMs ?? 10_000),
    })
    if (!res.ok) throw new Error('downstream lookup failed')
    const body = (await res.json()) as { found?: boolean }
    return { found: body.found === true }
  }

  private async readSecret(): Promise<RailSecret> {
    const url = new URL(`/v1/${this.options.secretPath.replace(/^\/+/, '')}`, this.options.address)
    let res: Response
    try {
      res = await fetch(url, {
        headers: { 'x-vault-token': this.options.token },
        signal: AbortSignal.timeout(this.options.timeoutMs ?? 5_000),
      })
    } catch {
      throw new Error('credential store unavailable')
    }
    if (!res.ok) throw new Error('credential store unavailable')
    const payload = (await res.json()) as { data?: { data?: { token?: unknown; writeUrl?: unknown } } }
    const token = payload.data?.data?.token
    const writeUrl = payload.data?.data?.writeUrl
    if (typeof token !== 'string' || token.length < 16) throw new Error('credential store unavailable')
    if (typeof writeUrl !== 'string' || !isAllowedDownstreamUrl(writeUrl, this.options.writeUrlPrefix)) {
      throw new Error('downstream url rejected')
    }
    return { token, writeUrl: new URL(writeUrl).toString() }
  }
}

/**
 * Treat the configured value as an HTTPS origin + path scope, not as a
 * string prefix. URL parsing also normalizes host casing and default ports.
 */
function isAllowedDownstreamUrl(writeUrl: string, configuredPrefix: string): boolean {
  try {
    const destination = new URL(writeUrl)
    const allowed = new URL(configuredPrefix)

    if (
      destination.protocol !== 'https:' ||
      allowed.protocol !== 'https:' ||
      destination.origin !== allowed.origin ||
      destination.username !== '' ||
      destination.password !== '' ||
      destination.hash !== '' ||
      destination.search !== '' ||
      allowed.username !== '' ||
      allowed.password !== '' ||
      allowed.hash !== '' ||
      allowed.search !== ''
    ) {
      return false
    }

    const allowedPath = allowed.pathname.endsWith('/') ? allowed.pathname.replace(/\/+$/, '') || '/' : allowed.pathname
    const destinationPath = destination.pathname
    return allowedPath === '/'
      ? destinationPath.startsWith('/')
      : destinationPath === allowedPath || destinationPath.startsWith(`${allowedPath}/`)
  } catch {
    return false
  }
}
