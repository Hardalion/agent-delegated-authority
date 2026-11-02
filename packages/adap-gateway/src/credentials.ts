/**
 * Credential broker boundary.
 *
 * Agents never receive rail credentials. The gateway holds a handle and performs
 * the downstream call after authorization. A real vault/KMS is outside this repo.
 */

export type SecretHandle = string

export interface DownstreamRequest {
  readonly action: string
  readonly target: string
  readonly parameters: Readonly<Record<string, unknown>>
  readonly intentHash: string
  readonly correlationId: string
}

export type DownstreamOutcome =
  | { readonly status: 'completed'; readonly correlationId: string; readonly body: unknown }
  | { readonly status: 'accepted'; readonly correlationId: string }
  | { readonly status: 'failed'; readonly correlationId: string; readonly error: string }
  | { readonly status: 'unknown'; readonly correlationId: string; readonly error: string }

export interface CredentialBroker {
  /** Resolve the least-privilege handle for an authorized action/target. Never returns raw secrets to callers. */
  resolveHandle(action: string, target: string): Promise<SecretHandle>
  /** Execute using a handle that never leaves the broker. */
  execute(handle: SecretHandle, request: DownstreamRequest): Promise<DownstreamOutcome>
}

/**
 * Test double: stores opaque tokens, never exposes them through public APIs.
 * Production deployments replace this with a vault-backed broker.
 */
export class MemoryCredentialBroker implements CredentialBroker {
  private readonly handles = new Map<string, { readonly token: string; readonly writeUrl: string }>()
  private readonly allowed = new Map<string, string>()

  registerRoute(action: string, targetPattern: string, token: string, writeUrl: string): SecretHandle {
    const handle = `hdl_${action}_${targetPattern}_${this.handles.size}`
    this.handles.set(handle, { token, writeUrl })
    this.allowed.set(`${action}|${targetPattern}`, handle)
    return handle
  }

  async resolveHandle(action: string, target: string): Promise<SecretHandle> {
    for (const [key, handle] of this.allowed) {
      const [a, pattern] = key.split('|')
      if (a !== action) continue
      if (matchTarget(pattern, target)) return handle
    }
    throw new Error('no credential handle for authorized route')
  }

  async execute(handle: SecretHandle, request: DownstreamRequest): Promise<DownstreamOutcome> {
    const secret = this.handles.get(handle)
    if (!secret) {
      return { status: 'failed', correlationId: request.correlationId, error: 'unknown_handle' }
    }
    // Intentionally do not return secret.token to the caller.
    try {
      const res = await fetch(secret.writeUrl, {
        method: 'POST',
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
        signal: AbortSignal.timeout(10_000),
      })
      const classified = classifyHttpStatus(res.status)
      if (classified === 'failed' || classified === 'unknown') {
        return {
          status: classified,
          correlationId: request.correlationId,
          error: `downstream_http_${res.status}`,
        }
      }
      if (classified === 'accepted') {
        return { status: 'accepted', correlationId: request.correlationId }
      }
      const body = await res.json().catch(() => null)
      return { status: 'completed', correlationId: request.correlationId, body }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'downstream_error'
      if (message.includes('Timeout') || message.includes('abort')) {
        return { status: 'unknown', correlationId: request.correlationId, error: message }
      }
      return { status: 'failed', correlationId: request.correlationId, error: message }
    }
  }

  /** Test helper: prove tokens are not enumerable from the public surface. */
  listPublicHandles(): readonly SecretHandle[] {
    return [...this.handles.keys()]
  }
}

export function classifyHttpStatus(
  status: number,
): 'completed' | 'accepted' | 'failed' | 'unknown' {
  if (status === 202) return 'accepted'
  if (status >= 200 && status < 300) return 'completed'
  if (status >= 400 && status < 500) return 'failed'
  return 'unknown'
}

function matchTarget(pattern: string, target: string): boolean {
  if (pattern.endsWith('/*')) {
    const prefix = pattern.slice(0, -1)
    return target.startsWith(prefix)
  }
  return pattern === target
}
