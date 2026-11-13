/**
 * Identity directory keyed by (identityId, kid).
 * Legacy callers that only hold Map<id, publicKey> are adapted via
 * `directoryFromPublicKeyMap` (single synthetic kid per identity).
 */

import { AuthorityError } from './errors.js'
import { importPublicKey, publicKeyFingerprint } from './crypto.js'

export type DirectoryKeyStatus = 'active' | 'revoked' | 'expired'
export type DirectoryIdentityKind = 'human' | 'agent' | 'service' | 'workload'

export interface DirectoryKeyRecord {
  readonly identityId: string
  readonly kid: string
  readonly alg: 'Ed25519'
  readonly publicKey: string
  readonly status: DirectoryKeyStatus
  readonly notBefore?: string
  readonly notAfter?: string
  readonly kind?: DirectoryIdentityKind
}

export interface AuthorityDirectory {
  /** Resolve a key. When kid is omitted, returns the sole active key for legacy verification. */
  lookup(identityId: string, kid?: string): DirectoryKeyRecord | undefined
  /** All keys for an identity (including revoked), for diagnostics. */
  list(identityId: string): readonly DirectoryKeyRecord[]
}

export class MemoryAuthorityDirectory implements AuthorityDirectory {
  private readonly byPair = new Map<string, DirectoryKeyRecord>()
  private readonly byIdentity = new Map<string, DirectoryKeyRecord[]>()

  constructor(keys: readonly DirectoryKeyRecord[] = []) {
    for (const key of keys) this.put(key)
  }

  put(key: DirectoryKeyRecord): void {
    if (key.alg !== 'Ed25519') {
      throw new AuthorityError('signature', 'unsupported algorithm', true)
    }
    importPublicKey(key.publicKey)
    const pair = pairKey(key.identityId, key.kid)
    this.byPair.set(pair, key)
    const list = this.byIdentity.get(key.identityId) ?? []
    const next = list.filter((item) => item.kid !== key.kid)
    next.push(key)
    this.byIdentity.set(key.identityId, next)
  }

  lookup(identityId: string, kid?: string): DirectoryKeyRecord | undefined {
    if (kid != null && kid.length > 0) {
      return this.byPair.get(pairKey(identityId, kid))
    }
    const keys = this.byIdentity.get(identityId) ?? []
    const active = keys.filter((key) => key.status === 'active')
    if (active.length === 1) return active[0]
    return undefined
  }

  list(identityId: string): readonly DirectoryKeyRecord[] {
    return [...(this.byIdentity.get(identityId) ?? [])]
  }
}

function pairKey(identityId: string, kid: string): string {
  return `${identityId}\0${kid}`
}

/** Adapt a legacy id→publicKey map. Each identity gets one active key with fingerprint kid. */
export function directoryFromPublicKeyMap(
  map: ReadonlyMap<string, string>,
  options?: { readonly kind?: DirectoryIdentityKind }
): MemoryAuthorityDirectory {
  const directory = new MemoryAuthorityDirectory()
  for (const [identityId, publicKey] of map) {
    directory.put({
      identityId,
      kid: publicKeyFingerprint(publicKey),
      alg: 'Ed25519',
      publicKey,
      status: 'active',
      kind: options?.kind,
    })
  }
  return directory
}

export function assertUsableDirectoryKey(
  key: DirectoryKeyRecord | undefined,
  now: Date,
  opts?: {
    readonly requireKid?: string
    readonly expectedKind?: DirectoryIdentityKind
    readonly allowRevokedForHistoricalVerify?: boolean
  }
): DirectoryKeyRecord {
  if (!key) throw new AuthorityError('signature', 'unknown identity or kid', true)
  if (opts?.requireKid && key.kid !== opts.requireKid) {
    throw new AuthorityError('signature', 'kid mismatch', true)
  }
  if (key.alg !== 'Ed25519') {
    throw new AuthorityError('signature', 'unsupported algorithm', true)
  }
  if (key.status === 'revoked' && !opts?.allowRevokedForHistoricalVerify) {
    throw new AuthorityError('signature', 'key revoked', true)
  }
  if (key.status === 'expired') {
    throw new AuthorityError('signature', 'key expired', true)
  }
  if (opts?.expectedKind && key.kind != null && key.kind !== opts.expectedKind) {
    throw new AuthorityError('signature', 'wrong identity kind', true)
  }
  const t = now.getTime()
  if (key.notBefore && Date.parse(key.notBefore) > t) {
    throw new AuthorityError('signature', 'key not yet valid', true)
  }
  if (key.notAfter && Date.parse(key.notAfter) <= t) {
    throw new AuthorityError('signature', 'key expired', true)
  }
  importPublicKey(key.publicKey)
  return key
}

export function isAuthorityDirectory(value: unknown): value is AuthorityDirectory {
  return (
    value != null &&
    typeof value === 'object' &&
    typeof (value as AuthorityDirectory).lookup === 'function' &&
    typeof (value as AuthorityDirectory).list === 'function'
  )
}

export function resolveAuthorityDirectory(
  directory: AuthorityDirectory | ReadonlyMap<string, string>
): AuthorityDirectory {
  if (isAuthorityDirectory(directory)) return directory
  return directoryFromPublicKeyMap(directory)
}
