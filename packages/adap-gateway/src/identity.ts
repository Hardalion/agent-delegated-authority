/**
 * Production identity verification interfaces.
 * ADAP is not an identity provider. Deployments plug verified keys into the directory.
 */

import { importPublicKey, verifyObject, AuthorityError } from 'adap'

export type KeyStatus = 'active' | 'revoked' | 'expired'

export interface DirectoryKey {
  readonly keyId: string
  readonly subjectId: string
  readonly algorithm: 'Ed25519'
  readonly publicKeyPemOrRaw: string
  readonly status: KeyStatus
  readonly notBefore?: string
  readonly notAfter?: string
  readonly issuer?: string
  readonly audience?: string
  readonly kind: 'human' | 'workload' | 'agent' | 'service'
}

export interface IdentityDirectory {
  lookup(subjectId: string): DirectoryKey | undefined
  lookupByKeyId(keyId: string): DirectoryKey | undefined
}

export class StaticIdentityDirectory implements IdentityDirectory {
  private readonly bySubject = new Map<string, DirectoryKey>()
  private readonly byKeyId = new Map<string, DirectoryKey>()

  constructor(keys: readonly DirectoryKey[] = []) {
    for (const key of keys) this.put(key)
  }

  put(key: DirectoryKey): void {
    if (key.algorithm !== 'Ed25519') {
      throw new AuthorityError('signature', 'unsupported algorithm', true)
    }
    this.bySubject.set(key.subjectId, key)
    this.byKeyId.set(key.keyId, key)
  }

  lookup(subjectId: string): DirectoryKey | undefined {
    return this.bySubject.get(subjectId)
  }

  lookupByKeyId(keyId: string): DirectoryKey | undefined {
    return this.byKeyId.get(keyId)
  }
}

export function assertUsableKey(key: DirectoryKey | undefined, now: Date, opts?: {
  readonly expectedKind?: DirectoryKey['kind']
  readonly issuer?: string
  readonly audience?: string
}): DirectoryKey {
  if (!key) throw new AuthorityError('signature', 'unknown identity', true)
  if (key.status === 'revoked') throw new AuthorityError('signature', 'key revoked', true)
  if (key.status === 'expired') throw new AuthorityError('signature', 'key expired', true)
  if (key.algorithm !== 'Ed25519') {
    throw new AuthorityError('signature', 'algorithm confusion rejected', true)
  }
  if (opts?.expectedKind && key.kind !== opts.expectedKind) {
    throw new AuthorityError('signature', 'wrong identity kind', true)
  }
  if (opts?.issuer && key.issuer !== opts.issuer) {
    throw new AuthorityError('signature', 'invalid issuer', true)
  }
  if (opts?.audience && key.audience !== opts.audience) {
    throw new AuthorityError('signature', 'invalid audience', true)
  }
  const t = now.getTime()
  if (key.notBefore && Date.parse(key.notBefore) > t) {
    throw new AuthorityError('signature', 'key not yet valid', true)
  }
  if (key.notAfter && Date.parse(key.notAfter) <= t) {
    throw new AuthorityError('signature', 'key expired', true)
  }
  // Ensure material parses
  importPublicKey(key.publicKeyPemOrRaw)
  return key
}

export function verifySignedPayload(
  payload: unknown,
  signatureHex: string,
  key: DirectoryKey,
): boolean {
  return verifyObject(payload as Record<string, unknown>, signatureHex, importPublicKey(key.publicKeyPemOrRaw))
}

/** Build the Map<string, string> directory expected by runAuthorityPath. */
export function toAuthorityDirectory(
  identity: IdentityDirectory,
  subjectIds: readonly string[],
  now: Date,
): Map<string, string> {
  const out = new Map<string, string>()
  for (const id of subjectIds) {
    const key = assertUsableKey(identity.lookup(id), now)
    out.set(id, key.publicKeyPemOrRaw)
  }
  return out
}
