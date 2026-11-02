/**
 * Trusted immutable policy pin resolver.
 *
 * Continuation of REQUIRE_HUMAN must resolve the policy by content hash through a
 * trusted registry. Caller-supplied Policy objects are not authoritative on resume.
 */

import type { Policy } from 'adap-policy'
import { PolicySchema } from 'adap-policy'
import { AuthorityError } from './errors.js'
import { sha256 } from './crypto.js'

export interface ImmutablePolicyBinding {
  readonly uri: string
  readonly policy: Policy
  readonly contentHash: string
}

export interface PolicyResolver {
  /** Register an immutable policy document under its content hash. */
  register(policy: Policy, uri: string): ImmutablePolicyBinding
  /** Resolve by content hash. Fails closed if unknown or mutated. */
  resolveByContentHash(contentHash: string): ImmutablePolicyBinding
  /** Resolve by URI pin when the document was previously registered under that URI. */
  resolveByUri(uri: string): ImmutablePolicyBinding | undefined
}

export class ImmutablePolicyResolver implements PolicyResolver {
  private readonly byHash = new Map<string, ImmutablePolicyBinding>()
  private readonly byUri = new Map<string, string>()

  register(policy: Policy, uri: string): ImmutablePolicyBinding {
    if (typeof uri !== 'string' || uri.length === 0) {
      throw new AuthorityError('policy', 'policy URI is required')
    }
    const parsed = PolicySchema.parse(policy)
    const contentHash = sha256(parsed)
    const priorHash = this.byUri.get(uri)
    if (priorHash && priorHash !== contentHash) {
      throw new AuthorityError('policy', 'policy URI already bound to a different immutable content hash')
    }
    const existing = this.byHash.get(contentHash)
    if (existing) {
      if (existing.uri !== uri) {
        throw new AuthorityError('policy', 'policy content hash already registered under a different URI')
      }
      return existing
    }
    if (priorHash === contentHash) {
      throw new AuthorityError('policy', 'policy URI binding is missing its content', true)
    }
    const pin: ImmutablePolicyBinding = { uri, policy: parsed, contentHash }
    this.byHash.set(contentHash, pin)
    this.byUri.set(uri, contentHash)
    return pin
  }

  resolveByContentHash(contentHash: string): ImmutablePolicyBinding {
    const pin = this.byHash.get(contentHash)
    if (!pin) {
      throw new AuthorityError('policy', 'unknown policy content hash', true)
    }
    if (sha256(pin.policy) !== contentHash) {
      throw new AuthorityError('policy', 'policy content hash mismatch', true)
    }
    return pin
  }

  resolveByUri(uri: string): ImmutablePolicyBinding | undefined {
    const hash = this.byUri.get(uri)
    if (!hash) return undefined
    return this.resolveByContentHash(hash)
  }
}

/** Ensure the presented policy object matches the expected immutable hash. */
export function assertPolicyContentHash(policy: Policy, expectedHash: string): string {
  const parsed = PolicySchema.parse(policy)
  const actual = sha256(parsed)
  if (actual !== expectedHash) {
    throw new AuthorityError('policy', 'presented policy does not match bound content hash', true)
  }
  return actual
}
