/**
 * Versioned ADAP signed-object envelope with domain-separated Ed25519 signatures.
 *
 * Profile `0.2` binds adap version, object type, algorithm, key id, and payload.
 * Legacy unversioned objects (no `adap` field) keep bare canonical-JSON signatures
 * and legacy constraint semantics — they must never silently gain authority.
 */

import type { KeyObject } from 'node:crypto'
import { sign, verify } from 'node:crypto'
import { canonicalJson } from './crypto.js'
import { AuthorityError } from './errors.js'

export const ADAP_SIGNED_VERSION = '0.2' as const
export type AdapSignedVersion = typeof ADAP_SIGNED_VERSION

export type SignedObjectType = 'delegation' | 'intent' | 'approval'
export type SignedObjectAlg = 'Ed25519'

/** Constraint interpretation bound to the signed-object profile. */
export type ConstraintProfile = 'legacy-v0.1' | 'ceilings-v1'

export interface SignedEnvelopeFields {
  readonly adap: AdapSignedVersion
  readonly typ: SignedObjectType
  readonly alg: SignedObjectAlg
  readonly kid: string
}

export interface SignedEnvelope<T> extends SignedEnvelopeFields {
  readonly payload: T
  readonly signature: string
}

export type UnsignedEnvelope<T> = Omit<SignedEnvelope<T>, 'signature'>

function domainPrefix(version: string, typ: SignedObjectType): Buffer {
  return Buffer.from(`ADAP/${version}/${typ}\0`, 'utf8')
}

function unsignedBody<T>(envelope: UnsignedEnvelope<T>): UnsignedEnvelope<T> {
  return {
    adap: envelope.adap,
    typ: envelope.typ,
    alg: envelope.alg,
    kid: envelope.kid,
    payload: envelope.payload,
  }
}

/** Domain-separated signing preimage for a versioned envelope (excludes signature). */
export function signedObjectPreimage<T>(envelope: UnsignedEnvelope<T>): Buffer {
  if (envelope.adap !== ADAP_SIGNED_VERSION) {
    throw new AuthorityError('signature', `unsupported adap signed-object version: ${envelope.adap}`, false)
  }
  if (envelope.alg !== 'Ed25519') {
    throw new AuthorityError('signature', `unsupported signature algorithm: ${envelope.alg}`, false)
  }
  const body = canonicalJson(unsignedBody(envelope))
  return Buffer.concat([domainPrefix(envelope.adap, envelope.typ), Buffer.from(body, 'utf8')])
}

export function signEnvelope<T>(
  fields: Omit<UnsignedEnvelope<T>, 'adap' | 'alg'> & { readonly adap?: AdapSignedVersion; readonly alg?: SignedObjectAlg },
  privateKey: KeyObject
): SignedEnvelope<T> {
  const envelope: UnsignedEnvelope<T> = {
    adap: fields.adap ?? ADAP_SIGNED_VERSION,
    typ: fields.typ,
    alg: fields.alg ?? 'Ed25519',
    kid: fields.kid,
    payload: fields.payload,
  }
  const signature = sign(null, signedObjectPreimage(envelope), privateKey).toString('base64url')
  return { ...envelope, signature }
}

export function verifyEnvelopeSignature<T>(
  envelope: SignedEnvelope<T>,
  publicKey: KeyObject,
  expectedTyp: SignedObjectType
): boolean {
  if (envelope.adap !== ADAP_SIGNED_VERSION) return false
  if (envelope.typ !== expectedTyp) return false
  if (envelope.alg !== 'Ed25519') return false
  if (typeof envelope.kid !== 'string' || envelope.kid.length === 0) return false
  if (typeof envelope.signature !== 'string' || envelope.signature.length === 0) return false
  try {
    const { signature, ...unsigned } = envelope
    return verify(null, signedObjectPreimage(unsigned), publicKey, Buffer.from(signature, 'base64url'))
  } catch {
    return false
  }
}

export function isVersionedEnvelope(value: unknown): value is SignedEnvelope<unknown> {
  if (value == null || typeof value !== 'object' || Array.isArray(value)) return false
  const record = value as Record<string, unknown>
  return typeof record.adap === 'string' && typeof record.typ === 'string' && 'payload' in record
}

export function constraintProfileOf(value: unknown): ConstraintProfile {
  if (isVersionedEnvelope(value) && value.adap === ADAP_SIGNED_VERSION) return 'ceilings-v1'
  return 'legacy-v0.1'
}

/** Resolve the inner payload for either a legacy signed object or a versioned envelope. */
export function delegationPayloadOf(
  value: SignedEnvelope<Record<string, unknown>> | Record<string, unknown>
): Record<string, unknown> {
  if (isVersionedEnvelope(value)) {
    if (value.typ !== 'delegation') {
      throw new AuthorityError('signature', 'signed object type is not delegation', true)
    }
    return value.payload as Record<string, unknown>
  }
  const { signature: _s, adap: _a, typ: _t, alg: _g, kid: _k, payload: _p, ...rest } = value as Record<
    string,
    unknown
  >
  return rest
}
