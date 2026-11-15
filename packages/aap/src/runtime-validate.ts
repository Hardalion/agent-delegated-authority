/**
 * Centralized strict runtime validation for ADAP security inputs.
 * TypeScript types are not a security boundary.
 */

import { AuthorityError } from './errors.js'
import { assertCanonicalAmount, isMaxAmountKey } from './amount.js'
import { hasOwn, toDataRecord, assertSafeKey, isPlainDataObject } from './safe-object.js'
import type {
  Capability,
  Constraints,
  HumanApproval,
  IntentPayload,
  SignedDelegation,
  SignedIntent,
} from './protocol.js'

/** Nonce: non-empty string, max 128, unreserved URL-safe charset (RFC 3986). */
export const NONCE_MAX_LENGTH = 128
export const NONCE_PATTERN = /^[A-Za-z0-9._~-]{1,128}$/

export const IDENTITY_MAX_LENGTH = 128
export const IDENTITY_PATTERN = /^[A-Za-z0-9:_./@-]{1,128}$/

const ISO_DATETIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/

export function assertValidNonce(value: unknown): string {
  if (typeof value !== 'string') {
    throw new AuthorityError('nonce', 'nonce must be a non-empty string', true)
  }
  if (value.length === 0 || value.length > NONCE_MAX_LENGTH) {
    throw new AuthorityError('nonce', `nonce length must be 1..${NONCE_MAX_LENGTH}`, true)
  }
  if (!NONCE_PATTERN.test(value)) {
    throw new AuthorityError(
      'nonce',
      'nonce must match [A-Za-z0-9._~-] (no objects, arrays, or whitespace)',
      true
    )
  }
  return value
}

export function assertValidIdentity(value: unknown, path: string): string {
  if (value === undefined) {
    throw new AuthorityError('identity', `${path} is required`, true)
  }
  if (typeof value !== 'string') {
    throw new AuthorityError('identity', `${path} must be a string`, true)
  }
  if (value.length === 0) {
    throw new AuthorityError('identity', `${path} must not be empty`, true)
  }
  if (value.trim() !== value || /\s/.test(value)) {
    throw new AuthorityError('identity', `${path} must not contain whitespace`, true)
  }
  if (value.length > IDENTITY_MAX_LENGTH || !IDENTITY_PATTERN.test(value)) {
    throw new AuthorityError('identity', `${path} is malformed`, true)
  }
  return value
}

export function assertIsoTimestamp(value: unknown, path: string): string {
  if (typeof value !== 'string' || !ISO_DATETIME.test(value)) {
    throw new AuthorityError('schema', `${path} must be ISO-8601 UTC`, true)
  }
  if (!Number.isFinite(Date.parse(value))) {
    throw new AuthorityError('schema', `${path} is not a valid instant`, true)
  }
  return value
}

function assertStringField(value: unknown, path: string, min = 1, max = 256): string {
  if (typeof value !== 'string' || value.length < min || value.length > max) {
    throw new AuthorityError('schema', `${path} must be a string of length ${min}..${max}`, true)
  }
  return value
}

function assertHexSignature(value: unknown, path: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256) {
    throw new AuthorityError('schema', `${path} must be a non-empty signature string`, true)
  }
  return value
}

export function normalizeConstraints(raw: unknown, path = 'constraints'): Constraints {
  const record = toDataRecord(raw, path)
  const out: Record<string, string | number | boolean> = Object.create(null)
  for (const key of Object.keys(record)) {
    assertSafeKey(key, path)
    const value = record[key]
    if (isMaxAmountKey(key)) {
      out[key] = assertCanonicalAmount(value, `${path}.${key}`)
      continue
    }
    if (key === 'currency') {
      out[key] = assertCanonicalCurrency(value, `${path}.${key}`)
      continue
    }
    if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'boolean') {
      throw new AuthorityError('schema', `${path}.${key} has unsupported type`, true)
    }
    if (typeof value === 'number') {
      if (!Number.isFinite(value) || !Number.isSafeInteger(value)) {
        throw new AuthorityError('schema', `${path}.${key} must be a finite safe integer`, true)
      }
      out[key] = value
      continue
    }
    out[key] = value
  }
  return out as Constraints
}

export function normalizeParameters(
  raw: unknown,
  path = 'parameters'
): Readonly<Record<string, unknown>> {
  const record = toDataRecord(raw, path)
  const out: Record<string, unknown> = Object.create(null)
  for (const key of Object.keys(record)) {
    assertSafeKey(key, path)
    const value = record[key]
    if (key === 'amount' || isMaxAmountKey(key)) {
      out[key] = assertCanonicalAmount(value, `${path}.${key}`)
      continue
    }
    if (value != null && typeof value === 'object') {
      if (Array.isArray(value)) {
        out[key] = value.map((item, index) =>
          item != null && typeof item === 'object'
            ? normalizeParameters(item, `${path}.${key}[${index}]`)
            : item
        )
      } else {
        out[key] = normalizeParameters(value, `${path}.${key}`)
      }
      continue
    }
    if (typeof value === 'number' && !Number.isFinite(value)) {
      throw new AuthorityError('schema', `${path}.${key} must be finite`, true)
    }
    out[key] = value
  }
  return out
}

function normalizeCapability(raw: unknown, path: string): Capability {
  if (!isPlainDataObject(raw)) {
    throw new AuthorityError('schema', `${path} must be an object`, true)
  }
  const action = assertStringField(raw.action, `${path}.action`, 1, 128)
  if (!hasOwn(raw, 'target') || raw.target == null) {
    throw new AuthorityError('target', `${path}.target is required`, true)
  }
  const capability: Capability = {
    action,
    target: assertCanonicalTarget(assertStringField(raw.target, `${path}.target`, 1, 512), { grant: true }),
  }
  if (hasOwn(raw, 'delegable')) {
    if (typeof raw.delegable !== 'boolean') {
      throw new AuthorityError('schema', `${path}.delegable must be boolean`, true)
    }
    ;(capability as { delegable?: boolean }).delegable = raw.delegable
  }
  return capability
}

export function validateIntentPayload(raw: unknown): IntentPayload {
  if (!isPlainDataObject(raw)) {
    throw new AuthorityError('schema', 'intent must be a plain object')
  }
  const required = [
    'intent_id',
    'actor',
    'delegation_chain',
    'action',
    'target',
    'parameters',
    'nonce',
    'issued_at',
    'expires_at',
  ] as const
  for (const key of required) {
    if (!hasOwn(raw, key) || raw[key] === null) {
      throw new AuthorityError('schema', `intent.${key} is required`)
    }
  }
  for (const key of Object.keys(raw)) {
    assertSafeKey(key, 'intent')
  }

  if (!Array.isArray(raw.delegation_chain) || raw.delegation_chain.length === 0) {
    throw new AuthorityError('schema', 'intent.delegation_chain must be a non-empty array')
  }
  const delegation_chain = raw.delegation_chain.map((id, index) =>
    assertValidIdentity(id, `intent.delegation_chain[${index}]`)
  )

  return {
    intent_id: assertStringField(raw.intent_id, 'intent.intent_id', 1, 128),
    actor: assertValidIdentity(raw.actor, 'intent.actor'),
    delegation_chain,
    action: assertStringField(raw.action, 'intent.action', 1, 128),
    target: assertCanonicalTarget(assertStringField(raw.target, 'intent.target', 1, 512)),
    parameters: normalizeParameters(raw.parameters, 'intent.parameters'),
    nonce: assertValidNonce(raw.nonce),
    issued_at: assertIsoTimestamp(raw.issued_at, 'intent.issued_at'),
    expires_at: assertIsoTimestamp(raw.expires_at, 'intent.expires_at'),
  }
}

export function validateSignedIntent(raw: unknown): SignedIntent {
  if (!isPlainDataObject(raw)) {
    throw new AuthorityError('schema', 'signed intent must be a plain object')
  }
  if (!hasOwn(raw, 'signature') || raw.signature == null) {
    throw new AuthorityError('schema', 'intent.signature is required')
  }
  const payload = validateIntentPayload(raw)
  return {
    ...payload,
    signature: assertHexSignature(raw.signature, 'intent.signature'),
  }
}

export function validateSignedDelegation(raw: unknown, path = 'delegation'): SignedDelegation {
  if (!isPlainDataObject(raw)) {
    throw new AuthorityError('schema', `${path} must be a plain object`)
  }
  for (const key of Object.keys(raw)) assertSafeKey(key, path)
  if (!Array.isArray(raw.capabilities) || raw.capabilities.length === 0) {
    throw new AuthorityError('schema', `${path}.capabilities must be a non-empty array`)
  }
  const capabilities = raw.capabilities.map((cap, index) =>
    normalizeCapability(cap, `${path}.capabilities[${index}]`)
  )
  const payload = {
    delegation_id: assertValidIdentity(raw.delegation_id, `${path}.delegation_id`),
    issuer: assertValidIdentity(raw.issuer, `${path}.issuer`),
    subject: assertValidIdentity(raw.subject, `${path}.subject`),
    capabilities,
    constraints: normalizeConstraints(raw.constraints, `${path}.constraints`),
    issued_at: assertIsoTimestamp(raw.issued_at, `${path}.issued_at`),
    expires_at: assertIsoTimestamp(raw.expires_at, `${path}.expires_at`),
    ...(hasOwn(raw, 'parent_delegation_id') && raw.parent_delegation_id != null
      ? {
          parent_delegation_id: assertValidIdentity(
            raw.parent_delegation_id,
            `${path}.parent_delegation_id`
          ),
        }
      : {}),
  }
  if (!hasOwn(raw, 'signature') || raw.signature == null) {
    throw new AuthorityError('schema', `${path}.signature is required`)
  }
  return {
    ...payload,
    signature: assertHexSignature(raw.signature, `${path}.signature`),
  }
}

export function validateHumanApproval(raw: unknown): HumanApproval {
  if (!isPlainDataObject(raw)) {
    throw new AuthorityError('schema', 'approval must be a plain object', true)
  }
  for (const key of Object.keys(raw)) assertSafeKey(key, 'approval')
  const required = [
    'intent_hash',
    'approver_id',
    'approved_at',
    'decision',
    'agent_id',
    'delegation_chain_hash',
    'policy_content_hash',
    'signature',
  ] as const
  for (const key of required) {
    if (!hasOwn(raw, key) || raw[key] === null) {
      throw new AuthorityError('schema', `approval.${key} is required`, true)
    }
  }
  if (raw.decision !== 'APPROVE') {
    throw new AuthorityError('approval', 'approval decision is not APPROVE', true)
  }
  const hex64 = /^[0-9a-f]{64}$/
  if (typeof raw.intent_hash !== 'string' || !hex64.test(raw.intent_hash)) {
    throw new AuthorityError('schema', 'approval.intent_hash must be 64 hex chars', true)
  }
  if (typeof raw.delegation_chain_hash !== 'string' || !hex64.test(raw.delegation_chain_hash)) {
    throw new AuthorityError('schema', 'approval.delegation_chain_hash must be 64 hex chars', true)
  }
  if (typeof raw.policy_content_hash !== 'string' || !hex64.test(raw.policy_content_hash)) {
    throw new AuthorityError('schema', 'approval.policy_content_hash must be 64 hex chars', true)
  }
  return {
    intent_hash: raw.intent_hash,
    approver_id: assertValidIdentity(raw.approver_id, 'approval.approver_id'),
    approved_at: assertIsoTimestamp(raw.approved_at, 'approval.approved_at'),
    decision: 'APPROVE',
    agent_id: assertValidIdentity(raw.agent_id, 'approval.agent_id'),
    delegation_chain_hash: raw.delegation_chain_hash,
    policy_content_hash: raw.policy_content_hash,
    ...(hasOwn(raw, 'matched_rule_id') && raw.matched_rule_id != null
      ? { matched_rule_id: assertStringField(raw.matched_rule_id, 'approval.matched_rule_id', 1, 256) }
      : {}),
    signature: assertHexSignature(raw.signature, 'approval.signature'),
  }
}

const TARGET_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._~-]*$/

/**
 * Accept one canonical resource form. Do not rewrite.
 *
 * A target is slash-separated ASCII segments. `.` and `..` segments, empty
 * segments, percent-encoding, backslashes, URL forms, and strings that change
 * under NFC or NFKC are rejected. Case is significant and is not folded.
 * A grant may end in a single `*` segment (`resource/*`). An intent target may not.
 */
export function assertCanonicalTarget(target: string, options?: { readonly grant?: boolean }): string {
  if (typeof target !== 'string' || target.length === 0 || target.length > 512) {
    throw new AuthorityError('target', 'target must be a non-empty canonical resource path', true)
  }
  if (target.normalize('NFC') !== target || target.normalize('NFKC') !== target) {
    throw new AuthorityError('target', 'target must not depend on unicode normalization', true)
  }
  if (target.includes('\\') || target.includes('\0')) {
    throw new AuthorityError('target', 'target must not contain backslashes or NUL', true)
  }
  if (target.includes('%')) {
    throw new AuthorityError('target', 'target must not contain percent-encoding', true)
  }
  if (target.includes('..')) {
    throw new AuthorityError('target', 'target must not contain dot-segments', true)
  }
  if (target.includes('://')) {
    throw new AuthorityError('target', 'URL-shaped targets are not a canonical resource path', true)
  }
  const segments = target.split('/')
  if (segments.some((segment) => segment.length === 0)) {
    throw new AuthorityError('target', 'target must not contain empty segments or repeated separators', true)
  }
  segments.forEach((segment, index) => {
    const last = index === segments.length - 1
    if (segment === '*' ) {
      if (!options?.grant || !last || segments.length < 2) {
        throw new AuthorityError('target', 'wildcard is only allowed as the final segment of a grant', true)
      }
      return
    }
    if (segment === '.' || segment === '..') {
      throw new AuthorityError('target', 'target must not contain dot-segments', true)
    }
    if (!TARGET_SEGMENT.test(segment)) {
      throw new AuthorityError('target', 'target segment is not canonical', true)
    }
  })
  return target
}

export function assertCanonicalCurrency(value: unknown, path: string): string {
  if (typeof value !== 'string' || !/^[A-Z]{3}$/.test(value)) {
    throw new AuthorityError('currency', `${path} must be a 3-letter ISO 4217 uppercase code`, true)
  }
  return value
}
