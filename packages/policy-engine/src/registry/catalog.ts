/**
 * Example documents shipped with the reference evaluator.
 * A pin resolves here, or the caller supplies the document. This is not a registry.
 */

import { createHash } from 'node:crypto'
import type { Policy } from '../schema.js'
import { CANONICAL_BASIC_AGENT_AUTHORITY } from '../schema.js'
import { PolicySchema } from '../schema.js'
import { BUNDLED_POLICIES } from '../policies/bundled.js'
import { canonicalJsonStringify } from '../canonical-json.js'
import { assertVersionPinned, type PolicyPin, registryRefKey } from './uri.js'

export interface PolicyRegistryEntry {
  readonly policyId: string
  readonly version: string
  readonly publisher: string
  readonly immutable: true
  readonly publishedAt: string
  readonly contentHash: string
  readonly policy: Policy
}

function hashPolicy(policy: Policy): string {
  return createHash('sha256').update(canonicalJsonStringify(policy)).digest('hex')
}

function entryFromPolicy(input: {
  policyId: string
  version: string
  publisher: string
  publishedAt: string
  policy: Policy
}): PolicyRegistryEntry {
  const policy = PolicySchema.parse({
    ...input.policy,
    version: input.version,
    policyName: input.policyId,
  })
  return {
    policyId: input.policyId,
    version: input.version,
    publisher: input.publisher,
    immutable: true,
    publishedAt: input.publishedAt,
    contentHash: hashPolicy(policy),
    policy,
  }
}

/** Local example documents. Not a hosted registry. */
export const POLICY_REGISTRY_CATALOG: Readonly<Record<string, PolicyRegistryEntry>> = {
  'basic-agent-authority@1.0.0': entryFromPolicy({
    policyId: CANONICAL_BASIC_AGENT_AUTHORITY,
    version: '1.0.0',
    publisher: 'example',
    publishedAt: '2026-06-01T00:00:00.000Z',
    policy: BUNDLED_POLICIES[CANONICAL_BASIC_AGENT_AUTHORITY]!,
  }),
}

export function listPolicyRegistryEntries(): PolicyRegistryEntry[] {
  return Object.values(POLICY_REGISTRY_CATALOG)
}

export function getPolicyRegistryEntry(ref: string): PolicyRegistryEntry | null {
  const key = ref.includes('@') ? ref.toLowerCase() : null
  if (!key) return null
  return POLICY_REGISTRY_CATALOG[key] ?? null
}

export function resolvePolicyRegistryEntry(uri: PolicyPin): PolicyRegistryEntry | null {
  const key = registryRefKey(uri)
  const entry = POLICY_REGISTRY_CATALOG[key]
  if (!entry) return null
  if (uri.publisher && entry.publisher !== uri.publisher) return null
  assertVersionPinned(uri.version, entry.version, 'Policy pin')
  return entry
}
