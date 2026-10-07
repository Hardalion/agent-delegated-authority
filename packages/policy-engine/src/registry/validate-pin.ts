import { formatPolicyPin, isPolicyPin, parsePolicyPin } from './uri.js'
import { resolvePolicyRegistryEntry } from './catalog.js'

export type PolicyPinValidationResult =
  | {
      ok: true
      uri: string
      policyId: string
      version: string
      contentHash: string
    }
  | {
      ok: false
      code: 'INVALID_URI' | 'UNRESOLVED'
      message: string
    }

/** Validate a pinned policy id against the local example catalog. */
export function validatePolicyPin(raw: string): PolicyPinValidationResult {
  const trimmed = raw.trim()
  if (!trimmed) {
    return {
      ok: false,
      code: 'INVALID_URI',
      message: 'Policy pin is required. Use {policy-id}@{semver}',
    }
  }

  if (!isPolicyPin(trimmed)) {
    return {
      ok: false,
      code: 'INVALID_URI',
      message: 'Policy pin must include a semver (e.g. basic-agent-authority@1.0.0)',
    }
  }

  try {
    const parsed = parsePolicyPin(trimmed)
    const entry = resolvePolicyRegistryEntry(parsed)
    if (!entry) {
      return {
        ok: false,
        code: 'UNRESOLVED',
        message: `No local document for ${trimmed}`,
      }
    }

    return {
      ok: true,
      uri: formatPolicyPin(parsed),
      policyId: entry.policyId,
      version: entry.version,
      contentHash: entry.contentHash,
    }
  } catch (err) {
    return {
      ok: false,
      code: 'INVALID_URI',
      message: err instanceof Error ? err.message : 'Invalid policy pin',
    }
  }
}
