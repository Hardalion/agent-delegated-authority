import { describe, expect, it } from 'vitest'
import {
  formatPolicyPin,
  isPolicyPin,
  normalizeSemver,
  parsePolicyPin,
} from './uri.js'
import {
  getPolicyRegistryEntry,
  listPolicyRegistryEntries,
  resolvePolicyRegistryEntry,
} from './catalog.js'
import { validatePolicyPin } from './validate-pin.js'

describe('policy pin', () => {
  it('requires version pinning', () => {
    expect(() => parsePolicyPin('basic-agent-authority')).toThrow(/Required form/)
  })

  it('parses a version pin and ignores an optional scheme', () => {
    const uri = parsePolicyPin('basic-agent-authority@1.0.0')
    expect(uri.policyId).toBe('basic-agent-authority')
    expect(uri.version).toBe('1.0.0')
    expect(formatPolicyPin(uri)).toBe('basic-agent-authority@1.0.0')
    expect(parsePolicyPin('policy://basic-agent-authority@1.0.0').policyId).toBe(
      'basic-agent-authority'
    )
  })

  it('rejects an unversioned name', () => {
    expect(isPolicyPin('demo@1.0.0')).toBe(true)
    expect(isPolicyPin('Basic_Agent')).toBe(false)
  })

  it('normalizes semver components', () => {
    expect(normalizeSemver('1.0')).toBe('1.0.0')
  })
})

describe('local example catalog', () => {
  it('lists immutable entries', () => {
    const entries = listPolicyRegistryEntries()
    expect(entries.some((e) => e.policyId === 'basic-agent-authority')).toBe(true)
  })

  it('resolves pinned version only', () => {
    const entry = getPolicyRegistryEntry('basic-agent-authority@1.0.0')
    expect(entry?.immutable).toBe(true)
    expect(entry?.version).toBe('1.0.0')
    expect(resolvePolicyRegistryEntry(parsePolicyPin('basic-agent-authority@1.0.0'))).not.toBeNull()
    expect(resolvePolicyRegistryEntry(parsePolicyPin('basic-agent-authority@9.9.9'))).toBeNull()
  })
})

describe('validatePolicyPin', () => {
  it('accepts a pin that has a local document', () => {
    const result = validatePolicyPin('basic-agent-authority@1.0.0')
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.policyId).toBe('basic-agent-authority')
      expect(result.version).toBe('1.0.0')
    }
  })

  it('rejects an unpinned name and an unknown pin', () => {
    expect(validatePolicyPin('basic-agent-authority').ok).toBe(false)
    expect(validatePolicyPin('basic-agent-authority@9.9.9').ok).toBe(false)
  })
})
