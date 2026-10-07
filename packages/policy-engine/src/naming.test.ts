import { describe, expect, it } from 'vitest'
import { CANONICAL_BASIC_AGENT_AUTHORITY, PolicySchema } from './schema.js'
import { normalizePolicyReference } from './policies/bundled.js'
import { resolvePolicy, listBundledPolicyNames } from './engine.js'
import { getPolicyRegistryEntry } from './registry/catalog.js'

describe('canonical policy naming', () => {
  it('uses kebab-case policyName in schema', () => {
    expect(() =>
      PolicySchema.parse({
        version: '1.0.0',
        policyName: 'Basic_Agent',
        targetAgents: ['*'],
        rules: [
          {
            ruleId: 'r1',
            action: 'ALLOW',
            condition: "tool.name == 'x'",
            alertSeverity: 'LOW',
          },
        ],
      })
    ).toThrow()
  })

  it('accepts the bundled example id', () => {
    const policy = resolvePolicy(CANONICAL_BASIC_AGENT_AUTHORITY)
    expect(policy.policyName).toBe(CANONICAL_BASIC_AGENT_AUTHORITY)
  })

  it('lowercases a policy reference', () => {
    expect(normalizePolicyReference('Basic-Agent-Authority')).toBe(
      CANONICAL_BASIC_AGENT_AUTHORITY
    )
  })

  it('lists only the bundled example', () => {
    expect(listBundledPolicyNames()).toEqual([CANONICAL_BASIC_AGENT_AUTHORITY])
  })

  it('local catalog matches the bundled example id', () => {
    const entry = getPolicyRegistryEntry(`${CANONICAL_BASIC_AGENT_AUTHORITY}@1.0.0`)
    expect(entry?.policyId).toBe(CANONICAL_BASIC_AGENT_AUTHORITY)
    expect(entry?.policy.policyName).toBe(CANONICAL_BASIC_AGENT_AUTHORITY)
  })
})
