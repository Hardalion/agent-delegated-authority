import type { Policy } from '../schema.js'
import { CANONICAL_BASIC_AGENT_AUTHORITY } from '../schema.js'

const BASIC_AGENT_AUTHORITY_V1: Policy = {
  version: '1.0.0',
  policyName: CANONICAL_BASIC_AGENT_AUTHORITY,
  description:
    'Example policy for protocol semantics. apply waits for a person. An amount over 500 is blocked.',
  targetAgents: ['*'],
  defaultAction: 'BLOCK',
  rules: [
    {
      ruleId: 'block_over_cap',
      action: 'BLOCK',
      condition: "tool.name == 'apply' && args.amount > 500",
      alertSeverity: 'CRITICAL',
    },
    {
      ruleId: 'apply_needs_human',
      action: 'REQUIRE_HUMAN',
      condition: "tool.name == 'apply'",
      alertSeverity: 'MEDIUM',
    },
    {
      ruleId: 'read_allow',
      action: 'ALLOW',
      condition: "tool.name == 'read'",
      alertSeverity: 'LOW',
    },
  ],
}

/** Example policy shipped with the reference evaluator. */
export const BUNDLED_POLICIES: Record<string, Policy> = {
  [CANONICAL_BASIC_AGENT_AUTHORITY]: BASIC_AGENT_AUTHORITY_V1,
}

export function normalizePolicyReference(ref: string): string {
  return ref.trim().toLowerCase()
}
