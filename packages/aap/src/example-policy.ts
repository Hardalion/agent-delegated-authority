import type { Policy } from 'adap-policy'

export const BASIC_AGENT_AUTHORITY_URI = 'basic-agent-authority@1.0.0'

/**
 * Reference walkthrough policy. Not normative.
 * The same document is examples/policies/basic-agent-authority.yaml.
 */
export const BASIC_AGENT_AUTHORITY: Policy = {
  version: '1.0.0',
  policyName: 'basic-agent-authority',
  description: 'Example policy for protocol semantics. apply waits for a person. An amount over 500 is blocked.',
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
