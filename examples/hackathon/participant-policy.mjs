/** Explicit participant policy. Agents outside this list are out of scope. */
export const AGENT_ID = 'agt_hackathon_demo'

export const POLICY = {
  version: '1.0.0',
  policyName: 'hackathon-participant-authority',
  description: 'Participant example. apply waits for a person. An amount over 500 is blocked. Unknown tools are blocked.',
  targetAgents: [AGENT_ID],
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
