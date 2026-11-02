import type { Policy } from 'adap-policy'

export const STAGING_ALLOW_URI = 'staging-allow@1'
export const STAGING_HUMAN_URI = 'staging-human@1'

export const STAGING_ALLOW_POLICY: Policy = {
  version: '1.0.0',
  policyName: 'staging-allow',
  targetAgents: ['*'],
  defaultAction: 'BLOCK',
  rules: [
    { ruleId: 'allow_apply', action: 'ALLOW', condition: "tool.name == 'apply'", alertSeverity: 'LOW' },
  ],
}

export const STAGING_HUMAN_POLICY: Policy = {
  version: '1.0.0',
  policyName: 'staging-human',
  targetAgents: ['*'],
  defaultAction: 'BLOCK',
  rules: [
    {
      ruleId: 'need_human',
      action: 'REQUIRE_HUMAN',
      condition: "tool.name == 'apply'",
      alertSeverity: 'MEDIUM',
    },
  ],
}
