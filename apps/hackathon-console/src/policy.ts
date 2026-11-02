import type { Policy } from 'adap-policy'

/** Autonomous create_payment ceiling, in USD minor units ($1,000.00). */
export const AUTONOMOUS_LIMIT_CENTS = 100_000

/** Hard create_payment ceiling, in USD minor units ($5,000.00). */
export const HARD_LIMIT_CENTS = 500_000

export const PURPOSE = 'treasury.demo'

export const POLICY_URI = 'treasury-demo-authority@1.0.0'

/**
 * Treasury demonstration policy.
 * Rule priority is the engine's: BLOCK outranks REQUIRE_HUMAN, which outranks ALLOW.
 * Amounts are integer minor units.
 */
export const TREASURY_POLICY: Policy = {
  version: '1.0.0',
  policyName: 'treasury-demo-authority',
  description:
    'Hackathon treasury policy for a simulated payment rail. Status reads are allowed. Payments above the autonomous limit wait for the principal. Beneficiary changes and amounts above the hard cap are blocked.',
  targetAgents: ['agt_treasury'],
  defaultAction: 'BLOCK',
  rules: [
    {
      ruleId: 'block_beneficiary',
      action: 'BLOCK',
      condition: "tool.name == 'change_beneficiary'",
      alertSeverity: 'CRITICAL',
    },
    {
      ruleId: 'block_over_cap',
      action: 'BLOCK',
      condition: `tool.name == 'create_payment' && args.amount > ${HARD_LIMIT_CENTS}`,
      alertSeverity: 'CRITICAL',
    },
    {
      ruleId: 'create_needs_human',
      action: 'REQUIRE_HUMAN',
      condition: `tool.name == 'create_payment' && args.amount > ${AUTONOMOUS_LIMIT_CENTS}`,
      alertSeverity: 'MEDIUM',
    },
    {
      ruleId: 'create_allow',
      action: 'ALLOW',
      condition: "tool.name == 'create_payment'",
      alertSeverity: 'LOW',
    },
    {
      ruleId: 'status_allow',
      action: 'ALLOW',
      condition: "tool.name == 'get_payment_status'",
      alertSeverity: 'LOW',
    },
  ],
}

export function authorityNote(ruleId: string, decision: string): string | null {
  if (ruleId === 'status_allow' && decision === 'ALLOW') {
    return 'Policy rule status_allow matched a status read. The delegation grants get_payment_status on payments/* when purpose is treasury.demo.'
  }
  if (ruleId === 'create_allow' && decision === 'ALLOW') {
    return `Policy rule create_allow matched. The amount is within the autonomous limit of ${AUTONOMOUS_LIMIT_CENTS} minor units (USD 1,000.00).`
  }
  if (ruleId === 'create_needs_human' && decision === 'REQUIRE_HUMAN') {
    return `The amount is above the autonomous limit of ${AUTONOMOUS_LIMIT_CENTS} minor units (USD 1,000.00) and within the hard cap of ${HARD_LIMIT_CENTS} minor units (USD 5,000.00). The executor is not called until a principal approval is bound to this intent.`
  }
  if (ruleId === 'block_beneficiary' && decision === 'BLOCK') {
    return 'The demo delegation names change_beneficiary so this request can reach policy evaluation. Rule block_beneficiary returns BLOCK. The simulated payment system is not called.'
  }
  if (ruleId === 'block_over_cap' && decision === 'BLOCK') {
    return `The amount is above the hard cap of ${HARD_LIMIT_CENTS} minor units (USD 5,000.00). BLOCK outranks REQUIRE_HUMAN when both match. The executor is not called.`
  }
  if (ruleId === 'capability' && decision === 'BLOCK') {
    return 'The delegation does not grant this action. Policy evaluation was not reached. The executor is not called.'
  }
  return null
}
