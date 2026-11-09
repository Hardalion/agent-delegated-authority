import type { Policy } from 'adap-policy'

/** Autonomous create_payment ceiling for the sandbox rail, in EUR minor units (€500.00). */
export const SANDBOX_AUTONOMOUS_CENTS = 50_000

/** Hard ceiling for sandbox payments and purchases, in EUR minor units (€5,000.00). */
export const SANDBOX_HARD_CAP_CENTS = 500_000

export const SANDBOX_PURPOSE = 'treasury.sandbox'
export const SANDBOX_POLICY_URI = 'hackathon-sandbox-authority@1.1.0'

/**
 * Policy for the persistent sandbox APIs.
 * €120.00 (12000) is ALLOW. €750.00 (75000) is REQUIRE_HUMAN. €6,000.00 (600000) is BLOCK.
 * A vendor account change always waits for a person. Restricted purchases are blocked.
 */
export const SANDBOX_POLICY: Policy = {
  version: '1.1.0',
  policyName: 'hackathon-sandbox-authority',
  description:
    'Hackathon sandbox policy for synthetic EUR records. This rail does not transfer real money. Payments above €500 wait for a person. Payments above €5,000 are blocked. Vendor account changes wait for a person.',
  targetAgents: ['agt_treasury'],
  defaultAction: 'BLOCK',
  rules: [
    {
      ruleId: 'block_over_cap',
      action: 'BLOCK',
      condition: `tool.name == 'create_payment' && args.amount > ${SANDBOX_HARD_CAP_CENTS}`,
      alertSeverity: 'CRITICAL',
    },
    {
      ruleId: 'block_purchase_over_cap',
      action: 'BLOCK',
      condition: `tool.name == 'create_purchase_request' && args.amount > ${SANDBOX_HARD_CAP_CENTS}`,
      alertSeverity: 'CRITICAL',
    },
    {
      ruleId: 'block_restricted_purchase',
      action: 'BLOCK',
      condition: "tool.name == 'create_purchase_request' && args.category == 'restricted'",
      alertSeverity: 'CRITICAL',
    },
    {
      ruleId: 'vendor_needs_human',
      action: 'REQUIRE_HUMAN',
      condition: "tool.name == 'update_vendor_account'",
      alertSeverity: 'MEDIUM',
    },
    {
      ruleId: 'create_needs_human',
      action: 'REQUIRE_HUMAN',
      condition: `tool.name == 'create_payment' && args.amount > ${SANDBOX_AUTONOMOUS_CENTS}`,
      alertSeverity: 'MEDIUM',
    },
    {
      ruleId: 'purchase_needs_human',
      action: 'REQUIRE_HUMAN',
      condition: `tool.name == 'create_purchase_request' && args.amount > ${SANDBOX_AUTONOMOUS_CENTS}`,
      alertSeverity: 'MEDIUM',
    },
    {
      ruleId: 'create_allow',
      action: 'ALLOW',
      condition: "tool.name == 'create_payment'",
      alertSeverity: 'LOW',
    },
    {
      ruleId: 'purchase_allow',
      action: 'ALLOW',
      condition: "tool.name == 'create_purchase_request'",
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
