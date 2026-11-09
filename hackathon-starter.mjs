import { pathToFileURL } from 'node:url'
import { evaluateToolCall } from './packages/policy-engine/dist/index.js'
import { AGENT_ID, POLICY } from './examples/hackathon/participant-policy.mjs'

export { AGENT_ID, POLICY }

/**
 * Evaluate one proposed tool call.
 * agentRole is required at the call site. There is no hidden identity default.
 */
export function evaluate(agentRole, toolName, toolArgs) {
  return evaluateToolCall({
    policy: POLICY,
    toolName,
    toolArgs,
    agentRole,
  })
}

async function executeAgentAction(toolName, args) {
  console.log(`[EXECUTING] Running tool: ${toolName} with data:`, args)
}

export async function safeExecute(agentIntent) {
  console.log(`\n--- Checking agent intent: ${agentIntent.toolName} ---`)
  const decision = evaluate(AGENT_ID, agentIntent.toolName, agentIntent.toolArgs)
  console.log(`[ADAP DECISION] Rule: ${decision.ruleId} -> Action: ${decision.action}`)

  if (decision.action === 'BLOCK') {
    console.error('BLOCKED. Policy rejected the action.')
    return decision
  }
  if (decision.action === 'REQUIRE_HUMAN') {
    console.warn('REQUIRE_HUMAN. Waiting for a person. The tool was not called.')
    return decision
  }
  if (decision.action === 'ALLOW') {
    console.log('ALLOW. Running the tool.')
    await executeAgentAction(agentIntent.toolName, agentIntent.toolArgs)
    return decision
  }
  console.error('BLOCKED. The decision was not ALLOW.')
  return decision
}

export async function runDemo() {
  await safeExecute({ toolName: 'read', toolArgs: {} })
  await safeExecute({ toolName: 'apply', toolArgs: { amount: 300 } })
  await safeExecute({ toolName: 'apply', toolArgs: { amount: 800 } })
  const prohibited = evaluate(AGENT_ID, 'delete_records', {})
  console.log(`[ADAP DECISION] Rule: ${prohibited.ruleId} -> Action: ${prohibited.action}`)
  const unknown = evaluate('agt_unknown', 'read', {})
  console.log(`[ADAP DECISION] Rule: ${unknown.ruleId} -> Action: ${unknown.action}`)
  const missing = evaluate(undefined, 'read', {})
  console.log(`[ADAP DECISION] Rule: ${missing.ruleId} -> Action: ${missing.action}`)
  const malformed = evaluate('bad role', 'read', {})
  console.log(`[ADAP DECISION] Rule: ${malformed.ruleId} -> Action: ${malformed.action}`)
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await runDemo()
}
