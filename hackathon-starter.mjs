import { evaluateToolCall } from './packages/policy-engine/dist/index.js'

// 1. The "dangerous" function the team built
async function executeAgentAction(toolName, args) {
  console.log(`[EXECUTING] Running tool: ${toolName} with data:`, args)
}

// 2. The ADAP wrapper
async function safeExecute(agentIntent) {
  console.log(`\n--- Checking agent intent: ${agentIntent.toolName} ---`)

  const decision = evaluateToolCall({
    policy: 'basic-agent-authority',
    toolName: agentIntent.toolName,
    toolArgs: agentIntent.toolArgs,
  })

  console.log(`[ADAP DECISION] Rule: ${decision.ruleId} -> Action: ${decision.action}`)

  if (decision.action === 'BLOCK') {
    console.error('BLOCKED. Policy rejected the action.')
    return
  }

  if (decision.action === 'REQUIRE_HUMAN') {
    console.warn('REQUIRE_HUMAN. Waiting for a person.')
    return
  }

  if (decision.action === 'ALLOW') {
    console.log('ALLOW. Running the tool.')
    await executeAgentAction(agentIntent.toolName, agentIntent.toolArgs)
  }
}

// 3. Demo intents an LLM might emit
async function runDemo() {
  await safeExecute({ toolName: 'read', toolArgs: {} })
  await safeExecute({ toolName: 'apply', toolArgs: { amount: 300 } })
  await safeExecute({ toolName: 'apply', toolArgs: { amount: 800 } })
}

await runDemo()
