#!/usr/bin/env node
/**
 * Fail the build if the bundled example in dist does not match source.
 */
import { evaluateToolCall, CANONICAL_BASIC_AGENT_AUTHORITY } from '../dist/index.js'

const readCall = evaluateToolCall({
  policy: CANONICAL_BASIC_AGENT_AUTHORITY,
  toolName: 'read',
  toolArgs: {},
})

if (readCall.action !== 'ALLOW' || readCall.ruleId !== 'read_allow') {
  console.error(
    '[policy-engine] Built policy bundle is stale.',
    `Expected read → ALLOW (read_allow), got ${readCall.action} (${readCall.ruleId}).`,
  )
  process.exit(1)
}

console.log('[policy-engine] Built policy bundle OK (read → ALLOW)')
