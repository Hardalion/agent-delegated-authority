#!/usr/bin/env node
/**
 * Framework-agnostic ADAP gate over HTTP (local hackathon console).
 *
 *   pnpm hackathon:start
 *   set ADAP_URL=http://127.0.0.1:4317
 *   set ADAP_TEAM_TOKEN=[REDACTED]   # printed at startup
 *   node examples/hackathon/http_gate.mjs
 */

const base = (process.env.ADAP_URL ?? 'http://127.0.0.1:4317').replace(/\/$/, '')
const token = process.env.ADAP_TEAM_TOKEN || ''
const agentId = process.env.ADAP_AGENT_ID ?? 'agt_hackathon_demo'

if (!token) {
  console.error('Set ADAP_TEAM_TOKEN to the token printed by pnpm hackathon:start.')
  process.exit(1)
}

export async function gate(tool, args = {}) {
  const response = await fetch(`${base}/api/gate`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${token}`,
      'x-adap-request': '1',
    },
    body: JSON.stringify({ agentId, tool, args }),
  })
  const body = await response.json().catch(() => null)
  if (!response.ok) {
    const message = body?.error?.message ?? `HTTP ${response.status}`
    throw new Error(message)
  }
  return body
}

export async function guarded(tool, args, execute) {
  const decision = await gate(tool, args)
  if (decision.action !== 'ALLOW') {
    return { decision, executed: false, output: null }
  }
  return { decision, executed: true, output: await execute() }
}

const demos = [
  ['search_web', { q: 'athens agents' }],
  ['send_email', { to: 'team@example.com' }],
  ['delete_record', { id: 'demo' }],
]

for (const [tool, args] of demos) {
  const result = await gate(tool, args)
  console.log(`${tool.padEnd(16)} → ${result.action}  runTool=${result.runTool}  ${result.ruleId}`)
}
