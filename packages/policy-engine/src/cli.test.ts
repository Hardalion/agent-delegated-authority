import { describe, expect, it } from 'vitest'
import { parsePolicyEvalArgs, runPolicyEval } from './cli.js'

describe('adap-policy CLI', () => {
  it('parses minimal args', () => {
    expect(parsePolicyEvalArgs(['--tool', 'read'])).toEqual({
      toolName: 'read',
      toolArgs: undefined,
      agentRole: undefined,
      policy: undefined,
      policyFile: undefined,
      policyUri: undefined,
      json: false,
    })
  })

  it('blocks an apply over the cap via the bundled example', async () => {
    const decision = await runPolicyEval({
      toolName: 'apply',
      toolArgs: { amount: 800 },
    })
    expect(decision.action).toBe('BLOCK')
    expect(decision.ruleId).toBe('block_over_cap')
  })

  it('resolves a local policy pin', async () => {
    const decision = await runPolicyEval({
      toolName: 'read',
      policyUri: 'basic-agent-authority@1.0.0',
    })
    expect(decision.action).toBe('ALLOW')
  })

  it('fails closed when a pin has no local document', async () => {
    const decision = await runPolicyEval({
      toolName: 'read',
      policyUri: 'missing-example@1.0.0',
    })
    expect(decision.action).toBe('BLOCK')
    expect(decision.ruleId).toBe('PIN_UNRESOLVED')
  })
})
