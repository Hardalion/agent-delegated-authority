/**
 * Fail-closed identity and default-action invariants.
 * An omitted field must not broaden the decision to ALLOW.
 */
import { describe, expect, it } from 'vitest'
import { evaluateToolCall, parsePolicyDocument } from './engine.js'
import type { Policy } from './schema.js'

const ROLE = 'agt_reader'

function scoped(targetAgents: string[], defaultAction?: Policy['defaultAction']): Policy {
  return {
    version: '1.0.0',
    policyName: 'scoped-role',
    targetAgents,
    ...(defaultAction ? { defaultAction } : {}),
    rules: [
      {
        ruleId: 'allow_read',
        action: 'ALLOW',
        condition: "tool.name == 'read'",
        alertSeverity: 'LOW',
      },
    ],
  } as Policy
}

describe('agent identity fails closed', () => {
  const policy = parsePolicyDocument(`version: "1.0.0"
policyName: scoped-role
targetAgents: ["agt_reader"]
defaultAction: BLOCK
rules:
  - ruleId: allow_read
    action: ALLOW
    condition: "tool.name == 'read'"
    alertSeverity: LOW
`)

  it.each([
    ['omitted', undefined],
    ['empty', ''],
    ['whitespace', '   '],
    ['null', null],
    ['unknown', 'agt_other'],
    ['malformed', 'agt reader'],
  ])('rejects a %s role on a scoped policy', (_label, agentRole) => {
    const decision = evaluateToolCall({
      policy,
      toolName: 'read',
      agentRole: agentRole as string | undefined,
    })
    expect(decision.action).toBe('BLOCK')
    expect(decision.ruleId).toBe('agent_not_in_scope')
    expect(decision.matched).toBe(false)
  })

  it('rejects an omitted role even when targetAgents is the wildcard', () => {
    const decision = evaluateToolCall({
      policy: scoped(['*'], 'ALLOW'),
      toolName: 'read',
    })
    expect(decision.action).toBe('BLOCK')
    expect(decision.ruleId).toBe('agent_not_in_scope')
  })

  it('allows the named role and a well-formed role under a wildcard', () => {
    expect(
      evaluateToolCall({ policy, toolName: 'read', agentRole: ROLE }).action
    ).toBe('ALLOW')
    expect(
      evaluateToolCall({ policy: scoped(['*'], 'BLOCK'), toolName: 'read', agentRole: ROLE }).ruleId
    ).toBe('allow_read')
  })
})

describe('ADAP-003 non-finite amount comparison', () => {
  const policy = parsePolicyDocument(`version: "1.0.0"
policyName: amount-cap
targetAgents: ["agt_reader"]
defaultAction: ALLOW
rules:
  - ruleId: over_cap
    action: BLOCK
    condition: "args.amount > 100"
    alertSeverity: CRITICAL
`)

  it('does not let NaN or infinity skip a greater-than cap and fall through to ALLOW', () => {
    for (const amount of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
      const decision = evaluateToolCall({
        policy,
        toolName: 'apply',
        toolArgs: { amount },
        agentRole: ROLE,
      })
      expect(decision.action).toBe('BLOCK')
      expect(decision.ruleId).toBe('amount_not_finite')
    }
    expect(
      evaluateToolCall({ policy, toolName: 'apply', toolArgs: { amount: 101 }, agentRole: ROLE }).action
    ).toBe('BLOCK')
    expect(
      evaluateToolCall({ policy, toolName: 'apply', toolArgs: { amount: 100 }, agentRole: ROLE }).action
    ).toBe('ALLOW')
  })
})

describe('defaultAction fails closed', () => {
  it('refuses to parse a document that omits defaultAction', () => {
    expect(() =>
      parsePolicyDocument(`version: "1.0.0"
policyName: missing-default
targetAgents: ["*"]
rules:
  - ruleId: allow_read
    action: ALLOW
    condition: "tool.name == 'read'"
    alertSeverity: LOW
`)
    ).toThrow()
  })

  it('blocks an unmatched call when a bypassed object omits or invalidates defaultAction', () => {
    for (const policy of [scoped(['*']), { ...scoped(['*'], 'BLOCK'), defaultAction: 'PERMIT' } as unknown as Policy]) {
      const decision = evaluateToolCall({ policy, toolName: 'other', agentRole: ROLE })
      expect(decision.action).toBe('BLOCK')
      expect(decision.ruleId).toBe('default_action_required')
    }
  })

  it('uses an explicit ALLOW only when the document says so', () => {
    const decision = evaluateToolCall({
      policy: scoped(['*'], 'ALLOW'),
      toolName: 'other',
      agentRole: ROLE,
    })
    expect(decision.action).toBe('ALLOW')
    expect(decision.ruleId).toBe('default_allow')
  })
})
