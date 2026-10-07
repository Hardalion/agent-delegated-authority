/**
 * Property-based policy assurance.
 * Run: `pnpm --filter adap-policy test:pbt`
 */
import { describe, expect, it } from 'vitest'
import * as fc from 'fast-check'
import {
  evaluateCondition,
  evaluateToolCall,
  type Policy,
} from './index.js'

const ACTIONS = ['ALLOW', 'BLOCK', 'REQUIRE_HUMAN', 'DEFER', 'SIMULATE'] as const
type Action = (typeof ACTIONS)[number]

const PRIORITY: Record<Action, number> = {
  BLOCK: 5,
  REQUIRE_HUMAN: 4,
  DEFER: 3,
  SIMULATE: 2,
  ALLOW: 1,
}

const toolNameArb = fc.constantFrom('read', 'apply', 'ping', 'query')

const amountArb = fc.integer({ min: 0, max: 1_000_000 })

function policyWithRules(
  rules: Array<{ ruleId: string; action: Action; condition: string }>
): Policy {
  return {
    version: '1.0.0',
    policyName: 'pbt-generated-policy',
    targetAgents: ['*'],
    rules: rules.map((r) => ({
      ...r,
      alertSeverity: r.action === 'BLOCK' ? 'CRITICAL' : 'MEDIUM',
    })),
  }
}

describe('policy property-based CI', () => {
  it('determinism: same tool call → identical decision', () => {
    fc.assert(
      fc.property(toolNameArb, amountArb, (toolName, amount) => {
        const policy = policyWithRules([
          {
            ruleId: 'r_block',
            action: 'BLOCK',
            condition: "tool.name == 'apply'",
          },
          {
            ruleId: 'r_human',
            action: 'REQUIRE_HUMAN',
            condition: "tool.name == 'read' && args.amount > 10000",
          },
          {
            ruleId: 'r_defer',
            action: 'DEFER',
            condition: "tool.name == 'ping'",
          },
        ])
        const a = evaluateToolCall({
          policy,
          toolName,
          toolArgs: { amount },
        })
        const b = evaluateToolCall({
          policy,
          toolName,
          toolArgs: { amount },
        })
        expect(a).toEqual(b)
      }),
      { numRuns: 100 }
    )
  })

  it('conflict resolution: highest priority matching action wins', () => {
    fc.assert(
      fc.property(
        fc.uniqueArray(fc.constantFrom(...ACTIONS), { minLength: 2, maxLength: 5 }),
        toolNameArb,
        (actions, toolName) => {
          const policy = policyWithRules(
            actions.map((action, i) => ({
              ruleId: `r_${i}_${action}`,
              action,
              // All rules match the same tool so conflict resolution is exercised.
              condition: `tool.name == '${toolName}'`,
            }))
          )
          const decision = evaluateToolCall({ policy, toolName, toolArgs: {} })
          const expected = actions.reduce((best, cur) =>
            PRIORITY[cur] > PRIORITY[best] ? cur : best
          )
          expect(decision.action).toBe(expected)
          expect(decision.matched).toBe(true)
        }
      ),
      { numRuns: 80 }
    )
  })

  it('BLOCK always beats REQUIRE_HUMAN when both match', () => {
    fc.assert(
      fc.property(amountArb, (amount) => {
        const policy = policyWithRules([
          {
            ruleId: 'human',
            action: 'REQUIRE_HUMAN',
            condition: "tool.name == 'apply'",
          },
          {
            ruleId: 'block',
            action: 'BLOCK',
            condition: "tool.name == 'apply' && args.amount >= 0",
          },
        ])
        const d = evaluateToolCall({
          policy,
          toolName: 'apply',
          toolArgs: { amount },
        })
        expect(d.action).toBe('BLOCK')
      }),
      { numRuns: 50 }
    )
  })

  it('evaluateCondition is pure and boolean for safe expressions', () => {
    fc.assert(
      fc.property(
        fc.constantFrom('apply', 'ping', 'read'),
        amountArb,
        (name, amount) => {
          const ctx = {
            tool: { name, args: { amount } },
            args: { amount },
          }
          const a = evaluateCondition(`tool.name == '${name}'`, ctx)
          const b = evaluateCondition(`tool.name == '${name}'`, ctx)
          expect(a).toBe(b)
          expect(typeof a).toBe('boolean')
          expect(evaluateCondition('args.amount > 10000', ctx)).toBe(amount > 10000)
        }
      ),
      { numRuns: 80 }
    )
  })

  it('basic-agent-authority example: an apply over the cap is blocked; read is allowed', () => {
    fc.assert(
      fc.property(fc.integer({ min: 501, max: 500_000 }), (amount) => {
        const d = evaluateToolCall({
          policy: 'basic-agent-authority',
          toolName: 'apply',
          toolArgs: { amount },
        })
        expect(d.action).toBe('BLOCK')
        expect(d.ruleId).toBe('block_over_cap')
      }),
      { numRuns: 40 }
    )

    const allowed = evaluateToolCall({
      policy: 'basic-agent-authority',
      toolName: 'read',
      toolArgs: {},
    })
    expect(allowed.action).toBe('ALLOW')
    expect(allowed.ruleId).toBe('read_allow')
  })

  it('example policy fails closed for an unknown tool', () => {
    const d = evaluateToolCall({
      policy: 'basic-agent-authority',
      toolName: 'ping',
      toolArgs: {},
    })
    expect(d.action).toBe('BLOCK')
    expect(d.matched).toBe(false)
    expect(d.ruleId).toBe('default_block')
  })
})
