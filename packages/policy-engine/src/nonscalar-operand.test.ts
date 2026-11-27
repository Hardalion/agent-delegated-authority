/**
 * Defence in depth: `==`, `!=`, and `in` require scalar operands. An agent must
 * not be able to pick an argument's shape (an array or object) to slip a
 * disallowed value past an allowlist (`in`) or a denylist (`==`/`!=`). A
 * non-scalar operand fails closed: the condition throws NonScalarOperandError
 * and evaluatePolicy returns BLOCK. `.contains()` keeps array-left semantics —
 * membership against an array is its defined purpose.
 */
import { describe, expect, it } from 'vitest'
import { evaluateCondition, evaluateToolCall } from './index.js'
import { NonScalarOperandError } from './evaluator.js'

const ALLOWLIST = {
  version: '1.0.0',
  policyName: 'allowlist',
  targetAgents: ['*'],
  defaultAction: 'BLOCK' as const,
  rules: [{ ruleId: 'a', action: 'ALLOW' as const, condition: "args.action in ['read','list']", alertSeverity: 'LOW' as const }],
}

const DENYLIST = {
  version: '1.0.0',
  policyName: 'denylist',
  targetAgents: ['*'],
  defaultAction: 'ALLOW' as const,
  rules: [{ ruleId: 'b', action: 'BLOCK' as const, condition: "args.target == 'admin'", alertSeverity: 'CRITICAL' as const }],
}

describe('equality and membership reject non-scalar operands', () => {
  it('allowlist: a scalar still passes', () => {
    expect(evaluateToolCall({ policy: ALLOWLIST, toolName: 't', toolArgs: { action: 'read' }, agentRole: 'a' }).action).toBe('ALLOW')
  })

  it('allowlist: an array-wrapped value is BLOCK, not ALLOW (closes the in bypass)', () => {
    const d = evaluateToolCall({ policy: ALLOWLIST, toolName: 't', toolArgs: { action: ['read', 'write'] }, agentRole: 'a' })
    expect(d.action).toBe('BLOCK')
    expect(d.ruleId).toBe('non_scalar_operand_rejected')
  })

  it('allowlist: an object value is BLOCK', () => {
    expect(evaluateToolCall({ policy: ALLOWLIST, toolName: 't', toolArgs: { action: { read: true } }, agentRole: 'a' }).action).toBe('BLOCK')
  })

  it('denylist: a scalar still blocks', () => {
    expect(evaluateToolCall({ policy: DENYLIST, toolName: 't', toolArgs: { target: 'admin' }, agentRole: 'a' }).action).toBe('BLOCK')
  })

  it('denylist: an array-wrapped value is BLOCK, not default-ALLOW (closes the !=/== bypass)', () => {
    const d = evaluateToolCall({ policy: DENYLIST, toolName: 't', toolArgs: { target: ['admin'] }, agentRole: 'a' })
    expect(d.action).toBe('BLOCK')
    expect(d.ruleId).toBe('non_scalar_operand_rejected')
  })

  it('throws NonScalarOperandError at the condition level', () => {
    expect(() => evaluateCondition("args.x == 'y'", { args: { x: ['y'] } })).toThrow(NonScalarOperandError)
    expect(() => evaluateCondition("args.x != 'y'", { args: { x: { y: 1 } } })).toThrow(NonScalarOperandError)
    expect(() => evaluateCondition("args.x in ['y']", { args: { x: ['y'] } })).toThrow(NonScalarOperandError)
  })

  it('null and scalar comparisons still work (null is a scalar)', () => {
    expect(evaluateCondition('args.x == null', { args: { x: null } })).toBe(true)
    expect(evaluateCondition("args.x != 'y'", { args: { x: 'z' } })).toBe(true)
    expect(evaluateCondition('args.n in [1, 2, 3]', { args: { n: 2 } })).toBe(true)
  })

  it('an unresolved (undefined) operand still returns false, not a throw', () => {
    expect(evaluateCondition("args.missing == 'y'", { args: {} })).toBe(false)
    expect(evaluateCondition("args.missing in ['y']", { args: {} })).toBe(false)
  })

  it('.contains() keeps array-left membership (unchanged, intended feature)', () => {
    expect(evaluateCondition("args.tags.contains('eu')", { args: { tags: ['eu', 'us'] } })).toBe(true)
    expect(evaluateCondition("args.tags.contains('jp')", { args: { tags: ['eu', 'us'] } })).toBe(false)
  })

  it('a non-scalar in an already-excluded && clause does not over-block an unrelated call', () => {
    // Rule targets tool "transfer"; for a "pay" call the left of && is false, so the
    // array-valued right must be swallowed (rule simply does not match) — not BLOCK.
    const policy = {
      version: '1.0.0', policyName: 'p', targetAgents: ['*'], defaultAction: 'ALLOW' as const,
      rules: [{ ruleId: 'r', action: 'BLOCK' as const, condition: "tool.name == 'transfer' && args.data == 'x'", alertSeverity: 'CRITICAL' as const }],
    }
    expect(evaluateToolCall({ policy, toolName: 'pay', toolArgs: { data: ['x'] }, agentRole: 'a' }).action).toBe('ALLOW')
    // And it still blocks the transfer it is meant to guard.
    expect(evaluateToolCall({ policy, toolName: 'transfer', toolArgs: { data: 'x' }, agentRole: 'a' }).action).toBe('BLOCK')
  })
})
