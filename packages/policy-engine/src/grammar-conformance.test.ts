import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { evaluateCondition } from './evaluator.js'
import { evaluateToolCall, parsePolicyDocument } from './engine.js'

const ctx = {
  args: { n: 2, delta: -1, note: 'Wire', region: "it's", tags: ['eu', 'vip'] },
  tool: { name: 'read', target: 'resource/example', args: {} },
}

describe('condition grammar conformance', () => {
  it('accepts the documented productions', () => {
    expect(evaluateCondition('args.n == 2 && args.delta > -5', ctx)).toBe(true)
    expect(evaluateCondition("args.region == 'it\\'s'", ctx)).toBe(true)
    expect(evaluateCondition('args.n in [1, 2, 3]', ctx)).toBe(true)
    expect(evaluateCondition("args.tags.contains('eu')", ctx)).toBe(true)
    expect(evaluateCondition("args.note.icontains('wire')", ctx)).toBe(true)
    expect(evaluateCondition("(args.n == 1 || args.n == 2) && true", ctx)).toBe(true)
    expect(evaluateCondition("args.missing == 'x'", ctx)).toBe(false)
    expect(evaluateCondition("false && args.note > 'no'", ctx)).toBe(false)
    expect(evaluateCondition("true || args.note > 'no'", ctx)).toBe(true)
    expect(evaluateCondition("tool.target == 'resource/example'", ctx)).toBe(true)
  })

  it('rejects malformed syntax', () => {
    expect(() => evaluateCondition('args.n in [1 2 3]', ctx)).toThrow(/comma/)
    expect(() => evaluateCondition("args.note.contains('wire'", ctx)).toThrow(/parenthesis/)
    expect(() => evaluateCondition('args.n in [1,]', ctx)).toThrow(/Trailing comma/)
    expect(() => evaluateCondition('args.n', ctx)).toThrow(/boolean/)
  })

  it('runs the published decision vectors', () => {
    const file = new URL('../../../examples/conformance/policy-grammar-vectors.json', import.meta.url)
    const vectors = JSON.parse(readFileSync(file, 'utf8')) as {
      vectors: {
        id: string
        condition: string
        expect: 'true' | 'false' | 'reject'
        decision?: 'ALLOW' | 'BLOCK'
      }[]
    }
    for (const vector of vectors.vectors) {
      if (vector.expect === 'reject') {
        expect(() => evaluateCondition(vector.condition, ctx), vector.id).toThrow()
        const policy = parsePolicyDocument(`version: "1.0.0"
policyName: vector
targetAgents: ["*"]
defaultAction: ALLOW
rules:
  - ruleId: gate
    action: ALLOW
    condition: ${JSON.stringify(vector.condition)}
    alertSeverity: LOW
`)
        expect(evaluateToolCall({ policy, toolName: 'read', toolArgs: ctx.args, agentRole: 'agt_reader', toolTarget: 'resource/example' }).action).toBe('BLOCK')
        continue
      }
      expect(evaluateCondition(vector.condition, ctx), vector.id).toBe(vector.expect === 'true')
    }
  })
})
