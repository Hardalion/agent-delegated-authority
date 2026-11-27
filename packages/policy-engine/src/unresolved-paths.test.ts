import { describe, expect, it } from 'vitest'
import { evaluateCondition } from './evaluator.js'

// #63: an unresolved path (a missing arg) must not match inside `in [...]` or
// `.contains()`, consistent with the spec rule that a missing path is false for
// == and !=. A missing/typed-wrong .contains() argument and an empty needle do
// not match either.
describe('#63 unresolved paths do not match in `in` and `.contains()`', () => {
  const ctx = { args: { memo: 'refund for undefined order', tags: ['eu', 'vip'] } }

  it('a missing path is not a member of a list', () => {
    // Baseline the spec already guarantees for == / !=.
    expect(evaluateCondition('args.missing == args.gone', ctx)).toBe(false)
    // in / contains now agree.
    expect(evaluateCondition('args.missing in [args.gone]', ctx)).toBe(false)
    expect(evaluateCondition("args.missing in ['a', 'b']", ctx)).toBe(false)
    expect(evaluateCondition('args.present in [args.gone]', { args: { present: 'x' } })).toBe(false)
  })

  it('an unresolved or empty `.contains()` argument never matches', () => {
    expect(evaluateCondition('args.memo.contains(args.flag)', ctx)).toBe(false)
    expect(evaluateCondition("args.memo.contains('')", ctx)).toBe(false)
    expect(evaluateCondition('args.tags.contains(args.flag)', ctx)).toBe(false)
  })

  it('still matches a resolved, non-empty needle (unchanged behavior)', () => {
    expect(evaluateCondition("args.memo.contains('refund')", ctx)).toBe(true)
    expect(evaluateCondition("args.tags.contains('eu')", ctx)).toBe(true)
    expect(evaluateCondition("args.memo in ['refund for undefined order']", ctx)).toBe(true)
  })
})
