import { describe, expect, it } from 'vitest'
import { evaluateCondition } from './evaluator.js'

describe('condition evaluator: boolean/null literals and nested path .contains()', () => {
  describe('boolean literals (passing and failing fixtures)', () => {
    it('evaluates true literal equality and inequality (passing fixture)', () => {
      expect(evaluateCondition('args.is_admin == true', { args: { is_admin: true } })).toBe(true)
      expect(evaluateCondition('args.sandbox != true', { args: { sandbox: false } })).toBe(true)
    })

    it('rejects mismatch against true literal (failing fixture)', () => {
      expect(evaluateCondition('args.is_admin == true', { args: { is_admin: false } })).toBe(false)
    })

    it('evaluates false literal equality and inequality (passing fixture)', () => {
      expect(evaluateCondition('args.is_admin == false', { args: { is_admin: false } })).toBe(true)
      expect(evaluateCondition('args.is_admin != false', { args: { is_admin: true } })).toBe(true)
    })

    it('rejects mismatch against false literal (failing fixture)', () => {
      expect(evaluateCondition('args.is_admin == false', { args: { is_admin: true } })).toBe(false)
    })
  })

  describe('null literal (passing and failing fixtures)', () => {
    it('evaluates null literal equality and inequality (passing fixture)', () => {
      expect(evaluateCondition('args.token == null', { args: { token: null } })).toBe(true)
      expect(evaluateCondition('args.token != null', { args: { token: 'active' } })).toBe(true)
    })

    it('rejects mismatch against null literal (failing fixture)', () => {
      expect(evaluateCondition('args.token == null', { args: { token: 'active' } })).toBe(false)
    })
  })

  describe('.contains() on nested paths (passing and failing fixtures)', () => {
    it('evaluates contains on nested object paths (passing fixture)', () => {
      expect(
        evaluateCondition("tool.target.contains('admin')", {
          tool: { target: 'service/internal-admin/users' },
        })
      ).toBe(true)
      expect(
        evaluateCondition("args.user.email.contains('@corp.internal')", {
          args: { user: { email: 'alice@corp.internal' } },
        })
      ).toBe(true)
    })

    it('rejects when substring is not contained in nested path (failing fixture)', () => {
      expect(
        evaluateCondition("tool.target.contains('admin')", {
          tool: { target: 'service/public/items' },
        })
      ).toBe(false)
    })

    it('evaluates array containment on nested paths (passing fixture)', () => {
      expect(
        evaluateCondition("args.metadata.tags.contains('production')", {
          args: { metadata: { tags: ['staging', 'production'] } },
        })
      ).toBe(true)
    })

    it('rejects when item is not in array on nested path (failing fixture)', () => {
      expect(
        evaluateCondition("args.metadata.tags.contains('production')", {
          args: { metadata: { tags: ['staging', 'dev'] } },
        })
      ).toBe(false)
    })
  })
})
