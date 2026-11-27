import { describe, expect, it } from 'vitest'
import { AuthorityError } from './errors.js'
import { validateParametersAgainstSchema } from './schema-validate.js'

const STRICT = {
  type: 'object',
  additionalProperties: false,
  required: ['customer_id'],
  properties: {
    customer_id: { type: 'string' },
    amount: { type: 'integer' },
    tags: { type: 'array', items: { type: 'string' } },
  },
} as const

function rejectionCode(params: Record<string, unknown>, schema: unknown = STRICT): string | undefined {
  try {
    validateParametersAgainstSchema(params, schema)
    return undefined
  } catch (error) {
    return error instanceof AuthorityError ? error.code : 'other'
  }
}

describe('validateParametersAgainstSchema', () => {
  it('accepts a conforming parameter bag', () => {
    expect(() =>
      validateParametersAgainstSchema({ customer_id: 'c_1', amount: 10, tags: ['a', 'b'] }, STRICT),
    ).not.toThrow()
  })

  it('rejects an undeclared key under a closed schema (additionalProperties:false)', () => {
    expect(rejectionCode({ customer_id: 'c_1', internal_override: true })).toBe('parameter_schema')
  })

  it('rejects a case/fold variant of a declared key', () => {
    expect(rejectionCode({ customer_id: 'c_1', customer_ID: 'c_victim' })).toBe('parameter_schema')
    // NFKC fold: "ﬁle" (U+FB01 ligature) folds to "file"
    expect(rejectionCode({ customer_id: 'c_1', CUSTOMER_ID: 'x' })).toBe('parameter_schema')
  })

  it('rejects two presented keys that fold to the same form', () => {
    const open = { type: 'object', additionalProperties: true, properties: {} } as const
    expect(rejectionCode({ Amount: 1, amount: 2 }, open)).toBe('parameter_schema')
  })

  it('rejects an array where a scalar type is declared', () => {
    expect(rejectionCode({ customer_id: ['c_1', 'c_victim'] })).toBe('parameter_schema')
    expect(rejectionCode({ customer_id: 'c_1', amount: [1, 2] })).toBe('parameter_schema')
  })

  it('rejects a wrong scalar type and a non-integer number for integer', () => {
    expect(rejectionCode({ customer_id: 5 })).toBe('parameter_schema')
    expect(rejectionCode({ customer_id: 'c_1', amount: 1.5 })).toBe('parameter_schema')
  })

  it('rejects a bad array item type', () => {
    expect(rejectionCode({ customer_id: 'c_1', tags: ['a', 7] })).toBe('parameter_schema')
  })

  it('rejects a missing required property', () => {
    expect(rejectionCode({ amount: 1 })).toBe('parameter_schema')
  })

  it('honors an open schema for undeclared keys but still folds declared ones', () => {
    const open = {
      type: 'object',
      additionalProperties: true,
      properties: { id: { type: 'string' } },
    } as const
    expect(() => validateParametersAgainstSchema({ id: 'x', extra: 1 }, open)).not.toThrow()
    expect(rejectionCode({ id: 'x', ID: 'y' }, open)).toBe('parameter_schema')
  })

  it('enforces enum membership', () => {
    const schema = {
      type: 'object',
      additionalProperties: false,
      properties: { side: { type: 'string', enum: ['buy', 'sell'] } },
    } as const
    expect(() => validateParametersAgainstSchema({ side: 'buy' }, schema)).not.toThrow()
    expect(rejectionCode({ side: 'hold' }, schema)).toBe('parameter_schema')
  })

  it('recurses into a nested object schema', () => {
    const schema = {
      type: 'object',
      additionalProperties: false,
      properties: {
        order: {
          type: 'object',
          additionalProperties: false,
          properties: { qty: { type: 'integer' } },
        },
      },
    } as const
    expect(() => validateParametersAgainstSchema({ order: { qty: 3 } }, schema)).not.toThrow()
    expect(rejectionCode({ order: { qty: 3, QTY: 9 } }, schema)).toBe('parameter_schema')
    expect(rejectionCode({ order: { qty: 3, extra: 1 } }, schema)).toBe('parameter_schema')
  })

  it('rejects a schema that itself declares fold-colliding properties (ambiguous)', () => {
    const ambiguous = {
      type: 'object',
      additionalProperties: false,
      properties: { Amount: { type: 'integer' }, amount: { type: 'integer' } },
    } as const
    expect(rejectionCode({ amount: 1 }, ambiguous)).toBe('parameter_schema')
  })

  it('is a no-op when the schema is not an enforceable object schema', () => {
    expect(() => validateParametersAgainstSchema({ anything: 1 }, true)).not.toThrow()
    expect(() => validateParametersAgainstSchema({ anything: 1 }, { type: 'string' })).not.toThrow()
    expect(() => validateParametersAgainstSchema({ anything: 1 }, undefined)).not.toThrow()
  })
})
