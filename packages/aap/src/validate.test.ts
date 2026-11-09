import { describe, expect, it } from 'vitest'
import { assertIntentWithinDelegation, assertNotExpired, validateDelegationNarrowing } from './validate.js'
import type { SignedDelegation } from './protocol.js'

const t0 = '2026-10-06T10:00:00.000Z'
const t1 = '2026-10-06T10:15:00.000Z'

function delegation(over: Partial<SignedDelegation>): SignedDelegation {
  return {
    delegation_id: 'd1',
    issuer: 'human',
    subject: 'agent-a',
    capabilities: [{ action: 'read', target: 'resource/*' }],
    constraints: { max_amount: 500 },
    issued_at: t0,
    expires_at: t1,
    signature: 'x',
    ...over,
  }
}

describe('delegation narrowing', () => {
  const parent = delegation({})
  const child = delegation({
    delegation_id: 'd2',
    issuer: 'agent-a',
    subject: 'agent-b',
    capabilities: [{ action: 'read', target: 'resource/example' }],
    parent_delegation_id: 'd1',
  })

  it('allows a narrower target and an equal lifetime', () => {
    expect(() => validateDelegationNarrowing(parent, child)).not.toThrow()
  })

  it('rejects a higher amount cap', () => {
    expect(() =>
      validateDelegationNarrowing(parent, { ...child, constraints: { max_amount: 900 } })
    ).toThrow(/raises max_amount/)
  })

  it('rejects re-delegation of a non-delegable apply', () => {
    const root = delegation({
      capabilities: [{ action: 'apply', target: 'resource/*', delegable: false }],
    })
    const passed = delegation({
      delegation_id: 'd2',
      issuer: 'agent-a',
      subject: 'agent-b',
      capabilities: [{ action: 'apply', target: 'resource/example' }],
      parent_delegation_id: 'd1',
    })
    expect(() => validateDelegationNarrowing(root, passed)).toThrow(/cannot be re-delegated/)
  })
})

describe('expiry', () => {
  it('accepts a clock inside the lifetime', () => {
    expect(() => assertNotExpired(t0, t1, new Date('2026-10-06T10:05:00.000Z'))).not.toThrow()
  })

  it('rejects a clock at or after expiry', () => {
    expect(() => assertNotExpired(t0, t1, new Date(t1))).toThrow(/expired or not-yet-valid/)
  })
})

describe('spending bound', () => {
  const grant = delegation({
    subject: 'agent-a',
    capabilities: [{ action: 'purchase', target: 'airline/*' }],
    constraints: { max_amount: 500, currency: 'EUR' },
  })

  it('requires quantity under max_quantity and ignores an echoed ceiling', () => {
    const grant = delegation({
      capabilities: [{ action: 'purchase', target: 'airline/*' }],
      constraints: { max_quantity: 5 },
    })
    const intent = (parameters: Record<string, unknown>) => ({
      intent_id: 'i',
      actor: 'agent-a',
      delegation_chain: ['d1'],
      action: 'purchase',
      target: 'airline/example',
      parameters,
      nonce: 'n',
      issued_at: t0,
      expires_at: t1,
    })
    for (const quantity of [0, 3, 5]) {
      expect(() => assertIntentWithinDelegation(intent({ quantity }), grant)).not.toThrow()
    }
    expect(() => assertIntentWithinDelegation(intent({ quantity: 6 }), grant)).toThrow(/exceeds delegated max_quantity/)
    expect(() => assertIntentWithinDelegation(intent({ quantity: 999 }), grant)).toThrow(
      /exceeds delegated max_quantity/,
    )
    expect(() => assertIntentWithinDelegation(intent({}), grant)).toThrow(/quantity is required/)
    expect(() =>
      assertIntentWithinDelegation(intent({ quantity: 999, max_quantity: 5 }), grant),
    ).toThrow(/exceeds delegated max_quantity/)
    expect(() => assertIntentWithinDelegation(intent({ max_quantity: 5 }), grant)).toThrow(
      /quantity is required/,
    )
    expect(() => assertIntentWithinDelegation(intent({ quantity: 3, max_quantity: 5 }), grant)).not.toThrow()
  })

  it('keeps other max_* ceilings and rejects non-canonical limits', () => {
    const records = delegation({
      capabilities: [{ action: 'export', target: 'archive/*' }],
      constraints: { max_records: 2 },
    })
    const intent = (parameters: Record<string, unknown>) => ({
      intent_id: 'i',
      actor: 'agent-a',
      delegation_chain: ['d1'],
      action: 'export',
      target: 'archive/example',
      parameters,
      nonce: 'n',
      issued_at: t0,
      expires_at: t1,
    })
    expect(() => assertIntentWithinDelegation(intent({ records: 2 }), records)).not.toThrow()
    expect(() => assertIntentWithinDelegation(intent({ records: 3 }), records)).toThrow(/max_records/)

    const bad = (constraints: Record<string, unknown>) =>
      delegation({
        capabilities: [{ action: 'purchase', target: 'airline/*' }],
        constraints: constraints as SignedDelegation['constraints'],
      })
    const sample = {
      intent_id: 'i',
      actor: 'agent-a',
      delegation_chain: ['d1'],
      action: 'purchase',
      target: 'airline/example',
      parameters: { quantity: 1 },
      nonce: 'n',
      issued_at: t0,
      expires_at: t1,
    }
    for (const constraints of [
      { max_quantity: -1 },
      { max_quantity: 1.5 },
      { max_quantity: Number.NaN },
      { max_quantity: Number.POSITIVE_INFINITY },
      { max_quantity: Number.NEGATIVE_INFINITY },
      { max_quantity: Number.MAX_SAFE_INTEGER + 1 },
      { max_: 1 },
    ]) {
      expect(() => assertIntentWithinDelegation(sample, bad(constraints))).toThrow()
    }
  })

  it('lets a child lower max_quantity and not raise it', () => {
    const parent = delegation({
      capabilities: [{ action: 'purchase', target: 'airline/*', delegable: true }],
      constraints: { max_quantity: 5 },
    })
    const child = delegation({
      delegation_id: 'd2',
      issuer: 'agent-a',
      subject: 'agent-b',
      capabilities: [{ action: 'purchase', target: 'airline/example' }],
      parent_delegation_id: 'd1',
      constraints: { max_quantity: 3 },
    })
    expect(() => validateDelegationNarrowing(parent, child)).not.toThrow()
    expect(() =>
      validateDelegationNarrowing(parent, { ...child, constraints: { max_quantity: 9 } }),
    ).toThrow(/raises max_quantity/)
    expect(() =>
      assertIntentWithinDelegation(
        {
          intent_id: 'i',
          actor: 'agent-b',
          delegation_chain: ['d2'],
          action: 'purchase',
          target: 'airline/example',
          parameters: { quantity: 4 },
          nonce: 'n',
          issued_at: t0,
          expires_at: t1,
        },
        child,
      ),
    ).toThrow(/exceeds delegated max_quantity/)
  })

  it('still allows read and search to omit amount, and not other ceilings', () => {
    const read = delegation({
      capabilities: [{ action: 'read', target: 'resource/*' }],
      constraints: { max_amount: 500 },
    })
    expect(() =>
      assertIntentWithinDelegation(
        {
          intent_id: 'i',
          actor: 'agent-a',
          delegation_chain: ['d1'],
          action: 'read',
          target: 'resource/example',
          parameters: {},
          nonce: 'n',
          issued_at: t0,
          expires_at: t1,
        },
        read,
      ),
    ).not.toThrow()
    const counted = delegation({
      capabilities: [{ action: 'read', target: 'resource/*' }],
      constraints: { max_quantity: 5 },
    })
    expect(() =>
      assertIntentWithinDelegation(
        {
          intent_id: 'i',
          actor: 'agent-a',
          delegation_chain: ['d1'],
          action: 'read',
          target: 'resource/example',
          parameters: {},
          nonce: 'n',
          issued_at: t0,
          expires_at: t1,
        },
        counted,
      ),
    ).toThrow(/quantity is required/)
  })

  it('requires an amount on a spending action', () => {
    expect(() =>
      assertIntentWithinDelegation(
        {
          intent_id: 'i',
          actor: 'agent-a',
          delegation_chain: ['d1'],
          action: 'purchase',
          target: 'airline/example',
          parameters: { currency: 'EUR' },
          nonce: 'n',
          issued_at: t0,
          expires_at: t1,
        },
        grant
      )
    ).toThrow(/amount is required/)
  })
})
