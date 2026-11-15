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
