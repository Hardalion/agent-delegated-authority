import { describe, expect, it } from 'vitest'
import { verifyPublishedProof } from './verify-published-proof.js'

describe('published proof', () => {
  it('verifies the committed delegation, intent, policy pin, and receipt offline', () => {
    expect(verifyPublishedProof()).toBe('published proof verified offline')
  })
})
