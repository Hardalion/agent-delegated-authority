import { describe, expect, it } from 'vitest'
import { dispatchAllowed } from './pool.js'

describe('dispatch capacity', () => {
  it('refuses a full server even when the caller already holds a connection', () => {
    expect(dispatchAllowed(40, 40)).toBe(false)
    expect(dispatchAllowed(39, 40)).toBe(false)
    expect(dispatchAllowed(38, 40)).toBe(true)
    // Staging postgres: max_connections=40, superuser_reserved_connections=3.
    // Ordinary clients are already refused at 37. A gateway that still holds
    // one of those connections must not dispatch.
    expect(dispatchAllowed(37, 40, 2, 3)).toBe(false)
    expect(dispatchAllowed(36, 40, 2, 3)).toBe(false)
    expect(dispatchAllowed(35, 40, 2, 3)).toBe(true)
  })

  it('fails closed on a non-integer or tiny server limit', () => {
    expect(dispatchAllowed(Number.NaN, 40)).toBe(false)
    expect(dispatchAllowed(1, 2)).toBe(false)
    expect(dispatchAllowed(1.5, 40)).toBe(false)
  })
})
