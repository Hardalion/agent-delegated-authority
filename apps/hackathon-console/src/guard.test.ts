import { describe, expect, it } from 'vitest'
import { DemoError } from './errors.js'
import { assertDemoResetAllowed, demoEnvFromProcess, isSafeDemoDatabaseUrl } from './guard.js'

describe('demo environment guard', () => {
  it('accepts a local hackathon database and refuses the integration database', () => {
    expect(isSafeDemoDatabaseUrl('postgresql://adap:adap@127.0.0.1:55432/adap_hackathon')).toBe(true)
    expect(isSafeDemoDatabaseUrl('postgresql://adap:adap@127.0.0.1:55432/adap')).toBe(false)
    expect(isSafeDemoDatabaseUrl('postgresql://adap:adap@db.prod.internal:5432/hackathon')).toBe(false)
    expect(isSafeDemoDatabaseUrl('postgresql://adap:adap@127.0.0.1:55432/hackathon_prod')).toBe(false)
  })

  it('drops ADAP_PG_URL when building the demo environment', () => {
    const env = demoEnvFromProcess({ ADAP_PG_URL: 'postgresql://adap:adap@127.0.0.1:55432/adap', NODE_ENV: 'development' })
    expect(env.ADAP_DEMO_ENV).toBe('hackathon')
    expect(env.ADAP_PG_URL).toBeUndefined()
  })

  it('refuses to start in production and refuses a non-demo database URL', () => {
    expect(() => demoEnvFromProcess({ NODE_ENV: 'production' })).toThrow(DemoError)
    expect(() => demoEnvFromProcess({ ADAP_DEMO_PG_URL: 'postgresql://adap:adap@127.0.0.1:55432/adap' })).toThrow(/localhost/)
  })

  it('refuses reset when the process can see a non-demo database URL', () => {
    expect(() => assertDemoResetAllowed({ NODE_ENV: 'production', ADAP_DEMO_ENV: 'hackathon' })).toThrow(/production/)
    expect(() => assertDemoResetAllowed({ NODE_ENV: 'demo', ADAP_DEMO_ENV: 'hackathon', ADAP_PG_URL: 'postgresql://adap:adap@127.0.0.1:55432/adap' })).toThrow(/ADAP_PG_URL/)
    expect(() => assertDemoResetAllowed({ NODE_ENV: 'demo' })).toThrow(/ADAP_DEMO_ENV/)
    expect(() => assertDemoResetAllowed({ NODE_ENV: 'demo', ADAP_DEMO_ENV: 'hackathon' })).not.toThrow()
  })
})
