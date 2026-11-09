import { describe, expect, it } from 'vitest'
import { DemoError } from './errors.js'
import { loadDeploymentConfig } from './security.js'
import { assertSandboxBaseUrl } from './adapters/http-sandbox.js'

describe('deployment configuration', () => {
  it('refuses the retired demo passphrase and a public bind', () => {
    expect(() => loadDeploymentConfig({ ADAP_APPROVER_PASSPHRASE: 'treasury-demo', ADAP_TEAM_TOKEN: 'x'.repeat(24) }, { generate: false })).toThrow(DemoError)
    expect(() =>
      loadDeploymentConfig({
        ADAP_DEPLOYMENT: 'hosted',
        ADAP_TEAM_ID: 'team-a',
        ADAP_TEAM_TOKEN: 't'.repeat(24),
        ADAP_APPROVER_PASSPHRASE: 'p'.repeat(16),
        ADAP_SESSION_SECRET: 's'.repeat(32),
        ADAP_SANDBOX_URL: 'http://127.0.0.1:9',
        ADAP_SANDBOX_TOKEN: 'k'.repeat(16),
        ADAP_BIND_HOST: '0.0.0.0',
      }),
    ).toThrow(/127\.0\.0\.1/)
  })

  it('refuses hosted startup without a sandbox credential', () => {
    expect(() =>
      loadDeploymentConfig({
        ADAP_DEPLOYMENT: 'hosted',
        ADAP_TEAM_ID: 'team-a',
        ADAP_TEAM_TOKEN: 't'.repeat(24),
        ADAP_APPROVER_PASSPHRASE: 'p'.repeat(16),
        ADAP_SESSION_SECRET: 's'.repeat(32),
      }),
    ).toThrow(/SANDBOX/)
  })

  it('accepts only a loopback sandbox URL', () => {
    expect(assertSandboxBaseUrl('http://127.0.0.1:4318').hostname).toBe('127.0.0.1')
    expect(() => assertSandboxBaseUrl('http://169.254.169.254/latest')).toThrow(/loopback|not allowed/)
    expect(() => assertSandboxBaseUrl('file:///tmp/sandbox')).toThrow(/scheme/)
  })
})
