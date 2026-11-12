/**
 * Verifies what human approval identity means in this hackathon console.
 *
 * Proven: team session (or team bearer) + shared approver passphrase gate the
 * approve route; the console then signs HumanApproval as the treasury principal.
 *
 * Not proven: a distinct human subject with independent credentials (OIDC,
 * personal key, named approver account separate from prn_treasury).
 */
import { afterEach, describe, expect, it } from 'vitest'
import type { Server } from 'node:http'
import { verifyHumanApproval } from 'adap'
import { DemoRuntime } from './runtime.js'
import { createDemoServer, listen } from './server.js'
import { ConsoleSecurity, type DeploymentConfig } from './security.js'

const TEAM_TOKEN = 'team-approver-id-token-0123456789'
const PASSPHRASE = 'approver-identity-passphrase'
const FIXED = new Date('2026-11-01T12:00:00.000Z')
const servers: Server[] = []

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))))
})

function securityConfig(): DeploymentConfig {
  return {
    deployment: 'local',
    teamId: 'local',
    teamToken: TEAM_TOKEN,
    approverPassphrase: PASSPHRASE,
    sessionSecret: 'session-secret-approver-identity-0123456789ab',
    bindHost: '127.0.0.1',
    port: 0,
    sandboxUrl: null,
    sandboxToken: null,
    generatedSecrets: false,
    cookieSecure: false,
    sessionTtlMs: 60_000,
    rateLimitPerMinute: 1_000,
  }
}

async function boot() {
  const runtime = new DemoRuntime({
    now: () => FIXED,
    passphrase: PASSPHRASE,
    teamId: 'local',
    env: { ADAP_DEMO_ENV: 'hackathon', NODE_ENV: 'demo' },
  })
  const server = createDemoServer(runtime, new ConsoleSecurity(securityConfig()))
  servers.push(server)
  const url = await listen(server)
  return { runtime, url }
}

describe('human approval identity model', () => {
  it('requires a team session before the approve route is reachable', async () => {
    const { url } = await boot()
    const anonymous = await fetch(`${url}/api/approvals/n-missing/approve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-adap-request': '1', origin: url },
      body: JSON.stringify({ passphrase: PASSPHRASE }),
    })
    expect(anonymous.status).toBe(401)
    expect((await anonymous.json()).error.code).toBe('auth_required')
  })

  it('rejects a wrong passphrase without consuming the pending intent', async () => {
    const { runtime, url } = await boot()
    const login = await fetch(`${url}/api/session`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: TEAM_TOKEN }),
    })
    const cookie = login.headers.getSetCookie?.()[0]?.split(';')[0] ?? ''
    expect(cookie).toMatch(/^adap_session=/)

    await runtime.runScenario('payment', { nonce: 'n-id-wrong' })
    const wrong = await fetch(`${url}/api/approvals/${encodeURIComponent('n-id-wrong')}/approve`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie,
        'x-adap-request': '1',
        origin: url,
      },
      body: JSON.stringify({ passphrase: 'not-the-approver-passphrase' }),
    })
    expect(wrong.status).toBe(401)
    expect((await wrong.json()).error.code).toBe('approver_rejected')
    expect(runtime.publicState().pending).toHaveLength(1)
    expect(runtime.publicState().sideEffects.paymentsCreated).toBe(0)
  })

  it('signs HumanApproval as the treasury principal after passphrase acceptance', async () => {
    const runtime = new DemoRuntime({
      now: () => FIXED,
      passphrase: PASSPHRASE,
      teamId: 'local',
      env: { ADAP_DEMO_ENV: 'hackathon', NODE_ENV: 'demo' },
    })
    const pending = await runtime.runScenario('payment', { nonce: 'n-id-principal' })
    expect(pending.cases[0]?.decision).toBe('REQUIRE_HUMAN')
    const principalId = runtime.publicState().principal.id
    expect(principalId).toBe('prn_treasury')

    const before = runtime.publicState().sideEffects.paymentsCreated
    const approved = await runtime.approve('n-id-principal', PASSPHRASE)
    expect(approved.sideEffects.paymentsCreated).toBe(before + 1)
    expect(approved.pending).toHaveLength(0)

    const continued = approved.cases.find((item) => item.executed && item.approvalState === 'approved')
    expect(continued).toBeTruthy()
    expect(continued?.intentHash).toBe(pending.cases[0]?.intentHash)

    // Protocol binding: approver_id must equal the delegating principal.
    // The console holds that principal key and signs after passphrase check.
    // There is no separate human identity object in public state.
    expect(approved).not.toHaveProperty('approverSession')
    expect(Object.keys(approved).some((key) => key.toLowerCase().includes('human'))).toBe(false)
  })

  it('exposes only the treasury principal in public state, not a separate human subject', async () => {
    const runtime = new DemoRuntime({
      now: () => FIXED,
      passphrase: PASSPHRASE,
      teamId: 'local',
      env: { ADAP_DEMO_ENV: 'hackathon', NODE_ENV: 'demo' },
    })
    await runtime.runScenario('payment', { nonce: 'n-id-verify' })
    await runtime.approve('n-id-verify', PASSPHRASE)
    const state = runtime.publicState()
    const evidence = runtime.exportEvidence()
    expect(state.principal.id).toBe('prn_treasury')
    expect(state).not.toHaveProperty('approver')
    expect(evidence).not.toHaveProperty('approver')
    expect(JSON.stringify(evidence)).not.toMatch(/oidc|openid|human_subject|approver_session/i)
    expect(typeof verifyHumanApproval).toBe('function')
  })
})
