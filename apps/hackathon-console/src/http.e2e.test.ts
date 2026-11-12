import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, describe, expect, it } from 'vitest'
import type { Server } from 'node:http'
import { RESET_CONFIRM } from './guard.js'
import { DemoRuntime } from './runtime.js'
import { createDemoServer, listen } from './server.js'
import { ConsoleSecurity, type DeploymentConfig } from './security.js'

const TEAM_TOKEN = 'team-test-token-0123456789abcdef'
const PASSPHRASE = 'approver-test-passphrase'

const FIXED = new Date('2026-11-01T12:00:00.000Z')
const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const servers: Server[] = []

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))))
})

function securityConfig(teamId: string, teamToken: string): DeploymentConfig {
  return {
    deployment: 'local',
    teamId,
    teamToken,
    approverPassphrase: PASSPHRASE,
    sessionSecret: `session-secret-${teamId}-0123456789abcdef`,
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

async function boot(teamId = 'local', teamToken = TEAM_TOKEN) {
  const runtime = new DemoRuntime({
    now: () => FIXED,
    passphrase: PASSPHRASE,
    teamId,
    env: { ADAP_DEMO_ENV: 'hackathon', NODE_ENV: 'demo' },
  })
  const server = createDemoServer(runtime, new ConsoleSecurity(securityConfig(teamId, teamToken)))
  servers.push(server)
  const url = await listen(server)
  const login = await fetch(`${url}/api/session`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token: teamToken }),
  })
  const cookie = (login.headers.getSetCookie?.() ?? []).map((value) => value.split(';')[0]).join('; ')
  async function call(path: string, init: RequestInit = {}) {
    const headers = new Headers(init.headers)
    headers.set('cookie', cookie)
    if ((init.method ?? 'GET') !== 'GET') headers.set('x-adap-request', '1')
    return fetch(`${url}${path}`, { ...init, headers })
  }
  return { runtime, url, call, cookie }
}

describe('console boundary', () => {
  it('keeps the agent and the HTTP server off the authority and rail internals', () => {
    const agent = readFileSync(join(root, 'src', 'agent.ts'), 'utf8')
    const server = readFileSync(join(root, 'src', 'server.ts'), 'utf8')
    const page = readFileSync(join(root, 'public', 'app.js'), 'utf8')
    const html = readFileSync(join(root, 'public', 'index.html'), 'utf8')
    expect(agent).not.toContain('executeAuthorized')
    expect(agent).not.toContain('SimulatedPayment')
    expect(agent).not.toContain('DemoBroker')
    expect(server).not.toContain('executeAuthorized')
    expect(server).not.toContain('probe')
    expect(server).not.toContain('armDownstream')
    expect(server).not.toContain('DemoBroker')
    expect(page).toContain('/api/scenarios/')
    expect(page).toContain('outcomeLabel')
    expect(page).not.toContain('executed = true')
    expect(html).toContain('id="rail-flag"')
    expect(html).toContain('Ελληνικά')
    expect(html).not.toContain('treasury-demo')
  })
})

describe('console HTTP', () => {
  it('serves the three scenarios, refresh, a second session, and a restart', async () => {
    const first = await boot()
    const page = await fetch(`${first.url}/`)
    const htmlPage = await page.text()
    expect(htmlPage).toContain('id="rail-flag"')
    expect(htmlPage).toContain('Français')
    const anonymous = await fetch(`${first.url}/api/state`)
    expect(anonymous.status).toBe(401)

    const forged = await first.call('/api/scenarios/status', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ decision: 'ALLOW', executed: true }),
    })
    expect(forged.status).toBe(400)

    const missing = await first.call('/api/execute', { method: 'POST' })
    expect(missing.status).toBe(404)
    const broker = await first.call('/api/broker/execute', { method: 'POST' })
    expect(broker.status).toBe(404)
    const rail = await first.call('/api/payments', { method: 'POST' })
    expect(rail.status).toBe(404)

    const allow = await first.call('/api/scenarios/status', { method: 'POST' })
    expect(allow.status).toBe(200)
    const allowBody = await allow.json()
    expect(allowBody.cases[0].outcomeLabel).toBe('EXECUTED')
    expect(allowBody.cases[0].verification.valid).toBe(true)

    const pendingResponse = await first.call('/api/scenarios/payment', { method: 'POST' })
    const pendingBody = await pendingResponse.json()
    const nonce = pendingBody.cases[0].nonce as string
    expect(pendingBody.cases[0].outcomeLabel).toBe('NOT EXECUTED · AWAITING APPROVAL')
    expect(pendingBody.sideEffects.paymentsCreated).toBe(0)

    const refreshed = await first.call('/api/state')
    const refreshedBody = await refreshed.json()
    expect(refreshedBody.pending).toHaveLength(1)
    expect(refreshedBody.sideEffects.paymentsCreated).toBe(0)

    const wrong = await first.call(`/api/approvals/${encodeURIComponent(nonce)}/approve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ passphrase: 'nope', signature: 'forged' }),
    })
    expect(wrong.status).toBe(400)

    const [left, right] = await Promise.all([
      first.call(`/api/approvals/${encodeURIComponent(nonce)}/approve`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ passphrase: PASSPHRASE }),
      }),
      first.call(`/api/approvals/${encodeURIComponent(nonce)}/approve`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ passphrase: PASSPHRASE }),
      }),
    ])
    const statuses = [left.status, right.status].sort()
    expect(statuses).toEqual([200, 409])
    const after = await (await first.call('/api/state')).json()
    expect(after.sideEffects.paymentsCreated).toBe(1)

    const blocked = await first.call('/api/scenarios/beneficiary', { method: 'POST' })
    const blockedBody = await blocked.json()
    expect(blockedBody.cases[0].decision).toBe('BLOCK')
    expect(blockedBody.cases[0].executed).toBe(false)
    expect(blockedBody.sideEffects.beneficiaryChanges).toBe(0)

    const receipt = blockedBody.cases.find((item: { receipt?: unknown }) => item.receipt)?.receipt
    const tampered = structuredClone(receipt)
    tampered.signature = 'cd'.repeat(64)
    const verified = await first.call('/api/receipts/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ receipt: tampered, valid: true }),
    })
    expect(verified.status).toBe(400)
    const honest = await first.call('/api/receipts/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ receipt: tampered }),
    })
    expect((await honest.json()).valid).toBe(false)

    const restarted = await boot()
    const replay = await restarted.call(`/api/approvals/${encodeURIComponent(nonce)}/approve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ passphrase: PASSPHRASE }),
    })
    expect(replay.status).toBe(404)
    expect((await (await restarted.call('/api/state')).json()).sideEffects.paymentsCreated).toBe(0)
  })

  it('refuses an unauthorized reset', async () => {
    const session = await boot()
    const anonymous = await fetch(`${session.url}/api/reset`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ confirm: RESET_CONFIRM, passphrase: PASSPHRASE, acknowledgeExport: true }),
    })
    expect(anonymous.status).toBe(401)
    await session.call('/api/scenarios/status', { method: 'POST' })
    const refused = await session.call('/api/reset', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ confirm: RESET_CONFIRM, passphrase: 'wrong', acknowledgeExport: true }),
    })
    expect(refused.status).toBe(401)
    const state = await (await session.call('/api/state')).json()
    expect(state.cases.length).toBeGreaterThan(0)
    const malformed = await session.call('/api/reset', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ passphrase: PASSPHRASE }),
    })
    expect(malformed.status).toBe(400)
  })
})
