import { spawn, type ChildProcess } from 'node:child_process'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, describe, expect, it } from 'vitest'
import { HttpSandboxAdapter } from './adapters/http-sandbox.js'
import { DemoRuntime } from './runtime.js'
import { createDemoServer, listen } from './server.js'
import { ConsoleSecurity, type DeploymentConfig } from './security.js'

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
const serverPath = join(root, 'services', 'sandbox-apis', 'server.mjs')
const children: ChildProcess[] = []
const PASSPHRASE = 'approver-test-passphrase'

function security(teamId: string, token: string): DeploymentConfig {
  return {
    deployment: 'local',
    teamId,
    teamToken: token,
    approverPassphrase: PASSPHRASE,
    sessionSecret: `session-${teamId}-${'s'.repeat(24)}`,
    bindHost: '127.0.0.1',
    port: 0,
    sandboxUrl: null,
    sandboxToken: null,
    generatedSecrets: false,
    cookieSecure: false,
    sessionTtlMs: 60_000,
    rateLimitPerMinute: 2_000,
  }
}

function startSandbox(dbPath: string, token: string): Promise<{ proc: ChildProcess; port: number }> {
  const proc = spawn(process.execPath, [serverPath], {
    cwd: root,
    env: {
      ...process.env,
      SANDBOX_TOKEN: token,
      SANDBOX_DB: dbPath,
      SANDBOX_PORT: '0',
      SANDBOX_FAULTS: '1',
      SANDBOX_FAULT_MS: '1200',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  children.push(proc)
  return new Promise((resolve, reject) => {
    let text = ''
    const timer = setTimeout(() => reject(new Error('sandbox did not become ready')), 8_000)
    proc.stdout?.on('data', (chunk: Buffer) => {
      text += chunk.toString('utf8')
      const match = text.match(/SANDBOX_READY (\d+)/)
      if (match?.[1]) {
        clearTimeout(timer)
        resolve({ proc, port: Number(match[1]) })
      }
    })
    proc.on('exit', (code) => {
      clearTimeout(timer)
      reject(new Error(`sandbox exited ${code}`))
    })
  })
}

async function session(url: string, token: string) {
  const login = await fetch(`${url}/api/session`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token }),
  })
  const cookie = (login.headers.getSetCookie?.() ?? []).map((value) => value.split(';')[0]).join('; ')
  return async (path: string, init: RequestInit = {}) => {
    const headers = new Headers(init.headers)
    headers.set('cookie', cookie)
    if ((init.method ?? 'GET') !== 'GET') headers.set('x-adap-request', '1')
    return fetch(`${url}${path}`, { ...init, headers })
  }
}

describe('persistent sandbox workflows', () => {
  const dir = mkdtempSync(join(tmpdir(), 'adap-hackathon-'))
  const tokenA = 'sandbox-token-team-a-0123456789'
  const tokenB = 'sandbox-token-team-b-0123456789'
  let portA = 0
  let portB = 0

  afterAll(async () => {
    await Promise.all(
      children.map(
        (child) =>
          new Promise<void>((resolve) => {
            child.once('exit', () => resolve())
            child.kill()
          }),
      ),
    )
  })

  it('runs allow, approval, block, vendor, purchase, replay, timeout, isolation, and load', async () => {
    const first = await startSandbox(join(dir, 'team-a-hackathon.sqlite'), tokenA)
    const second = await startSandbox(join(dir, 'team-b-hackathon.sqlite'), tokenB)
    portA = first.port
    portB = second.port
    const adapterA = new HttpSandboxAdapter({
      baseUrl: `http://127.0.0.1:${portA}`,
      token: tokenA,
      timeoutMs: 400,
      faults: true,
    })
    const runtimeA = new DemoRuntime({
      passphrase: PASSPHRASE,
      teamId: 'team-a',
      sandbox: adapterA,
      env: { ADAP_DEMO_ENV: 'hackathon', NODE_ENV: 'demo' },
    })
    await runtimeA.refreshSandbox()
    const before = await adapterA.counters()

    const read = await runtimeA.runScenario('status')
    expect(read.cases[0]?.decision).toBe('ALLOW')
    expect(read.cases[0]?.executed).toBe(true)
    expect(read.cases[0]?.executionMode).toBe('sandbox-api')
    expect(read.cases[0]?.downstreamResourceId).toBe('pay_seed_1001')

    const low = await runtimeA.runScenario('pay-120')
    expect(low.cases[0]?.decision).toBe('ALLOW')
    expect(low.cases[0]?.executed).toBe(true)
    expect(low.cases[0]?.downstreamResourceId).toMatch(/^pay_/)
    const lowId = low.cases[0]?.downstreamResourceId

    const review = await runtimeA.runScenario('pay-750', { nonce: 'n-review-750' })
    expect(review.cases[0]?.decision).toBe('REQUIRE_HUMAN')
    expect(review.cases[0]?.executed).toBe(false)
    const mid = await adapterA.counters()
    expect(mid.committedPayments).toBe(before.committedPayments + 1)

    const approved = await runtimeA.approve('n-review-750', PASSPHRASE)
    const paymentIds = approved.payments.map((payment) => payment.id)
    expect(paymentIds.filter((id) => id === lowId)).toHaveLength(1)
    expect(approved.sideEffects.paymentsCreated).toBe(2)
    const afterApproval = await adapterA.counters()
    expect(afterApproval.committedPayments).toBe(before.committedPayments + 2)
    await runtimeA.runScenario('pay-750', { nonce: 'n-parallel-750' })
    const beforeParallel = (await adapterA.counters()).committedPayments
    const parallel = await Promise.allSettled([
      runtimeA.approve('n-parallel-750', PASSPHRASE),
      runtimeA.approve('n-parallel-750', PASSPHRASE),
    ])
    expect(parallel.filter((item) => item.status === 'fulfilled')).toHaveLength(1)
    expect((await adapterA.counters()).committedPayments).toBe(beforeParallel + 1)
    const expectedPayments = beforeParallel + 1
    await expect(runtimeA.approve('n-review-750', PASSPHRASE)).rejects.toThrow(/additional execution/i)
    expect((await adapterA.counters()).committedPayments).toBe(expectedPayments)

    const rejectedRuntime = new DemoRuntime({
      passphrase: PASSPHRASE,
      teamId: 'team-a',
      sandbox: adapterA,
      env: { ADAP_DEMO_ENV: 'hackathon', NODE_ENV: 'demo' },
    })
    await rejectedRuntime.runScenario('pay-750', { nonce: 'n-reject-750' })
    await rejectedRuntime.reject('n-reject-750', PASSPHRASE)
    expect((await adapterA.counters()).committedPayments).toBe(expectedPayments)

    const blocked = await runtimeA.runScenario('pay-6000')
    expect(blocked.cases[0]?.decision).toBe('BLOCK')
    expect(blocked.cases[0]?.executed).toBe(false)
    expect((await adapterA.counters()).committedPayments).toBe(expectedPayments)

    const vendorBefore = (await adapterA.listVendors()).find((vendor) => vendor.id === 'vendor_northwind')?.iban
    const pendingVendor = await runtimeA.runScenario('vendor-change', { nonce: 'n-vendor-1' })
    expect(pendingVendor.cases[0]?.decision).toBe('REQUIRE_HUMAN')
    expect((await adapterA.listVendors()).find((vendor) => vendor.id === 'vendor_northwind')?.iban).toBe(vendorBefore)
    const changed = await runtimeA.approve('n-vendor-1', PASSPHRASE)
    expect(changed.sideEffects.beneficiaryChanges).toBe(1)
    expect((await adapterA.listVendors()).find((vendor) => vendor.id === 'vendor_northwind')?.iban).toBe('GR9900000000000000000000099')
    expect((await adapterA.counters()).committedVendorChanges).toBe(1)

    const purchase = await runtimeA.runScenario('purchase-allow')
    expect(purchase.cases[0]?.decision).toBe('ALLOW')
    expect(purchase.cases[0]?.executionMode).toBe('sandbox-api')
    const purchaseReview = await runtimeA.runScenario('purchase-review', { nonce: 'n-purchase-review' })
    expect(purchaseReview.cases[0]?.decision).toBe('REQUIRE_HUMAN')
    expect(purchaseReview.cases[0]?.executed).toBe(false)
    const restricted = await runtimeA.runScenario('purchase-block')
    expect(restricted.cases[0]?.decision).toBe('BLOCK')
    expect((await adapterA.counters()).committedPurchases).toBe(1)

    const replay = await runtimeA.runScenario('status', { nonce: read.cases[0]?.nonce })
    expect(replay.cases[0]?.ruleId).toBe('replay')
    expect(replay.cases[0]?.executed).toBe(false)

    const paymentsBeforeTimeout = (await adapterA.listPayments()).length
    runtimeA.armSandboxFault('timeout-before')
    const beforeCommit = await runtimeA.runScenario('pay-120')
    expect(beforeCommit.cases[0]?.outcomeLabel).toBe('OUTCOME UNKNOWN')
    expect(beforeCommit.cases[0]?.executed).toBe(false)
    const reconciledAbsent = await runtimeA.reconcile(beforeCommit.cases[0]?.correlationId ?? '')
    expect(reconciledAbsent.cases.find((item) => item.correlationId === beforeCommit.cases[0]?.correlationId)?.reason).toMatch(/no committed record/i)
    expect((await adapterA.listPayments()).length).toBe(paymentsBeforeTimeout)

    runtimeA.armSandboxFault('timeout-after')
    const afterCommit = await runtimeA.runScenario('pay-120')
    expect(afterCommit.cases[0]?.outcomeLabel).toBe('OUTCOME UNKNOWN')
    expect(afterCommit.cases[0]?.executed).toBe(false)
    const reconciled = await runtimeA.reconcile(afterCommit.cases[0]?.correlationId ?? '')
    const reconciledCase = reconciled.cases.find((item) => item.correlationId === afterCommit.cases[0]?.correlationId)
    expect(reconciledCase?.downstreamResourceId).toMatch(/^pay_/)
    expect(reconciledCase?.reason).toMatch(/not repeated/i)
    const samePayment = (await adapterA.listPayments()).filter((payment) => payment.id === reconciledCase?.downstreamResourceId)
    expect(samePayment).toHaveLength(1)

    await adapterA.setWrites(false)
    const paused = await runtimeA.runScenario('pay-120')
    expect(paused.cases[0]?.executed).toBe(false)
    expect(paused.cases[0]?.downstreamStatus === 'failed' || paused.cases[0]?.downstreamStatus === 'unknown').toBe(true)
    await adapterA.setWrites(true)

    const closed = new HttpSandboxAdapter({ baseUrl: 'http://127.0.0.1:1', token: tokenA, timeoutMs: 300 })
    const closedRuntime = new DemoRuntime({
      passphrase: PASSPHRASE,
      teamId: 'team-a',
      sandbox: closed,
      env: { ADAP_DEMO_ENV: 'hackathon', NODE_ENV: 'demo' },
    })
    const unavailable = await closedRuntime.runScenario('pay-120')
    expect(unavailable.cases[0]?.executed).toBe(false)
    expect(unavailable.cases[0]?.executionMode).not.toBe('sandbox-api')

    const http = createDemoServer(runtimeA, new ConsoleSecurity(security('team-a', 'team-a-console-token-0123456789')))
    const urlA = await listen(http)
    const callA = await session(urlA, 'team-a-console-token-0123456789')
    const unknownAgent = await callA('/api/requests', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        agentId: 'agt_unknown',
        action: 'create_payment',
        target: 'payments/outgoing',
        parameters: { purpose: 'treasury.sandbox', amount: 100, currency: 'EUR', beneficiary: 'vendor_acme' },
      }),
    })
    expect(unknownAgent.status).toBe(403)
    const malformedAgent = await callA('/api/requests', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        agentId: 'bad agent',
        action: 'get_payment_status',
        target: 'payments/pay_seed_1001',
        parameters: { purpose: 'treasury.sandbox' },
      }),
    })
    expect(malformedAgent.status).toBe(400)

    const adapterB = new HttpSandboxAdapter({ baseUrl: `http://127.0.0.1:${portB}`, token: tokenB, timeoutMs: 800 })
    const runtimeB = new DemoRuntime({
      passphrase: PASSPHRASE,
      teamId: 'team-b',
      sandbox: adapterB,
      env: { ADAP_DEMO_ENV: 'hackathon', NODE_ENV: 'demo' },
    })
    await runtimeB.refreshSandbox()
    await runtimeB.runScenario('pay-120')
    const teamBPayments = (await adapterB.listPayments()).length
    const httpB = createDemoServer(runtimeB, new ConsoleSecurity(security('team-b', 'team-b-console-token-0123456789')))
    const urlB = await listen(httpB)
    const cross = await fetch(`${urlB}/api/state`, { headers: { cookie: (await callA('/api/state')).headers.get('set-cookie') ?? 'adap_session=nope' } })
    expect(cross.status).toBe(401)
    await runtimeA.reset({ confirm: 'RESET HACKATHON DEMO', passphrase: PASSPHRASE, acknowledgeExport: true })
    expect((await adapterB.listPayments()).length).toBe(teamBPayments)
    expect((await adapterA.listPayments()).some((payment) => payment.id === 'pay_seed_1001')).toBe(true)

    const exportBody = JSON.stringify(runtimeA.exportEvidence())
    expect(exportBody).not.toContain(tokenA)
    expect(exportBody).not.toContain(PASSPHRASE)
    expect(exportBody).not.toContain('PRIVATE KEY')

    const samples: number[] = []
    const waves = 4
    const width = 20
    for (let wave = 0; wave < waves; wave += 1) {
      const batch = await Promise.all(
        Array.from({ length: width }, async () => {
          const started = performance.now()
          const state = await runtimeB.runScenario('status')
          samples.push(performance.now() - started)
          return state
        }),
      )
      expect(batch.every((state) => state.cases[0]?.decision === 'ALLOW' || state.cases[0]?.ruleId === 'replay')).toBe(true)
    }
    samples.sort((a, b) => a - b)
    const p50 = samples[Math.floor(samples.length * 0.5)] ?? 0
    const p95 = samples[Math.floor(samples.length * 0.95)] ?? 0
    const memory = process.memoryUsage()
    process.stdout.write(
      `LOAD team-b status waves=${waves} width=${width} samples=${samples.length} p50=${p50.toFixed(1)} p95=${p95.toFixed(1)} rss=${memory.rss} heap=${memory.heapUsed}\n`,
    )
    expect(samples.length).toBe(waves * width)
  }, 60_000)
})
