#!/usr/bin/env node
/**
 * Synthetic HTTP load profile for the hackathon console.
 * Default: 10 teams × 5 concurrent clients each against isolated in-process servers.
 * Does not start Docker. Does not touch real money.
 */
import { performance } from 'node:perf_hooks'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const teams = Number(process.env.ADAP_LOAD_TEAMS ?? 10)
const clientsPerTeam = Number(process.env.ADAP_LOAD_CLIENTS ?? 5)
const rounds = Number(process.env.ADAP_LOAD_ROUNDS ?? 4)

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const { DemoRuntime } = await import(pathToFileURL(join(root, 'apps/hackathon-console/dist/runtime.js')).href)
const { createDemoServer } = await import(pathToFileURL(join(root, 'apps/hackathon-console/dist/server.js')).href)
const { ConsoleSecurity } = await import(pathToFileURL(join(root, 'apps/hackathon-console/dist/security.js')).href)

function listen(server) {
  return new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      if (!address || typeof address === 'string') reject(new Error('no port'))
      else resolve(`http://127.0.0.1:${address.port}`)
    })
    server.on('error', reject)
  })
}

function percentile(sorted, p) {
  if (sorted.length === 0) return 0
  const index = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)
  return sorted[index]
}

const stateDir = mkdtempSync(join(tmpdir(), 'adap-load-'))
const servers = []
const results = []
let errors = 0
let limited = 0

try {
  for (let t = 0; t < teams; t += 1) {
    const teamId = `load-${t}`
    const token = `team-token-${teamId}-${'x'.repeat(16)}`
    const passphrase = `approver-${teamId}-pass`
    const runtime = new DemoRuntime({
      passphrase,
      teamId,
      durableStore: null,
      env: { ADAP_DEMO_ENV: 'hackathon', NODE_ENV: 'demo' },
    })
    const security = new ConsoleSecurity({
      deployment: 'local',
      teamId,
      teamToken: token,
      approverPassphrase: passphrase,
      sessionSecret: `session-${teamId}-${'s'.repeat(24)}`,
      bindHost: '127.0.0.1',
      port: 0,
      sandboxUrl: null,
      sandboxToken: null,
      generatedSecrets: false,
      cookieSecure: false,
      sessionTtlMs: 60_000,
      rateLimitPerMinute: 5_000,
    })
    const server = createDemoServer(runtime, security)
    const url = await listen(server)
    servers.push(server)
    const login = await fetch(`${url}/api/session`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token }),
    })
    if (!login.ok) throw new Error(`login failed for ${teamId}`)
    const cookie = (login.headers.getSetCookie?.() ?? []).map((v) => v.split(';')[0]).join('; ')

    for (let round = 0; round < rounds; round += 1) {
      const batch = Array.from({ length: clientsPerTeam }, async () => {
        const started = performance.now()
        const response = await fetch(`${url}/api/state`, { headers: { cookie } })
        const ms = performance.now() - started
        if (response.status === 429) limited += 1
        else if (!response.ok) errors += 1
        else results.push(ms)
        return ms
      })
      await Promise.all(batch)
    }
  }

  const sorted = [...results].sort((a, b) => a - b)
  const memory = process.memoryUsage()
  const report = {
    teams,
    clientsPerTeam,
    rounds,
    samples: results.length,
    errors,
    limited,
    p50: Number(percentile(sorted, 50).toFixed(1)),
    p95: Number(percentile(sorted, 95).toFixed(1)),
    throughputRps: Number((results.length / (sorted.reduce((a, b) => a + b, 0) / 1000 || 1)).toFixed(2)),
    rss: memory.rss,
    heapUsed: memory.heapUsed,
  }
  process.stdout.write(`${JSON.stringify(report)}\n`)
  process.stdout.write(
    `LOAD teams=${teams} clients=${clientsPerTeam} rounds=${rounds} samples=${report.samples} p50=${report.p50} p95=${report.p95} errors=${errors} 429=${limited} rss=${memory.rss} heap=${memory.heapUsed}\n`,
  )
  if (errors > 0) process.exitCode = 1
} finally {
  await Promise.all(servers.map((server) => new Promise((resolve) => server.close(() => resolve()))))
  rmSync(stateDir, { recursive: true, force: true })
}
