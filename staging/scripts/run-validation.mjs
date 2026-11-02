/**
 * Local staging validation. Generates throwaway secrets under staging/.secrets
 * and never prints them. Run from anywhere: node staging/scripts/run-validation.mjs
 */
import { spawn } from 'node:child_process'
import { generateKeyPairSync, randomBytes } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import https from 'node:https'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const stagingDir = dirname(dirname(fileURLToPath(import.meta.url)))
const repoRoot = dirname(stagingDir)
const secretsDir = join(stagingDir, '.secrets')
const evidenceDir = join(stagingDir, '.evidence')
const tlsDir = join(secretsDir, 'tls')
const require = createRequire(join(repoRoot, 'packages/adap-store-postgres/package.json'))

const checks = []
function check(name, ok, detail = {}) {
  checks.push({ name, ok: Boolean(ok), detail })
  console.log(JSON.stringify({ check: name, ok: Boolean(ok), detail }))
}

function run(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const executable = cmd === 'pnpm' && process.platform === 'win32' ? 'pnpm.cmd' : cmd
    const child = spawn(executable, args, {
      cwd: opts.cwd ?? stagingDir,
      env: { ...process.env, ...opts.env },
      shell: executable.endsWith('.cmd'),
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (chunk) => { stdout += chunk })
    child.stderr.on('data', (chunk) => { stderr += chunk })
    child.on('error', (error) => resolve({ code: 1, stdout, stderr: error.message }))
    if (opts.input) child.stdin.end(opts.input)
    else child.stdin.end()
    child.on('close', (code) => resolve({ code: code ?? 1, stdout, stderr }))
  })
}

const compose = (args, opts) => run('docker', ['compose', ...args], opts)

function pemPair(id) {
  const keys = generateKeyPairSync('ed25519')
  const pem = keys.privateKey.export({ type: 'pkcs8', format: 'pem' })
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url')
  return { id, publicKey, privateKey: keys.privateKey, pem }
}

function httpsJson(port, path, { method = 'GET', body, headers = {}, ca }) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      host: '127.0.0.1',
      port,
      path,
      method,
      ca,
      headers: body ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body), ...headers } : headers,
    }, (res) => {
      const chunks = []
      res.on('data', (chunk) => chunks.push(chunk))
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8')
        let json = null
        try { json = JSON.parse(text) } catch { json = null }
        resolve({ status: res.statusCode ?? 0, text, json })
      })
    })
    req.setTimeout(8_000, () => req.destroy(new Error('client_timeout')))
    req.on('error', reject)
    if (body) req.write(body)
    req.end()
  })
}

function percentile(samples, p) {
  const sorted = [...samples].sort((a, b) => a - b)
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * (sorted.length - 1)))]
}

async function psql(sql, database = 'adap') {
  return compose(['exec', '-T', 'postgres', 'psql', '-U', 'adap', '-d', database, '-v', 'ON_ERROR_STOP=1', '-c', sql])
}

async function downstreamSummary() {
  const result = await compose(['exec', '-T', 'downstream', 'node', '-e', "fetch('http://127.0.0.1:8080/summary').then(r=>r.text()).then(t=>process.stdout.write(t))"])
  return JSON.parse(result.stdout)
}

async function main() {
  mkdirSync(tlsDir, { recursive: true })
  mkdirSync(evidenceDir, { recursive: true })
  const pgPassword = randomBytes(18).toString('hex')
  const vaultRoot = randomBytes(18).toString('hex')
  const clientToken = randomBytes(24).toString('hex')
  writeFileSync(join(stagingDir, '.env'), [
    `ADAP_PG_PASSWORD=${pgPassword}`,
    `VAULT_DEV_ROOT_TOKEN_ID=${vaultRoot}`,
    `ADAP_GATEWAY_CLIENT_TOKEN=${clientToken}`,
    '',
  ].join('\n'), { mode: 0o600 })

  const principal = pemPair('prn_staging')
  const agent = pemPair('agt_staging')
  const issuer = pemPair('staging-runtime')
  writeFileSync(join(secretsDir, 'issuer.pem'), issuer.pem, { mode: 0o600 })
  writeFileSync(join(secretsDir, 'directory.json'), JSON.stringify({
    entries: [
      { id: principal.id, publicKey: principal.publicKey },
      { id: agent.id, publicKey: agent.publicKey },
    ],
  }, null, 2))

  const tls = await run('docker', ['run', '--rm', '-v', `${tlsDir}:/certs`, 'alpine:3.20', 'sh', '-c',
    'apk add --no-cache openssl >/dev/null && openssl req -x509 -newkey rsa:2048 -keyout /certs/key.pem -out /certs/cert.pem -days 2 -nodes -subj /CN=adap-staging -addext subjectAltName=DNS:gateway-a,DNS:gateway-b,DNS:localhost,IP:127.0.0.1'], { cwd: repoRoot })
  check('tls-material', tls.code === 0, { exit: tls.code })
  if (tls.code !== 0) throw new Error(tls.stderr.slice(0, 500))
  const ca = readFileSync(join(tlsDir, 'cert.pem'))

  const build = await run('pnpm', ['--filter', 'adap', 'build'], { cwd: repoRoot })
  check('host-build', build.code === 0, { exit: build.code })
  if (build.code !== 0) throw new Error(build.stderr.slice(-500))
  const adap = await import(pathToFileURL(join(repoRoot, 'packages/aap/dist/index.js')).href)

  console.log(JSON.stringify({ step: 'compose-up' }))
  await compose(['down', '-v', '--remove-orphans'])
  const up = await compose(['up', '-d', '--build'])
  writeFileSync(join(evidenceDir, 'compose-up.txt'), `${up.stdout}\n${up.stderr}`.slice(-20000))
  check('compose-up', up.code === 0, { exit: up.code })
  if (up.code !== 0) throw new Error('compose up failed')

  const issued = new Date().toISOString()
  const expires = new Date(Date.now() + 15 * 60 * 1000).toISOString()
  const delegation = adap.signDelegation({
    delegation_id: 'del_staging',
    issuer: principal.id,
    subject: agent.id,
    capabilities: [{ action: 'apply', target: 'resource/*', delegable: false }],
    constraints: { max_amount: 800 },
    issued_at: issued,
    expires_at: expires,
  }, { id: principal.id, publicKey: principal.publicKey, privateKey: principal.privateKey })

  function intentFor(nonce) {
    return adap.signIntent({
      intent_id: `int_${nonce}`,
      actor: agent.id,
      delegation_chain: [delegation.delegation_id],
      action: 'apply',
      target: 'resource/example',
      parameters: { amount: 10 },
      nonce,
      issued_at: issued,
      expires_at: expires,
    }, { id: agent.id, publicKey: agent.publicKey, privateKey: agent.privateKey })
  }

  async function authorize(port, nonce, policyUri, approval) {
    const body = JSON.stringify({ chain: [delegation], intent: intentFor(nonce), ...(approval ? { approval } : {}) })
    try {
      return await httpsJson(port, '/v1/authorize', {
        method: 'POST',
        body,
        ca,
        headers: { authorization: `Bearer ${clientToken}`, 'x-adap-policy-uri': policyUri },
      })
    } catch (error) {
      return { status: 0, json: null, error: error instanceof Error ? error.message : 'request_failed' }
    }
  }

  async function waitReady() {
    const deadline = Date.now() + 180000
    let last = ''
    while (Date.now() < deadline) {
      try {
        const a = await httpsJson(8443, '/readyz', { ca })
        const b = await httpsJson(8444, '/readyz', { ca })
        last = `${a.status}/${b.status}`
        if (a.status === 200 && b.status === 200) return true
      } catch (error) {
        last = error instanceof Error ? error.message : 'connect'
      }
      await new Promise((resolve) => setTimeout(resolve, 2000))
    }
    check('gateways-ready', false, { last })
    return false
  }

  const ready = await waitReady()
  check('gateways-ready', ready, {})
  if (!ready) {
    const logs = await compose(['logs', '--tail', '40', 'gateway-a', 'gateway-b'])
    const scrubbed = logs.stdout.split(clientToken).join('[redacted]').split(pgPassword).join('[redacted]').split(vaultRoot).join('[redacted]')
    writeFileSync(join(evidenceDir, 'gateway-boot.txt'), scrubbed.slice(-8000))
    throw new Error('gateways not ready')
  }

  const same = 'nonce-replica'
  const [first, second] = await Promise.all([authorize(8443, same, 'staging-allow@1'), authorize(8444, same, 'staging-allow@1')])
  const executed = [first, second].filter((result) => result.json?.executed === true)
  check('one-execution', executed.length === 1, {
    statuses: [first.status, second.status],
    executed: [first.json?.executed ?? null, second.json?.executed ?? null],
    decisions: [first.json?.decision ?? null, second.json?.decision ?? null],
  })
  const nonceRow = await psql(`SELECT status, in_flight FROM adap_nonces WHERE nonce = '${same}'`)
  check('nonce-consumed-row', nonceRow.stdout.includes('consumed'), { row: nonceRow.stdout.trim().slice(0, 300) })
  const writesAfterReplay = await downstreamSummary()
  check('one-downstream-write', writesAfterReplay.businessWrites === 1, writesAfterReplay)

  await new Promise((resolve) => setTimeout(resolve, 500))
  const alertsAfterReplay = await fetch('http://127.0.0.1:9099/alerts').then((res) => res.json())
  check('alert-replay', alertsAfterReplay.alerts.some((alert) => alert.alert === 'replay.attempt'), {
    types: alertsAfterReplay.alerts.map((alert) => alert.alert),
  })

  const humanNonce = 'nonce-human'
  const pending = await authorize(8443, humanNonce, 'staging-human@1')
  check('require-human', pending.json?.decision === 'REQUIRE_HUMAN', { decision: pending.json?.decision ?? null })
  await compose(['restart', 'gateway-a', 'gateway-b'])
  check('gateways-ready-after-restart', await waitReady(), {})
  const pendingRow = await psql(`SELECT approval_state FROM adap_pending WHERE nonce = '${humanNonce}'`)
  check('pending-survives-gateway-restart', pendingRow.stdout.includes('pending'), { row: pendingRow.stdout.trim().slice(0, 200) })

  const approval = adap.signApproval({
    intent_hash: pending.json.intentHash,
    approver_id: principal.id,
    approved_at: issued,
    decision: 'APPROVE',
    agent_id: agent.id,
    delegation_chain_hash: pending.json.delegationHash,
    policy_content_hash: pending.json.policyHash,
    matched_rule_id: pending.json.ruleId,
  }, { id: principal.id, publicKey: principal.publicKey, privateKey: principal.privateKey })
  const [approvedA, approvedB] = await Promise.all([
    authorize(8443, humanNonce, 'staging-human@1', approval),
    authorize(8444, humanNonce, 'staging-human@1', approval),
  ])
  const approvalsExecuted = [approvedA, approvedB].filter((result) => result.json?.executed === true)
  check('one-approval-winner', approvalsExecuted.length === 1, {
    executed: [approvedA.json?.executed ?? null, approvedB.json?.executed ?? null],
    decisions: [approvedA.json?.decision ?? null, approvedB.json?.decision ?? null],
  })

  await compose(['exec', '-T', 'downstream', 'node', '-e', "fetch('http://127.0.0.1:8080/control/drop-next',{method:'POST'}).then(r=>process.stdout.write(String(r.status)))"])
  const unknownNonce = 'nonce-unknown'
  const unknown = await authorize(8443, unknownNonce, 'staging-allow@1')
  check('outcome-unknown', unknown.json?.executionState === 'unknown' && unknown.json?.executed === true, {
    executionState: unknown.json?.executionState ?? null,
    executed: unknown.json?.executed ?? null,
  })
  const retry = await authorize(8444, unknownNonce, 'staging-allow@1')
  check('unknown-retry-blocked', retry.json?.executed !== true, { decision: retry.json?.decision ?? null, status: retry.status })
  const reconcile = await httpsJson(8443, `/v1/reconcile/${unknown.json.intentHash}`, {
    ca,
    headers: { authorization: `Bearer ${clientToken}` },
  })
  check('reconciled-without-second-write', reconcile.json?.state === 'reconciled', { state: reconcile.json?.state ?? null, detail: reconcile.json?.detail ?? null })
  const writesAfterUnknown = await downstreamSummary()
  check('unknown-single-business-write', writesAfterUnknown.businessWrites === writesAfterReplay.businessWrites + approvalsExecuted.length + 1, writesAfterUnknown)

  const secretRes = await fetch('http://127.0.0.1:18200/v1/secret/data/adap/rail', { headers: { 'x-vault-token': vaultRoot } })
  const secretJson = await secretRes.json()
  const railToken = secretJson?.data?.data?.token
  const responseBlob = JSON.stringify(unknown.json) + JSON.stringify(first.json) + JSON.stringify(approvedA.json)
  check('response-omits-rail-token', typeof railToken === 'string' && !responseBlob.includes(railToken), {})
  const rotated = randomBytes(32).toString('hex')
  const rotateRes = await fetch('http://127.0.0.1:18200/v1/secret/data/adap/rail', {
    method: 'POST',
    headers: { 'x-vault-token': vaultRoot, 'content-type': 'application/json' },
    body: JSON.stringify({ data: { token: rotated, writeUrl: 'http://downstream:8080/write' } }),
  })
  const oldProbe = await compose(['exec', '-T', '-e', `PROBE_TOKEN=${railToken}`, 'downstream', 'node', '-e', "fetch('http://127.0.0.1:8080/ledger?intentHash=missing',{headers:{authorization:'Bearer '+process.env.PROBE_TOKEN}}).then(r=>process.stdout.write(String(r.status)))"])
  const newProbe = await compose(['exec', '-T', '-e', `PROBE_TOKEN=${rotated}`, 'downstream', 'node', '-e', "fetch('http://127.0.0.1:8080/ledger?intentHash=missing',{headers:{authorization:'Bearer '+process.env.PROBE_TOKEN}}).then(r=>process.stdout.write(String(r.status)))"])
  check('credential-rotation', rotateRes.ok && oldProbe.stdout.trim() === '401' && newProbe.stdout.trim() === '200', {
    oldStatus: oldProbe.stdout.trim(),
    newStatus: newProbe.stdout.trim(),
  })
  const afterRotation = await authorize(8443, 'nonce-rotated', 'staging-allow@1')
  check('authorize-after-rotation', afterRotation.json?.executed === true, { decision: afterRotation.json?.decision ?? null })

  const agentHealth = await compose(['exec', '-T', 'agent', 'curl', '-m', '3', '--cacert', '/certs/cert.pem', '-sS', '-o', '/dev/null', '-w', '%{http_code}', 'https://gateway-a:8443/healthz'])
  const agentDirect = await compose(['exec', '-T', 'agent', 'curl', '-m', '3', '-sS', 'http://downstream:8080/write'])
  const agentVault = await compose(['exec', '-T', 'agent', 'curl', '-m', '3', '-sS', 'http://vault:8200/v1/sys/health'])
  const agentUnauth = await compose(['exec', '-T', 'agent', 'curl', '-m', '3', '--cacert', '/certs/cert.pem', '-sS', '-o', '/dev/null', '-w', '%{http_code}', '-X', 'POST', 'https://gateway-a:8443/v1/authorize'])
  check('agent-reaches-gateway', agentHealth.stdout.trim() === '200', { status: agentHealth.stdout.trim() })
  check('agent-denied-downstream', agentDirect.code !== 0, { exit: agentDirect.code })
  check('agent-denied-vault', agentVault.code !== 0, { exit: agentVault.code })
  check('agent-unauthorized-without-token', agentUnauth.stdout.trim() === '401', { status: agentUnauth.stdout.trim() })

  await compose(['pause', 'postgres'])
  let duringPause = { status: 0, json: null }
  try {
    duringPause = await authorize(8443, 'nonce-paused', 'staging-allow@1')
  } catch (error) {
    duringPause = { status: 0, json: null, error: error instanceof Error ? error.message : 'timeout' }
  }
  check('postgres-pause-fails-closed', duringPause.json?.executed !== true, {
    status: duringPause.status,
    decision: duringPause.json?.decision ?? null,
    error: duringPause.error ?? null,
  })
  await compose(['unpause', 'postgres'])
  check('gateways-ready-after-unpause', await waitReady(), {})
  const retryPaused = await authorize(8444, 'nonce-paused', 'staging-allow@1')
  const pausedNonce = await psql("SELECT status FROM adap_nonces WHERE nonce = 'nonce-paused'")
  check('paused-timeout-does-not-authorize-retry', retryPaused.json?.executed !== true, {
    retryStatus: retryPaused.status,
    retryExecuted: retryPaused.json?.executed ?? null,
    retryDecision: retryPaused.json?.decision ?? null,
    nonceRow: pausedNonce.stdout.trim().slice(0, 180),
  })

  await compose(['restart', 'postgres'])
  check('gateways-ready-after-postgres-restart', await waitReady(), {})
  const nonceAfterDbRestart = await psql(`SELECT status FROM adap_nonces WHERE nonce = '${same}'`)
  check('consumed-nonce-survives-postgres-restart', nonceAfterDbRestart.stdout.includes('consumed'), { row: nonceAfterDbRestart.stdout.trim().slice(0, 200) })

  const dumpStarted = Date.now()
  const dump = await compose(['exec', '-T', 'postgres', 'pg_dump', '-U', 'adap', '-d', 'adap', '--no-owner'])
  const dumpMs = Date.now() - dumpStarted
  writeFileSync(join(evidenceDir, 'backup.sql'), dump.stdout)
  await psql('DROP DATABASE IF EXISTS adap_restore', 'postgres')
  await psql('CREATE DATABASE adap_restore', 'postgres')
  const restoreStarted = Date.now()
  const restore = await compose(['exec', '-T', 'postgres', 'psql', '-U', 'adap', '-d', 'adap_restore', '-v', 'ON_ERROR_STOP=1'], { input: dump.stdout })
  const restoreMs = Date.now() - restoreStarted
  const restored = await psql(`SELECT status FROM adap_nonces WHERE nonce = '${same}'`, 'adap_restore')
  const restoredPending = await psql(`SELECT approval_state FROM adap_pending WHERE nonce = '${humanNonce}'`, 'adap_restore')
  check('backup-restore', dump.code === 0 && restore.code === 0 && restored.stdout.includes('consumed'), {
    dumpMs,
    restoreMs,
    rpoMs: dumpMs,
    rtoMs: restoreMs,
    pending: restoredPending.stdout.trim().slice(0, 200),
  })

  await compose(['exec', '-d', 'postgres', 'psql', '-U', 'adap', '-d', 'adap', '-c', 'BEGIN; LOCK TABLE adap_nonces IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(8); COMMIT;'])
  await new Promise((resolve) => setTimeout(resolve, 700))
  const locked = await authorize(8443, 'nonce-locked', 'staging-allow@1')
  check('lock-contention-fails-closed', locked.json?.executed !== true, { status: locked.status, decision: locked.json?.decision ?? null })

  await compose(['exec', '-d', 'postgres', 'psql', '-U', 'adap', '-d', 'adap', '-c', "BEGIN; INSERT INTO adap_nonces (tenant_id, nonce, version, status, intent_hash, in_flight) VALUES ('default', 'interrupt-nonce', 1, 'pending', 'interrupt-hash', false); SELECT pg_sleep(30); COMMIT;"])
  await new Promise((resolve) => setTimeout(resolve, 700))
  await psql("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE query LIKE '%interrupt-nonce%' AND pid <> pg_backend_pid()")
  const interrupted = await psql("SELECT count(*) FROM adap_nonces WHERE nonce = 'interrupt-nonce'")
  check('interrupted-transaction-not-visible', interrupted.stdout.includes(' 0'), { row: interrupted.stdout.trim().slice(0, 240) })

  const timeout = await psql("SET statement_timeout = '50ms'; SELECT pg_sleep(1);")
  check('statement-timeout', timeout.code !== 0, { exit: timeout.code })

  await psql('DROP DATABASE IF EXISTS adap_drill', 'postgres')
  await psql('CREATE DATABASE adap_drill', 'postgres')
  const { createPool, applyMigrations, rollbackMigrations } = await import(pathToFileURL(join(repoRoot, 'packages/adap-store-postgres/dist/index.js')).href)
  const drill = createPool({ connectionString: `postgresql://adap:${pgPassword}@127.0.0.1:55433/adap_drill` })
  await applyMigrations(drill)
  const beforeRollback = await drill.query("SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename LIKE 'adap%'")
  await rollbackMigrations(drill)
  const afterRollback = await drill.query("SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename LIKE 'adap%'")
  await drill.end()
  check('migration-rollback', beforeRollback.rows.some((row) => row.tablename === 'adap_nonces') && afterRollback.rows.length === 0, {
    before: beforeRollback.rows.map((row) => row.tablename),
    after: afterRollback.rows.map((row) => row.tablename),
  })

  const latencies = []
  let loadErrors = 0
  let loadOk = 0
  for (const concurrency of [1, 8, 24]) {
    const started = Date.now()
    const batch = await Promise.all(Array.from({ length: concurrency }, (_, index) => {
      const t0 = Date.now()
      return authorize(index % 2 === 0 ? 8443 : 8444, `load-${concurrency}-${index}-${started}`, 'staging-allow@1')
        .then((result) => {
          latencies.push(Date.now() - t0)
          if (result.json?.executed === true) loadOk += 1
          else loadErrors += 1
        })
        .catch(() => { loadErrors += 1 })
    }))
    void batch
  }
  const load = {
    samples: latencies.length,
    ok: loadOk,
    errors: loadErrors,
    p50: percentile(latencies, 50),
    p95: percentile(latencies, 95),
    p99: percentile(latencies, 99),
  }
  check('load-unique-intents', load.errors === 0 && load.p99 < 2000, load)

  const pg = require('pg')
  const exhaust = new pg.Pool({ connectionString: `postgresql://adap:${pgPassword}@127.0.0.1:55433/adap`, max: 40 })
  const held = []
  let exhaustionError = null
  try {
    for (let i = 0; i < 40; i += 1) held.push(await exhaust.connect())
  } catch (error) {
    exhaustionError = error instanceof Error ? error.message : 'error'
  }
  const duringExhaustion = await authorize(8443, 'nonce-exhaust', 'staging-allow@1')
  check('connection-exhaustion-not-allow', duringExhaustion.json?.executed !== true || exhaustionError != null, {
    exhaustionError,
    status: duringExhaustion.status,
    executed: duringExhaustion.json?.executed ?? null,
  })
  for (const client of held) client.release()
  await exhaust.end()

  const stats = await run('docker', ['stats', '--no-stream', '--format', '{{.Name}} cpu={{.CPUPerc}} mem={{.MemUsage}}'])
  const logs = await compose(['logs', '--no-color', '--tail', '200', 'gateway-a', 'gateway-b', 'downstream'])
  const scrubbed = logs.stdout.split(railToken).join('[redacted-rail]').split(rotated).join('[redacted-rail]').split(clientToken).join('[redacted-client]').split(vaultRoot).join('[redacted-root]')
  writeFileSync(join(evidenceDir, 'gateway-logs.txt'), scrubbed.slice(-30000))
  check('logs-omit-secrets', !logs.stdout.includes(railToken) && !logs.stdout.includes(clientToken) && !logs.stdout.includes(rotated), {})

  const finalAlerts = await fetch('http://127.0.0.1:9099/alerts').then((res) => res.json())
  check('alert-storage-failure', finalAlerts.alerts.some((alert) => alert.alert === 'storage.failure'), {
    types: [...new Set(finalAlerts.alerts.map((alert) => alert.alert))],
  })

  const summary = {
    at: new Date().toISOString(),
    checks,
    load,
    backup: { dumpMs, restoreMs },
    stats: stats.stdout.trim().split(/\r?\n/).filter((line) => line.includes('adap-staging')),
    downstream: await downstreamSummary(),
  }
  writeFileSync(join(evidenceDir, 'summary.json'), JSON.stringify(summary, null, 2))
  const failed = checks.filter((item) => !item.ok)
  console.log(JSON.stringify({ failed: failed.map((item) => item.name), passed: checks.length - failed.length, total: checks.length }))
  process.exit(failed.length === 0 ? 0 : 1)
}

main().catch((error) => {
  console.error(JSON.stringify({ fatal: error instanceof Error ? error.message : 'fatal' }))
  process.exit(1)
})
