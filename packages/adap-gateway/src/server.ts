import { createPrivateKey, createPublicKey, timingSafeEqual } from 'node:crypto'
import { createServer as createHttpsServer } from 'node:https'
import { readFileSync } from 'node:fs'
import { z } from 'zod'
import {
  exportPublicKey,
  SharedNonceLedger,
  type Identity,
} from 'adap'
import {
  applyMigrations,
  createPool,
  PostgresAtomicNonceBackend,
  PostgresExecutionLog,
  PostgresPendingStore,
  PostgresPolicyRegistry,
} from 'adap-store-postgres'
import { AlertingEventSink } from './alerts.js'
import { JsonSecurityEventSink } from './events.js'
import { executeAuthorized } from './executor.js'
import { STAGING_ALLOW_POLICY, STAGING_ALLOW_URI, STAGING_HUMAN_POLICY, STAGING_HUMAN_URI } from './staging-policies.js'
import { VaultCredentialBroker } from './vault-broker.js'

const BodySchema = z
  .object({
    chain: z.array(z.unknown()).min(1).max(8),
    intent: z.unknown(),
    approval: z.unknown().optional(),
  })
  .strict()

const MAX_BODY = 64 * 1024

function requiredEnv(name: string): string {
  const value = process.env[name]
  if (!value) {
    console.error(JSON.stringify({ channel: 'adap.security', type: 'boot.missing_env', name }))
    process.exit(1)
  }
  return value
}

function loadIssuer(pemPath: string): Identity {
  const privateKey = createPrivateKey(readFileSync(pemPath))
  const publicKey = createPublicKey(privateKey)
  return { id: 'staging-runtime', publicKey: exportPublicKey(publicKey), privateKey }
}

function loadDirectory(filePath: string): Map<string, string> {
  const parsed = JSON.parse(readFileSync(filePath, 'utf8')) as {
    entries?: Array<{ id?: string; publicKey?: string }>
  }
  const directory = new Map<string, string>()
  for (const entry of parsed.entries ?? []) {
    if (!entry.id || !entry.publicKey) continue
    directory.set(entry.id, entry.publicKey)
  }
  if (directory.size < 2) {
    console.error(JSON.stringify({ channel: 'adap.security', type: 'boot.directory_incomplete' }))
    process.exit(1)
  }
  return directory
}

function tokenMatches(presented: string, expected: string): boolean {
  const a = Buffer.from(presented)
  const b = Buffer.from(expected)
  if (a.length !== b.length) return false
  return timingSafeEqual(a, b)
}

async function readBody(req: import('node:http').IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
    size += buf.length
    if (size > MAX_BODY) throw new Error('body_too_large')
    chunks.push(buf)
  }
  return Buffer.concat(chunks)
}

async function migrateAndRegister(pool: ReturnType<typeof createPool>): Promise<PostgresPolicyRegistry> {
  let last: unknown
  for (let attempt = 0; attempt < 6; attempt += 1) {
    try {
      await applyMigrations(pool)
      const registry = new PostgresPolicyRegistry({ pool })
      await registry.registerAsync(STAGING_ALLOW_POLICY, STAGING_ALLOW_URI)
      await registry.registerAsync(STAGING_HUMAN_POLICY, STAGING_HUMAN_URI)
      return registry
    } catch (error) {
      last = error
      await new Promise((resolve) => setTimeout(resolve, 250 * (attempt + 1)))
    }
  }
  throw last
}

export async function startGateway(): Promise<void> {
  const replica = process.env.ADAP_REPLICA_ID ?? 'gateway'
  const pool = createPool({
    connectionString: requiredEnv('ADAP_PG_URL'),
    max: 4,
    queryTimeoutMs: 4_000,
  })
  const registry = await migrateAndRegister(pool)
  const directory = loadDirectory(requiredEnv('ADAP_DIRECTORY_PATH'))
  const signer = loadIssuer(requiredEnv('ADAP_ISSUER_KEY_PATH'))
  const clientToken = requiredEnv('ADAP_GATEWAY_CLIENT_TOKEN')
  const broker = new VaultCredentialBroker({
    address: requiredEnv('VAULT_ADDR'),
    token: requiredEnv('VAULT_TOKEN'),
    secretPath: process.env.VAULT_SECRET_PATH ?? 'secret/data/adap/rail',
    writeUrlPrefix: requiredEnv('ADAP_DOWNSTREAM_ALLOWLIST'),
  })
  const events = new AlertingEventSink(
    new JsonSecurityEventSink(),
    process.env.ADAP_ALERT_WEBHOOK,
    replica,
  )
  const executionLog = new PostgresExecutionLog(pool)
  let dbReady = false
  let vaultReady = false
  let dbWasReady = true
  let vaultWasReady = true

  const refreshDependencies = async (): Promise<void> => {
    try {
      await pool.query('SELECT 1')
      dbReady = true
    } catch {
      dbReady = false
      if (dbWasReady) {
        events.emit({
          type: 'storage.failure',
          timestamp: new Date().toISOString(),
          correlationId: `ready_${replica}`,
          reason: 'postgres readiness failed',
        })
      }
    }
    dbWasReady = dbReady
    try {
      const res = await fetch(new URL('/v1/sys/health', process.env.VAULT_ADDR ?? 'http://127.0.0.1:9'), {
        signal: AbortSignal.timeout(2_000),
      })
      vaultReady = res.ok
    } catch {
      vaultReady = false
      if (vaultWasReady) {
        events.emit({
          type: 'credential.broker_failure',
          timestamp: new Date().toISOString(),
          correlationId: `ready_${replica}`,
          reason: 'vault readiness failed',
        })
      }
    }
    vaultWasReady = vaultReady
  }

  const server = createHttpsServer(
    {
      cert: readFileSync(requiredEnv('TLS_CERT_PATH')),
      key: readFileSync(requiredEnv('TLS_KEY_PATH')),
    },
    async (req, res) => {
      const url = req.url ?? '/'
      if (req.method === 'GET' && url === '/healthz') {
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ status: 'live', replica }))
        return
      }
      if (req.method === 'GET' && url === '/readyz') {
        await refreshDependencies()
        const ready = dbReady && vaultReady
        res.writeHead(ready ? 200 : 503, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ status: ready ? 'ready' : 'not_ready', replica, dbReady, vaultReady }))
        return
      }
      const header = req.headers.authorization ?? ''
      const presented = header.startsWith('Bearer ') ? header.slice(7) : ''
      if (!tokenMatches(presented, clientToken)) {
        res.writeHead(401, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: { code: 'unauthorized', message: 'gateway authentication failed' } }))
        return
      }
      if (req.method === 'GET' && url.startsWith('/v1/reconcile/')) {
        const intentHash = decodeURIComponent(url.slice('/v1/reconcile/'.length))
        try {
          const current = await executionLog.get(intentHash)
          if (!current) {
            res.writeHead(404, { 'content-type': 'application/json' })
            res.end(JSON.stringify({ error: { code: 'not_found', message: 'no execution record' } }))
            return
          }
          if (current.state === 'unknown' || current.state === 'started') {
            const found = await broker.lookup(intentHash)
            await executionLog.record({
              intentHash,
              nonce: current.nonce,
              correlationId: current.correlationId,
              state: 'reconciled',
              detail: found.found ? 'downstream_has_one_record' : 'downstream_has_no_record',
            })
          }
          const after = await executionLog.get(intentHash)
          res.writeHead(200, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ state: after?.state, detail: after?.detail ?? null }))
        } catch {
          events.emit({
            type: 'storage.failure',
            timestamp: new Date().toISOString(),
            correlationId: `reconcile_${replica}`,
            intentHash,
            reason: 'reconciliation failed closed',
          })
          res.writeHead(503, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error: { code: 'unavailable', message: 'reconciliation failed closed' } }))
        }
        return
      }
      if (req.method !== 'POST' || url !== '/v1/authorize') {
        res.writeHead(404, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: { code: 'not_found', message: 'unknown route' } }))
        return
      }
      if (!dbReady || !vaultReady) await refreshDependencies()
      if (!dbReady || !vaultReady) {
        res.writeHead(503, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: { code: 'unavailable', message: 'dependencies not ready' } }))
        return
      }
      const policyUri = req.headers['x-adap-policy-uri']
      if (policyUri !== STAGING_ALLOW_URI && policyUri !== STAGING_HUMAN_URI) {
        res.writeHead(400, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: { code: 'policy', message: 'policy URI is not registered' } }))
        return
      }
      let parsed: z.infer<typeof BodySchema>
      try {
        const raw = JSON.parse((await readBody(req)).toString('utf8')) as unknown
        parsed = BodySchema.parse(raw)
      } catch {
        res.writeHead(400, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: { code: 'schema', message: 'request rejected' } }))
        return
      }
      const pin = registry.resolveByUri(policyUri)
      if (!pin) {
        res.writeHead(503, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: { code: 'policy', message: 'policy pin unavailable' } }))
        return
      }
      try {
        const result = await executeAuthorized({
          chain: parsed.chain as never,
          intent: parsed.intent as never,
          approval: parsed.approval as never,
          directory,
          policy: pin.policy,
          policyUri,
          ledger: new SharedNonceLedger(new PostgresAtomicNonceBackend({ pool })),
          pendingStore: new PostgresPendingStore({ pool }),
          policyResolver: registry,
          signer,
          broker,
          events,
          clock: undefined,
          onExecutionState: async (state, info) => {
            const nonce = (parsed.intent as { nonce?: unknown }).nonce
            if (typeof nonce !== 'string') return
            await executionLog.record({
              intentHash: info.intentHash,
              nonce,
              correlationId: info.correlationId,
              state,
              detail: info.detail,
            })
          },
        })
        console.info(JSON.stringify({
          channel: 'adap.security',
          type: 'http.authorize',
          replica,
          correlationId: result.correlationId,
          decision: result.decision,
          executed: result.executed,
          executionState: result.executionState,
          intentHash: result.intentHash,
        }))
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({
          decision: result.decision,
          ruleId: result.ruleId,
          reason: result.reason,
          intentHash: result.intentHash,
          delegationHash: result.delegationHash,
          policyHash: result.policyHash,
          executionHash: result.executionHash,
          executed: result.executed,
          authenticated: result.authenticated,
          correlationId: result.correlationId,
          executionState: result.executionState,
          downstreamStatus: result.downstream?.status ?? null,
        }))
      } catch {
        events.emit({
          type: 'storage.failure',
          timestamp: new Date().toISOString(),
          correlationId: `authorize_${replica}`,
          reason: 'authorize failed closed',
        })
        res.writeHead(503, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ error: { code: 'unavailable', message: 'authorization failed closed' } }))
      }
    },
  )

  await refreshDependencies()
  const port = Number(process.env.PORT ?? 8443)
  server.listen(port, '0.0.0.0', () => {
    console.info(JSON.stringify({ channel: 'adap.security', type: 'boot.listening', replica, port }))
  })
}

const entry = process.argv[1]?.replaceAll('\\', '/')
if (entry?.endsWith('/src/server.ts') || entry?.endsWith('/dist/server.js')) {
  startGateway().catch((error) => {
    const raw = error instanceof Error ? error.message : 'error'
    const message = raw.replace(/postgres:\/\/\S+/gi, 'postgres://redacted').slice(0, 180)
    const code = typeof error === 'object' && error && 'code' in error ? String((error as { code: unknown }).code) : undefined
    console.error(JSON.stringify({ channel: 'adap.security', type: 'boot.failed', code, message }))
    process.exit(1)
  })
}
