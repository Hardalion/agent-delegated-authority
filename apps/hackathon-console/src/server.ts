import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { z } from 'zod'
import { DemoError } from './errors.js'
import { gateTool } from './weekend-gate.js'
import type { DemoRuntime } from './runtime.js'
import { ConsoleSecurity } from './security.js'

const EmptyBody = z.object({}).strict()
const PassphraseBody = z.object({ passphrase: z.string().min(1).max(200) }).strict()
const ResetBody = z
  .object({
    confirm: z.string(),
    passphrase: z.string(),
    acknowledgeExport: z.boolean(),
  })
  .strict()
const VerifyBody = z.object({ receipt: z.unknown() }).strict()
const SessionBody = z.object({ token: z.string().min(1).max(500) }).strict()
const Scalar = z.union([z.string().max(200), z.number().finite(), z.boolean()])
const GateArgs = z.record(
  z.string().max(64),
  z.union([z.string().max(500), z.number().finite(), z.boolean()]),
)
const GateBody = z
  .object({
    agentId: z.string().min(1).max(128),
    tool: z.string().min(1).max(80),
    args: GateArgs.optional(),
  })
  .strict()
const AgentRequestBody = z
  .object({
    agentId: z.string().min(1).max(128),
    action: z.string().min(1).max(80),
    target: z.string().min(1).max(200),
    parameters: z.record(z.string().max(40), Scalar).optional(),
  })
  .strict()

const FILES: Readonly<Record<string, { readonly file: string; readonly type: string }>> = {
  '/': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/index.html': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/styles.css': { file: 'styles.css', type: 'text/css; charset=utf-8' },
  '/app.js': { file: 'app.js', type: 'text/javascript; charset=utf-8' },
  '/i18n.js': { file: 'i18n.js', type: 'text/javascript; charset=utf-8' },
  '/guide-lang.js': { file: 'guide-lang.js', type: 'text/javascript; charset=utf-8' },
  '/guide': { file: 'guide.html', type: 'text/html; charset=utf-8' },
  '/guide.html': { file: 'guide.html', type: 'text/html; charset=utf-8' },
}

function publicDir(): string {
  return join(dirname(fileURLToPath(import.meta.url)), '..', 'public')
}

function send(
  security: ConsoleSecurity,
  res: ServerResponse,
  status: number,
  body: unknown,
  type = 'application/json; charset=utf-8',
): void {
  const payload = type.startsWith('application/json') ? JSON.stringify(body) : String(body)
  security.applyHeaders(res)
  res.writeHead(status, { 'content-type': type })
  res.end(payload)
}

function sendError(security: ConsoleSecurity, res: ServerResponse, error: unknown): void {
  if (res.headersSent) return
  const status = error instanceof DemoError ? error.status : 500
  const code = error instanceof DemoError ? error.code : 'internal'
  const message = error instanceof DemoError ? error.message : 'The request failed.'
  send(security, res, status, { error: { code, message } })
}

function readBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let size = 0
    const declared = Number(req.headers['content-length'] ?? 0)
    if (Number.isFinite(declared) && declared > 65_536) {
      reject(new DemoError(413, 'payload_too_large', 'request body exceeds 64KiB'))
      return
    }
    req.on('data', (chunk: Buffer) => {
      size += chunk.length
      if (size > 65_536) {
        reject(new DemoError(413, 'payload_too_large', 'request body exceeds 64KiB'))
        req.destroy()
      } else {
        chunks.push(chunk)
      }
    })
    req.on('end', () => {
      if (chunks.length === 0) {
        resolve(undefined)
        return
      }
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')))
      } catch {
        reject(new DemoError(400, 'malformed_input', 'request body must be JSON'))
      }
    })
    req.on('error', () => reject(new DemoError(400, 'malformed_input', 'request failed')))
  })
}

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value ?? {})
  if (!parsed.success) throw new DemoError(400, 'malformed_input', 'Request body is not valid.')
  return parsed.data
}

export function createDemoServer(runtime: DemoRuntime, security: ConsoleSecurity): Server {
  return createServer(async (req, res) => {
    req.setTimeout(15_000)
    try {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1')
      const path = url.pathname
      const method = req.method ?? 'GET'
      security.authorize(req, method)

      if (method === 'GET' && path === '/api/health') {
        send(security, res, 200, { ok: true, service: 'adap-hackathon-console', sandbox: true, realMoney: false })
        return
      }
      if (method === 'GET' && path === '/api/ready') {
        const ready = await runtime.ready()
        send(security, res, ready.ready ? 200 : 503, ready)
        return
      }
      if (method === 'POST' && path === '/api/session') {
        const body = parse(SessionBody, await readBody(req))
        const session = security.login(body.token)
        security.applyHeaders(res)
        res.setHeader('set-cookie', session.cookie)
        send(security, res, 200, {
          authenticated: true,
          teamId: security.config.teamId,
          expiresAt: session.expiresAt,
        })
        return
      }
      if (method === 'POST' && path === '/api/session/logout') {
        parse(EmptyBody, await readBody(req))
        security.logout(req)
        security.applyHeaders(res)
        res.setHeader('set-cookie', 'adap_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
        send(security, res, 200, { authenticated: false })
        return
      }
      if (method === 'GET' && path === '/api/state') {
        send(security, res, 200, runtime.publicState())
        return
      }
      if (method === 'GET' && path === '/api/export') {
        send(security, res, 200, runtime.exportEvidence())
        return
      }
      if (method === 'POST' && path === '/api/reset') {
        const body = parse(ResetBody, await readBody(req))
        const result = await runtime.reset(body)
        security.revokeAll()
        send(security, res, 200, result)
        return
      }
      if (method === 'POST' && path === '/api/receipts/verify') {
        const body = parse(VerifyBody, await readBody(req))
        send(security, res, 200, runtime.verifyReceipt(body.receipt))
        return
      }
      if (method === 'POST' && path === '/api/gate') {
        const body = parse(GateBody, await readBody(req))
        const result = await gateTool({
          agentRole: body.agentId,
          toolName: body.tool,
          toolArgs: body.args ?? {},
        })
        send(security, res, 200, {
          action: result.decision.action,
          ruleId: result.decision.ruleId,
          reason: result.decision.reason,
          executed: false,
          runTool: result.decision.action === 'ALLOW',
        })
        return
      }
      if (method === 'POST' && path === '/api/requests') {
        const body = parse(AgentRequestBody, await readBody(req))
        const parameters = body.parameters ?? {}
        send(security, res, 200, await runtime.submit({ ...body, parameters }))
        return
      }

      const reconcile = path.match(/^\/api\/cases\/([^/]+)\/reconcile$/)
      if (reconcile) {
        if (method !== 'POST') {
          send(security, res, 405, { error: { code: 'method_not_allowed', message: 'Use POST.' } })
          return
        }
        parse(EmptyBody, await readBody(req))
        send(security, res, 200, await runtime.reconcile(decodeURIComponent(reconcile[1] ?? '')))
        return
      }

      const scenario = path.match(/^\/api\/scenarios\/([a-z0-9-]+)$/)
      if (scenario) {
        if (method !== 'POST') {
          send(security, res, 405, { error: { code: 'method_not_allowed', message: 'Use POST.' } })
          return
        }
        const id = scenario[1] ?? ''
        if (!runtime.hasScenario(id)) throw new DemoError(404, 'not_found', 'Unknown scenario.')
        parse(EmptyBody, await readBody(req))
        send(security, res, 200, await runtime.runScenario(id))
        return
      }

      const approval = path.match(/^\/api\/approvals\/([^/]+)\/(approve|reject)$/)
      if (approval) {
        if (method !== 'POST') {
          send(security, res, 405, { error: { code: 'method_not_allowed', message: 'Use POST.' } })
          return
        }
        const nonce = decodeURIComponent(approval[1] ?? '')
        const action = approval[2]
        const body = parse(PassphraseBody, await readBody(req))
        const state =
          action === 'approve' ? await runtime.approve(nonce, body.passphrase) : await runtime.reject(nonce, body.passphrase)
        send(security, res, 200, state)
        return
      }

      const stored = path.match(/^\/api\/receipts\/([^/]+)\/verify$/)
      if (stored && method === 'GET') {
        send(security, res, 200, runtime.verifyStored(decodeURIComponent(stored[1] ?? '')))
        return
      }

      if (method === 'GET' && FILES[path]) {
        const item = FILES[path]
        if (!item) throw new DemoError(404, 'not_found', 'Not found.')
        const text = await readFile(join(publicDir(), item.file), 'utf8')
        send(security, res, 200, text, item.type)
        return
      }

      send(security, res, 404, { error: { code: 'not_found', message: 'Not found.' } })
    } catch (error) {
      sendError(security, res, error)
    }
  })
}

export function listen(server: Server): Promise<string> {
  server.requestTimeout = 15_000
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      if (!address || typeof address === 'string') {
        reject(new Error('no port'))
        return
      }
      resolve(`http://127.0.0.1:${address.port}`)
    })
  })
}
