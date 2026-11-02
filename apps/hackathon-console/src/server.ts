import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { z } from 'zod'
import { DemoError } from './errors.js'
import { isScenarioId } from './scenarios.js'
import type { DemoRuntime } from './runtime.js'

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

const FILES: Readonly<Record<string, { readonly file: string; readonly type: string }>> = {
  '/': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/index.html': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/styles.css': { file: 'styles.css', type: 'text/css; charset=utf-8' },
  '/app.js': { file: 'app.js', type: 'text/javascript; charset=utf-8' },
}

function publicDir(): string {
  return join(dirname(fileURLToPath(import.meta.url)), '..', 'public')
}

function send(res: ServerResponse, status: number, body: unknown, type = 'application/json; charset=utf-8'): void {
  const payload = type.startsWith('application/json') ? JSON.stringify(body) : String(body)
  res.writeHead(status, {
    'content-type': type,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  })
  res.end(payload)
}

function sendError(res: ServerResponse, error: unknown): void {
  if (res.headersSent) return
  const status = error instanceof DemoError ? error.status : 500
  const code = error instanceof DemoError ? error.code : 'internal'
  const message = error instanceof DemoError ? error.message : 'demo request failed'
  send(res, status, { error: { code, message } })
}

function readBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let size = 0
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

export function createDemoServer(runtime: DemoRuntime): Server {
  return createServer(async (req, res) => {
    req.setTimeout(15_000)
    try {
      const url = new URL(req.url ?? '/', 'http://127.0.0.1')
      const path = url.pathname
      const method = req.method ?? 'GET'

      if (method === 'GET' && path === '/api/health') {
        send(res, 200, runtime.health())
        return
      }
      if (method === 'GET' && path === '/api/state') {
        send(res, 200, runtime.publicState())
        return
      }
      if (method === 'GET' && path === '/api/export') {
        send(res, 200, runtime.exportEvidence())
        return
      }
      if (method === 'POST' && path === '/api/reset') {
        const body = parse(ResetBody, await readBody(req))
        send(res, 200, await runtime.reset(body))
        return
      }
      if (method === 'POST' && path === '/api/receipts/verify') {
        const body = parse(VerifyBody, await readBody(req))
        send(res, 200, runtime.verifyReceipt(body.receipt))
        return
      }

      const scenario = path.match(/^\/api\/scenarios\/([a-z-]+)$/)
      if (scenario) {
        if (method !== 'POST') {
          send(res, 405, { error: { code: 'method_not_allowed', message: 'Use POST.' } })
          return
        }
        const id = scenario[1] ?? ''
        if (!isScenarioId(id)) throw new DemoError(404, 'not_found', 'Unknown scenario.')
        parse(EmptyBody, await readBody(req))
        send(res, 200, await runtime.runScenario(id))
        return
      }

      const approval = path.match(/^\/api\/approvals\/([^/]+)\/(approve|reject)$/)
      if (approval) {
        if (method !== 'POST') {
          send(res, 405, { error: { code: 'method_not_allowed', message: 'Use POST.' } })
          return
        }
        const nonce = decodeURIComponent(approval[1] ?? '')
        const action = approval[2]
        const body = parse(PassphraseBody, await readBody(req))
        const state = action === 'approve' ? await runtime.approve(nonce, body.passphrase) : await runtime.reject(nonce, body.passphrase)
        send(res, 200, state)
        return
      }

      const stored = path.match(/^\/api\/receipts\/([^/]+)\/verify$/)
      if (stored && method === 'GET') {
        send(res, 200, runtime.verifyStored(decodeURIComponent(stored[1] ?? '')))
        return
      }

      if (method === 'GET' && FILES[path]) {
        const item = FILES[path]
        if (!item) throw new DemoError(404, 'not_found', 'Not found.')
        const text = await readFile(join(publicDir(), item.file), 'utf8')
        send(res, 200, text, item.type)
        return
      }

      send(res, 404, { error: { code: 'not_found', message: 'Not found.' } })
    } catch (error) {
      sendError(res, error)
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
