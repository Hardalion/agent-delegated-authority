import http from 'node:http'
import { readFileSync } from 'node:fs'

const port = Number(process.env.PORT ?? 8080)
const vaultAddr = process.env.VAULT_ADDR
const tokenFile = process.env.VAULT_TOKEN_FILE
const secretPath = process.env.VAULT_SECRET_PATH ?? 'secret/data/adap/rail'

/** intentHash → committed business write. HTTP retries do not add a second row. */
const ledger = new Map()
let dropNext = false

async function railToken() {
  const vaultToken = readFileSync(tokenFile, 'utf8').trim()
  const res = await fetch(new URL(`/v1/${secretPath}`, vaultAddr), {
    headers: { 'x-vault-token': vaultToken },
    signal: AbortSignal.timeout(3000),
  })
  if (!res.ok) throw new Error('vault read failed')
  const body = await res.json()
  const token = body?.data?.data?.token
  if (typeof token !== 'string') throw new Error('vault secret missing')
  return token
}

function isLocal(req) {
  const addr = req.socket.remoteAddress ?? ''
  return addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1'
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'POST' && req.url === '/control/drop-next') {
      if (!isLocal(req)) {
        res.writeHead(403)
        res.end('forbidden')
        return
      }
      dropNext = true
      res.writeHead(200)
      res.end('armed')
      return
    }
    if (req.method === 'GET' && req.url === '/summary') {
      if (!isLocal(req)) {
        res.writeHead(403)
        res.end('forbidden')
        return
      }
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ businessWrites: ledger.size }))
      return
    }
    const expected = await railToken()
    const presented = (req.headers.authorization ?? '').replace(/^Bearer /, '')
    if (presented.length === 0 || presented !== expected) {
      res.writeHead(401, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ error: 'unauthorized' }))
      return
    }
    if (req.method === 'GET' && req.url?.startsWith('/ledger')) {
      const intentHash = new URL(req.url, 'http://downstream').searchParams.get('intentHash')
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ found: intentHash != null && ledger.has(intentHash) }))
      return
    }
    if (req.method !== 'POST' || req.url !== '/write') {
      res.writeHead(404)
      res.end('not found')
      return
    }
    const chunks = []
    for await (const chunk of req) chunks.push(chunk)
    const payload = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')
    const intentHash = payload.intentHash
    if (typeof intentHash !== 'string' || intentHash.length < 8) {
      res.writeHead(400)
      res.end(JSON.stringify({ error: 'intent required' }))
      return
    }
    const duplicate = ledger.has(intentHash)
    if (!duplicate) ledger.set(intentHash, { at: new Date().toISOString() })
    if (dropNext && !duplicate) {
      dropNext = false
      req.socket.destroy()
      return
    }
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ ok: true, duplicate }))
  } catch {
    res.writeHead(503, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ error: 'unavailable' }))
  }
})

server.listen(port, '0.0.0.0')
