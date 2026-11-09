/**
 * Local sandbox APIs for the hackathon console.
 * Persists synthetic payments, vendor accounts, and purchase requests in SQLite.
 * This process never transfers real money and refuses a non-demo database path.
 */
import { createServer } from 'node:http'
import { randomBytes, timingSafeEqual } from 'node:crypto'
import { mkdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'

const token = process.env.SANDBOX_TOKEN ?? ''
if (token.length < 16 || token === 'treasury-demo') {
  process.stderr.write('SANDBOX_TOKEN must be at least 16 characters and must not be a default password.\n')
  process.exit(1)
}

const dbPath = resolve(process.env.SANDBOX_DB ?? '.demo/hackathon-sandbox.sqlite')
if (!/(hackathon|demo)/i.test(dbPath) || /(prod|customer|live)/i.test(dbPath)) {
  process.stderr.write('Refusing to open a database path that is not a hackathon or demo file.\n')
  process.exit(1)
}

const faultsEnabled = process.env.SANDBOX_FAULTS === '1'
const faultMs = Number(process.env.SANDBOX_FAULT_MS ?? 1500)
const host = process.env.SANDBOX_CONTAINER === '1' ? '0.0.0.0' : '127.0.0.1'
const port = Number(process.env.SANDBOX_PORT ?? 0)

mkdirSync(dirname(dbPath), { recursive: true })
const db = new DatabaseSync(dbPath)
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS payments (
    id TEXT PRIMARY KEY,
    intent_hash TEXT UNIQUE NOT NULL,
    beneficiary TEXT NOT NULL,
    amount INTEGER NOT NULL,
    currency TEXT NOT NULL,
    status TEXT NOT NULL,
    reference TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS vendors (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    iban TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS vendor_changes (
    id TEXT PRIMARY KEY,
    intent_hash TEXT UNIQUE NOT NULL,
    vendor_id TEXT NOT NULL,
    before_iban TEXT NOT NULL,
    after_iban TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS purchases (
    id TEXT PRIMARY KEY,
    intent_hash TEXT UNIQUE NOT NULL,
    category TEXT NOT NULL,
    amount INTEGER NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS request_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    intent_hash TEXT,
    committed INTEGER NOT NULL,
    at TEXT NOT NULL
  );
`)

function seed() {
  const payments = db.prepare('SELECT COUNT(*) AS n FROM payments').get()
  if (Number(payments.n) === 0) {
    const now = new Date().toISOString()
    const insert = db.prepare(
      'INSERT INTO payments (id, intent_hash, beneficiary, amount, currency, status, reference, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    )
    insert.run('pay_seed_1001', 'seed-pay-1001', 'vendor_northwind', 15000, 'EUR', 'settled', 'SEED-1001', now)
    insert.run('pay_seed_1002', 'seed-pay-1002', 'vendor_acme', 42000, 'EUR', 'settled', 'SEED-1002', now)
  }
  const vendors = db.prepare('SELECT COUNT(*) AS n FROM vendors').get()
  if (Number(vendors.n) === 0) {
    const now = new Date().toISOString()
    const insert = db.prepare('INSERT INTO vendors (id, name, iban, updated_at) VALUES (?, ?, ?, ?)')
    insert.run('vendor_northwind', 'Northwind Supplies', 'GR1100000000000000000000001', now)
    insert.run('vendor_acme', 'Acme Components', 'GR1100000000000000000000002', now)
  }
}
seed()

let acceptWrites = true

function secretEqual(input) {
  const left = Buffer.from(input)
  const right = Buffer.from(token)
  if (left.length !== right.length) return false
  return timingSafeEqual(left, right)
}

function authorized(req) {
  const header = req.headers.authorization ?? ''
  const presented = header.startsWith('Bearer ') ? header.slice('Bearer '.length) : ''
  return secretEqual(presented)
}

function send(res, status, body) {
  const payload = JSON.stringify(body)
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  })
  res.end(payload)
}

function readBody(req) {
  return new Promise((resolveBody, reject) => {
    const chunks = []
    let size = 0
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > 65_536) {
        reject(Object.assign(new Error('payload_too_large'), { status: 413 }))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => {
      if (chunks.length === 0) {
        resolveBody({})
        return
      }
      try {
        resolveBody(JSON.parse(Buffer.concat(chunks).toString('utf8')))
      } catch {
        reject(Object.assign(new Error('malformed_json'), { status: 400 }))
      }
    })
    req.on('error', () => reject(Object.assign(new Error('malformed_json'), { status: 400 })))
  })
}

function logRequest(kind, intentHash, committed) {
  db.prepare('INSERT INTO request_log (kind, intent_hash, committed, at) VALUES (?, ?, ?, ?)').run(
    kind,
    intentHash ?? null,
    committed ? 1 : 0,
    new Date().toISOString(),
  )
}

function counters() {
  const row = db.prepare(
    `SELECT
      SUM(CASE WHEN kind IN ('payment', 'vendor', 'purchase') THEN 1 ELSE 0 END) AS mutating,
      SUM(CASE WHEN kind = 'payment' AND committed = 1 THEN 1 ELSE 0 END) AS payments,
      SUM(CASE WHEN kind = 'vendor' AND committed = 1 THEN 1 ELSE 0 END) AS vendors,
      SUM(CASE WHEN kind = 'purchase' AND committed = 1 THEN 1 ELSE 0 END) AS purchases,
      SUM(committed) AS committed
    FROM request_log`,
  ).get()
  return {
    mutatingRequests: Number(row.mutating ?? 0),
    committedPayments: Number(row.payments ?? 0),
    committedVendorChanges: Number(row.vendors ?? 0),
    committedPurchases: Number(row.purchases ?? 0),
    committed: Number(row.committed ?? 0),
  }
}

function wait(ms, req) {
  return new Promise((resolveWait) => {
    const timer = setTimeout(() => resolveWait('elapsed'), ms)
    req.on('close', () => {
      clearTimeout(timer)
      resolveWait('closed')
    })
  })
}

function faultHeader(req) {
  if (!faultsEnabled) return null
  const value = req.headers['x-sandbox-fault']
  return value === 'timeout-before' || value === 'timeout-after' ? value : null
}

function paymentRow(row) {
  return {
    id: row.id,
    beneficiary: row.beneficiary,
    amount: row.amount,
    currency: row.currency,
    status: row.status,
    reference: row.reference,
  }
}

const server = createServer(async (req, res) => {
  try {
    if (!authorized(req)) {
      send(res, 401, { error: { code: 'unauthorized', message: 'sandbox credential was not accepted' } })
      return
    }
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const path = url.pathname
    const method = req.method ?? 'GET'

    if (method === 'GET' && path === '/health') {
      send(res, 200, { ok: true, service: 'hackathon-sandbox', currency: 'EUR', realMoney: false })
      return
    }
    if (method === 'GET' && path === '/ready') {
      send(res, acceptWrites ? 200 : 503, { ready: acceptWrites })
      return
    }
    if (method === 'GET' && path === '/v1/meta') {
      send(res, 200, { ...counters(), acceptWrites, database: 'hackathon-sandbox' })
      return
    }
    if (method === 'GET' && path === '/v1/payments') {
      const rows = db.prepare('SELECT * FROM payments ORDER BY created_at ASC').all()
      send(res, 200, { payments: rows.map(paymentRow) })
      return
    }
    if (method === 'GET' && path === '/v1/vendors') {
      const rows = db.prepare('SELECT id, name, iban, updated_at FROM vendors ORDER BY id ASC').all()
      send(res, 200, { vendors: rows })
      return
    }
    if (method === 'GET' && path === '/v1/purchases') {
      const rows = db.prepare('SELECT id, category, amount, title, status, intent_hash FROM purchases ORDER BY created_at ASC').all()
      send(res, 200, { purchases: rows })
      return
    }

    const paymentRead = path.match(/^\/v1\/payments\/(pay_[A-Za-z0-9_-]+)$/)
    if (method === 'GET' && paymentRead) {
      const row = db.prepare('SELECT * FROM payments WHERE id = ?').get(paymentRead[1])
      if (!row) {
        send(res, 404, { error: { code: 'not_found', message: 'payment was not found' } })
        return
      }
      send(res, 200, paymentRow(row))
      return
    }

    const reconcile = path.match(/^\/v1\/reconcile\/([a-f0-9]{64}|seed-pay-\d+)$/)
    if (method === 'GET' && reconcile) {
      const intentHash = reconcile[1]
      const payment = db.prepare('SELECT * FROM payments WHERE intent_hash = ?').get(intentHash)
      const vendor = db.prepare('SELECT * FROM vendor_changes WHERE intent_hash = ?').get(intentHash)
      const purchase = db.prepare('SELECT * FROM purchases WHERE intent_hash = ?').get(intentHash)
      if (payment) {
        send(res, 200, { state: 'committed', kind: 'payment', resourceId: payment.id, record: paymentRow(payment) })
        return
      }
      if (vendor) {
        send(res, 200, { state: 'committed', kind: 'vendor', resourceId: vendor.id, record: vendor })
        return
      }
      if (purchase) {
        send(res, 200, { state: 'committed', kind: 'purchase', resourceId: purchase.id, record: purchase })
        return
      }
      send(res, 200, { state: 'absent', kind: null, resourceId: null })
      return
    }

    if (method === 'POST' && path === '/v1/admin/reset') {
      const body = await readBody(req)
      if (body.confirm !== 'RESET SANDBOX DATA') {
        send(res, 400, { error: { code: 'reset_confirm_required', message: 'reset confirmation was not accepted' } })
        return
      }
      db.exec('DELETE FROM payments; DELETE FROM vendor_changes; DELETE FROM purchases; DELETE FROM request_log; DELETE FROM vendors;')
      seed()
      acceptWrites = true
      send(res, 200, { reset: true, ...counters() })
      return
    }

    if (method === 'POST' && path === '/v1/admin/writes') {
      if (!faultsEnabled) {
        send(res, 404, { error: { code: 'not_found', message: 'not found' } })
        return
      }
      const body = await readBody(req)
      acceptWrites = body.accept === true
      send(res, 200, { acceptWrites })
      return
    }

    if (!acceptWrites && method === 'POST') {
      send(res, 503, { error: { code: 'unavailable', message: 'sandbox writes are paused' } })
      return
    }

    if (method === 'POST' && path === '/v1/payments') {
      const body = await readBody(req)
      const fault = faultHeader(req)
      const intentHash = typeof body.intentHash === 'string' ? body.intentHash : ''
      if (!/^[a-f0-9]{64}$/.test(intentHash)) {
        logRequest('payment', null, false)
        send(res, 400, { error: { code: 'invalid_intent', message: 'intent hash is required' } })
        return
      }
      if (fault === 'timeout-before') {
        const waited = await wait(faultMs, req)
        if (waited === 'closed' || res.writableEnded) {
          logRequest('payment', intentHash, false)
          return
        }
      }
      const existing = db.prepare('SELECT * FROM payments WHERE intent_hash = ?').get(intentHash)
      if (existing) {
        logRequest('payment', intentHash, false)
        send(res, 200, { ...paymentRow(existing), duplicate: true, resourceId: existing.id })
        return
      }
      if (typeof body.amount !== 'number' || !Number.isInteger(body.amount) || body.amount <= 0) {
        logRequest('payment', intentHash, false)
        send(res, 400, { error: { code: 'invalid_amount', message: 'amount must be a positive integer of minor units' } })
        return
      }
      if (body.currency !== 'EUR' || typeof body.beneficiary !== 'string' || !/^vendor_[a-z0-9_]+$/.test(body.beneficiary)) {
        logRequest('payment', intentHash, false)
        send(res, 400, { error: { code: 'invalid_payment', message: 'payment fields were rejected' } })
        return
      }
      const id = `pay_${randomBytes(8).toString('hex')}`
      const now = new Date().toISOString()
      db.prepare(
        'INSERT INTO payments (id, intent_hash, beneficiary, amount, currency, status, reference, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      ).run(id, intentHash, body.beneficiary, body.amount, 'EUR', 'recorded', String(body.reference ?? 'SANDBOX'), now)
      logRequest('payment', intentHash, true)
      if (fault === 'timeout-after') await wait(faultMs, req)
      if (!res.writableEnded) {
        send(res, 201, {
          id,
          resourceId: id,
          beneficiary: body.beneficiary,
          amount: body.amount,
          currency: 'EUR',
          status: 'recorded',
          reference: String(body.reference ?? 'SANDBOX'),
          duplicate: false,
        })
      }
      return
    }

    const vendorPath = path.match(/^\/v1\/vendors\/(vendor_[a-z0-9_]+)\/account$/)
    if (method === 'POST' && vendorPath) {
      const body = await readBody(req)
      const fault = faultHeader(req)
      const intentHash = typeof body.intentHash === 'string' ? body.intentHash : ''
      const vendorId = vendorPath[1]
      if (!/^[a-f0-9]{64}$/.test(intentHash)) {
        logRequest('vendor', null, false)
        send(res, 400, { error: { code: 'invalid_intent', message: 'intent hash is required' } })
        return
      }
      if (fault === 'timeout-before') {
        const waited = await wait(faultMs, req)
        if (waited === 'closed' || res.writableEnded) {
          logRequest('vendor', intentHash, false)
          return
        }
      }
      const existing = db.prepare('SELECT * FROM vendor_changes WHERE intent_hash = ?').get(intentHash)
      if (existing) {
        logRequest('vendor', intentHash, false)
        send(res, 200, { ...existing, duplicate: true, resourceId: existing.id })
        return
      }
      const vendor = db.prepare('SELECT * FROM vendors WHERE id = ?').get(vendorId)
      if (!vendor || typeof body.iban !== 'string' || !/^[A-Z0-9]{15,34}$/.test(body.iban)) {
        logRequest('vendor', intentHash, false)
        send(res, 400, { error: { code: 'invalid_vendor', message: 'vendor account change was rejected' } })
        return
      }
      const id = `vch_${randomBytes(8).toString('hex')}`
      const now = new Date().toISOString()
      const before = vendor.iban
      db.exec('BEGIN IMMEDIATE')
      try {
        db.prepare('UPDATE vendors SET iban = ?, updated_at = ? WHERE id = ?').run(body.iban, now, vendorId)
        db.prepare(
          'INSERT INTO vendor_changes (id, intent_hash, vendor_id, before_iban, after_iban, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        ).run(id, intentHash, vendorId, before, body.iban, now)
        db.exec('COMMIT')
      } catch (error) {
        db.exec('ROLLBACK')
        throw error
      }
      logRequest('vendor', intentHash, true)
      if (fault === 'timeout-after') await wait(faultMs, req)
      if (!res.writableEnded) {
        send(res, 200, {
          id,
          resourceId: id,
          vendorId,
          beforeIban: before,
          afterIban: body.iban,
          duplicate: false,
        })
      }
      return
    }

    if (method === 'POST' && path === '/v1/purchases') {
      const body = await readBody(req)
      const fault = faultHeader(req)
      const intentHash = typeof body.intentHash === 'string' ? body.intentHash : ''
      if (!/^[a-f0-9]{64}$/.test(intentHash)) {
        logRequest('purchase', null, false)
        send(res, 400, { error: { code: 'invalid_intent', message: 'intent hash is required' } })
        return
      }
      if (fault === 'timeout-before') {
        const waited = await wait(faultMs, req)
        if (waited === 'closed' || res.writableEnded) {
          logRequest('purchase', intentHash, false)
          return
        }
      }
      const existing = db.prepare('SELECT * FROM purchases WHERE intent_hash = ?').get(intentHash)
      if (existing) {
        logRequest('purchase', intentHash, false)
        send(res, 200, { ...existing, duplicate: true, resourceId: existing.id })
        return
      }
      if (typeof body.amount !== 'number' || !Number.isInteger(body.amount) || body.amount <= 0) {
        logRequest('purchase', intentHash, false)
        send(res, 400, { error: { code: 'invalid_amount', message: 'amount must be a positive integer of minor units' } })
        return
      }
      if (typeof body.category !== 'string' || typeof body.title !== 'string' || body.title.length > 120) {
        logRequest('purchase', intentHash, false)
        send(res, 400, { error: { code: 'invalid_purchase', message: 'purchase fields were rejected' } })
        return
      }
      const id = `pur_${randomBytes(8).toString('hex')}`
      const now = new Date().toISOString()
      db.prepare(
        'INSERT INTO purchases (id, intent_hash, category, amount, title, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      ).run(id, intentHash, body.category, body.amount, body.title, 'open', now)
      logRequest('purchase', intentHash, true)
      if (fault === 'timeout-after') await wait(faultMs, req)
      if (!res.writableEnded) {
        send(res, 201, {
          id,
          resourceId: id,
          category: body.category,
          amount: body.amount,
          title: body.title,
          status: 'open',
          duplicate: false,
        })
      }
      return
    }

    send(res, 404, { error: { code: 'not_found', message: 'not found' } })
  } catch (error) {
    if (!res.headersSent) {
      const status = typeof error?.status === 'number' ? error.status : 500
      send(res, status, { error: { code: 'sandbox_error', message: 'sandbox request failed' } })
    }
  }
})

server.requestTimeout = 20_000
server.listen(port, host, () => {
  const address = server.address()
  const bound = address && typeof address !== 'string' ? address.port : port
  process.stdout.write(`SANDBOX_READY ${bound}\n`)
})

function shutdown() {
  server.close(() => {
    try {
      db.close()
    } catch {
      // The process is exiting.
    }
    process.exit(0)
  })
  setTimeout(() => process.exit(0), 2000).unref()
}
process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)
