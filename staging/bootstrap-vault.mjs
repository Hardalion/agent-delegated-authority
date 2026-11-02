import { randomBytes } from 'node:crypto'
import { writeFileSync } from 'node:fs'

const address = process.env.VAULT_ADDR
const root = process.env.VAULT_DEV_ROOT_TOKEN_ID
const outDir = process.env.BOOTSTRAP_DIR ?? '/bootstrap'
if (!address || !root) {
  console.error(JSON.stringify({ type: 'bootstrap.missing_env' }))
  process.exit(1)
}

async function waitReady() {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      const res = await fetch(new URL('/v1/sys/health', address), { signal: AbortSignal.timeout(1000) })
      if (res.ok) return
    } catch {
      // vault is still starting
    }
    await new Promise((resolve) => setTimeout(resolve, 500))
  }
  throw new Error('vault did not become ready')
}

await waitReady()

const railToken = randomBytes(32).toString('hex')
const write = await fetch(new URL('/v1/secret/data/adap/rail', address), {
  method: 'POST',
  headers: { 'x-vault-token': root, 'content-type': 'application/json' },
  body: JSON.stringify({
    data: { token: railToken, writeUrl: 'http://downstream:8080/write' },
  }),
})
if (!write.ok) {
  console.error(JSON.stringify({ type: 'bootstrap.secret_write_failed', status: write.status }))
  process.exit(1)
}

const policy = await fetch(new URL('/v1/sys/policies/acl/adap-read', address), {
  method: 'PUT',
  headers: { 'x-vault-token': root, 'content-type': 'application/json' },
  body: JSON.stringify({
    policy: 'path "secret/data/adap/rail" { capabilities = ["read"] }\n',
  }),
})
if (!policy.ok) {
  console.error(JSON.stringify({ type: 'bootstrap.policy_failed', status: policy.status }))
  process.exit(1)
}

const created = await fetch(new URL('/v1/auth/token/create', address), {
  method: 'POST',
  headers: { 'x-vault-token': root, 'content-type': 'application/json' },
  body: JSON.stringify({ policies: ['adap-read'], ttl: '768h', renewable: false }),
})
if (!created.ok) {
  console.error(JSON.stringify({ type: 'bootstrap.token_failed', status: created.status }))
  process.exit(1)
}
const payload = await created.json()
const readToken = payload?.auth?.client_token
if (typeof readToken !== 'string' || readToken.length < 8) {
  console.error(JSON.stringify({ type: 'bootstrap.token_missing' }))
  process.exit(1)
}

writeFileSync(`${outDir}/read-token`, readToken, { mode: 0o600 })
writeFileSync(`${outDir}/ready`, 'ok')
console.error(JSON.stringify({ type: 'bootstrap.ready' }))
