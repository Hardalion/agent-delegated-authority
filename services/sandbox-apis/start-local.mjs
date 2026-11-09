/**
 * Starts one local sandbox API and one console, both bound to 127.0.0.1.
 * Prints generated credentials once. Does not write them to disk.
 */
import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { mkdirSync } from 'node:fs'

const sandboxToken = process.env.ADAP_SANDBOX_TOKEN || randomBytes(24).toString('base64url')
const port = process.env.SANDBOX_PORT || '4318'
mkdirSync('.demo', { recursive: true })

const sandbox = spawn(process.execPath, ['services/sandbox-apis/server.mjs'], {
  stdio: 'inherit',
  env: {
    ...process.env,
    SANDBOX_TOKEN: sandboxToken,
    SANDBOX_PORT: port,
    SANDBOX_DB: process.env.SANDBOX_DB || '.demo/hackathon-sandbox.sqlite',
    SANDBOX_FAULTS: '0',
  },
})

const consoleApp = spawn('pnpm', ['--filter', 'adap-hackathon-console', 'start'], {
  stdio: 'inherit',
  shell: true,
  env: {
    ...process.env,
    ADAP_DEPLOYMENT: 'local',
    ADAP_SANDBOX_URL: `http://127.0.0.1:${port}`,
    ADAP_SANDBOX_TOKEN: sandboxToken,
    ADAP_DEMO_PORT: process.env.ADAP_DEMO_PORT || '4317',
    ADAP_BIND_HOST: '127.0.0.1',
  },
})

function shutdown() {
  sandbox.kill()
  consoleApp.kill()
}
process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)
sandbox.on('exit', (code) => {
  consoleApp.kill()
  process.exit(code ?? 0)
})
consoleApp.on('exit', (code) => {
  sandbox.kill()
  process.exit(code ?? 0)
})
