import { createDemoServer } from './server.js'
import { demoEnvFromProcess } from './guard.js'
import { DemoRuntime } from './runtime.js'
import { HttpSandboxAdapter } from './adapters/http-sandbox.js'
import { ConsoleSecurity, loadDeploymentConfig, securityLog } from './security.js'

const config = loadDeploymentConfig(process.env)
const env = demoEnvFromProcess(process.env)
const sandbox =
  config.sandboxUrl && config.sandboxToken
    ? new HttpSandboxAdapter({
        baseUrl: config.sandboxUrl,
        token: config.sandboxToken,
        faults: process.env.SANDBOX_FAULTS === '1',
      })
    : undefined
if (config.deployment === 'hosted' && !sandbox) {
  process.stderr.write('Hosted mode requires a sandbox API.\n')
  process.exit(1)
}

const runtime = new DemoRuntime({
  env,
  passphrase: config.approverPassphrase,
  teamId: config.teamId,
  sandbox,
})
const server = createDemoServer(runtime, new ConsoleSecurity(config))

server.on('error', (error: NodeJS.ErrnoException) => {
  const code = error.code ?? 'error'
  process.stderr.write(`Hackathon console failed to start (${code}).\n`)
  process.exit(1)
})

let shuttingDown = false
function shutdown() {
  if (shuttingDown) return
  shuttingDown = true
  server.close(() => {
    void sandbox?.close().finally(() => process.exit(0))
  })
  setTimeout(() => process.exit(0), 5_000).unref()
}
process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)

server.listen(config.port, config.bindHost, () => {
  const rail = sandbox ? 'local sandbox API' : 'process memory (simulated rail)'
  process.stdout.write(
    `ADAP hackathon sandbox http://${config.bindHost}:${config.port} team=${config.teamId} rail=${rail}. Synthetic records only. No real money.\n`,
  )
  if (config.generatedSecrets) {
    securityLog('startup.generated_secrets', { teamId: config.teamId })
    process.stdout.write('Generated local credentials. They are not written to disk.\n')
    process.stdout.write(`ADAP_TEAM_ID=${config.teamId}\n`)
    process.stdout.write(`ADAP_TEAM_TOKEN=${config.teamToken}\n`)
    process.stdout.write(`ADAP_APPROVER_PASSPHRASE=${config.approverPassphrase}\n`)
  }
})
