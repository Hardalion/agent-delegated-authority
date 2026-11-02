import { createDemoServer } from './server.js'
import { demoEnvFromProcess } from './guard.js'
import { DemoRuntime } from './runtime.js'

const env = demoEnvFromProcess(process.env)
const runtime = new DemoRuntime({
  env,
  passphrase: process.env.ADAP_DEMO_PASSPHRASE || 'treasury-demo',
})
const port = Number(process.env.ADAP_DEMO_PORT ?? 4317)
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  process.stderr.write('ADAP_DEMO_PORT is not a valid port.\n')
  process.exit(1)
}

const server = createDemoServer(runtime)
server.on('error', (error: NodeJS.ErrnoException) => {
  const code = error.code ?? 'error'
  process.stderr.write(`Demo server failed to start (${code}).\n`)
  process.exit(1)
})
server.listen(port, '127.0.0.1', () => {
  process.stdout.write(
    `ADAP hackathon console http://127.0.0.1:${port} — simulated payment rail, demo environment\n`,
  )
})
