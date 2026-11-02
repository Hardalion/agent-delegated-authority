const port = process.env.ADAP_DEMO_PORT ?? '4317'
const passphrase = process.env.ADAP_DEMO_PASSPHRASE || 'treasury-demo'
const base = `http://127.0.0.1:${port}`

const response = await fetch(`${base}/api/reset`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    confirm: 'RESET HACKATHON DEMO',
    passphrase,
    acknowledgeExport: true,
  }),
})

const body: unknown = await response.json().catch(() => null)
const record = body != null && typeof body === 'object' ? (body as { error?: { message?: string }; file?: string }) : null
if (!response.ok) {
  const message = record?.error?.message || 'Demo reset failed. Start the console first with pnpm demo:up.'
  process.stderr.write(`${message}\n`)
  process.exit(1)
}

process.stdout.write('Hackathon demo reset. Evidence was exported before the fixtures were restored.\n')
if (record?.file) process.stdout.write(`Export file: ${record.file}\n`)
