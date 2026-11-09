const port = process.env.ADAP_DEMO_PORT ?? '4317'
const passphrase = process.env.ADAP_APPROVER_PASSPHRASE || process.env.ADAP_DEMO_PASSPHRASE || ''
const token = process.env.ADAP_TEAM_TOKEN || ''
if (!passphrase || passphrase === 'treasury-demo' || !token || token === 'treasury-demo') {
  process.stderr.write('Set ADAP_TEAM_TOKEN and ADAP_APPROVER_PASSPHRASE. The console has no default password.\n')
  process.exit(1)
}
const base = `http://127.0.0.1:${port}`

const login = await fetch(`${base}/api/session`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ token }),
})
if (!login.ok) {
  process.stderr.write('Team sign-in failed. Reset was not attempted.\n')
  process.exit(1)
}
const cookie = (login.headers.getSetCookie?.() ?? []).map((value) => value.split(';')[0]).join('; ')
const response = await fetch(`${base}/api/reset`, {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    'x-adap-request': '1',
    cookie,
  },
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
