#!/usr/bin/env node
import { createPool } from './pool.js'
import { applyMigrations, rollbackMigrations } from './migrate.js'

async function main(): Promise<void> {
  const url = process.env.ADAP_PG_URL
  if (!url) {
    console.error('ADAP_PG_URL is required')
    process.exit(1)
  }
  const cmd = process.argv[2] ?? 'up'
  const pool = createPool({ connectionString: url })
  try {
    if (cmd === 'up') {
      const applied = await applyMigrations(pool)
      console.log(JSON.stringify({ ok: true, applied }))
    } else if (cmd === 'down') {
      await rollbackMigrations(pool)
      console.log(JSON.stringify({ ok: true, rolledBack: '001_adap_store' }))
    } else {
      console.error('usage: migrate-cli [up|down]')
      process.exit(1)
    }
  } finally {
    await pool.end()
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err)
  process.exit(1)
})
