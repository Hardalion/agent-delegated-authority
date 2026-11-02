import { readdir, readFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Pool } from './pool.js'

const here = dirname(fileURLToPath(import.meta.url))
const migrationsDir = join(here, '..', 'migrations')

async function sqlFiles(kind: 'up' | 'down'): Promise<string[]> {
  const names = await readdir(migrationsDir)
  const selected = names.filter((name) =>
    kind === 'up'
      ? name.endsWith('.sql') && !name.includes('rollback')
      : name.endsWith('_rollback.sql'),
  )
  selected.sort()
  if (kind === 'down') selected.reverse()
  return selected
}

export async function applyMigrations(pool: Pool): Promise<readonly string[]> {
  for (const name of await sqlFiles('up')) {
    const sql = await readFile(join(migrationsDir, name), 'utf8')
    await pool.query(sql)
  }
  const { rows } = await pool.query<{ id: string }>(
    'SELECT id FROM adap_schema_migrations ORDER BY id',
  )
  return rows.map((row) => row.id)
}

export async function rollbackMigrations(pool: Pool): Promise<void> {
  for (const name of await sqlFiles('down')) {
    const sql = await readFile(join(migrationsDir, name), 'utf8')
    await pool.query(sql)
  }
}
