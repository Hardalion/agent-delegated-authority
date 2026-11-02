import { createPool, type Pool } from './pool.js'
import { applyMigrations, rollbackMigrations } from './migrate.js'

export const DEFAULT_PG_URL =
  process.env.ADAP_PG_URL ?? 'postgresql://adap:adap@127.0.0.1:55432/adap'

export function postgresAvailable(): boolean {
  return process.env.ADAP_PG_URL != null || process.env.ADAP_PG_FORCE === '1'
}

export async function withFreshStore<T>(
  connectionString: string,
  fn: (pool: Pool) => Promise<T>,
): Promise<T> {
  const pool = createPool({ connectionString, max: 8 })
  try {
    await applyMigrations(pool)
    // Truncate between tests for isolation
    await pool.query(
      `TRUNCATE adap_nonces, adap_pending, adap_policies, adap_execution_log RESTART IDENTITY CASCADE`,
    )
    return await fn(pool)
  } finally {
    await pool.end()
  }
}

export async function resetSchema(pool: Pool): Promise<void> {
  await rollbackMigrations(pool)
  await applyMigrations(pool)
}
