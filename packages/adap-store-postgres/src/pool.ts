import pg from 'pg'

export type Pool = pg.Pool
export type PoolClient = pg.PoolClient

export interface CreatePoolOptions {
  readonly connectionString: string
  readonly max?: number
  readonly idleTimeoutMillis?: number
  readonly connectionTimeoutMillis?: number
  readonly statementTimeoutMs?: number
  /** Client-side query deadline. A paused database must not leave the call waiting. */
  readonly queryTimeoutMs?: number
}

/**
 * Connection pool for ADAP store adapters.
 * Failures must surface to callers; the authority path fails closed on store errors.
 */
export function createPool(options: CreatePoolOptions): Pool {
  const timeout = options.statementTimeoutMs
  const connectionString =
    timeout == null
      ? options.connectionString
      : appendStatementTimeout(options.connectionString, timeout)
  const pool = new pg.Pool({
    connectionString,
    max: options.max ?? 10,
    idleTimeoutMillis: options.idleTimeoutMillis ?? 10_000,
    connectionTimeoutMillis: options.connectionTimeoutMillis ?? 5_000,
    query_timeout: options.queryTimeoutMs,
  })
  pool.on('error', (err: Error & { code?: string }) => {
    const message = (err.message || 'pool client error').replace(/postgres:\/\/\S+/gi, 'postgres://redacted').slice(0, 160)
    console.error(JSON.stringify({
      channel: 'adap.security',
      type: 'storage.failure',
      code: err.code ?? null,
      message,
    }))
  })
  return pool
}

/** Apply statement_timeout at connect time so it cannot race a later query. */
function appendStatementTimeout(connectionString: string, timeoutMs: number): string {
  const ms = Math.floor(timeoutMs)
  if (!Number.isFinite(ms) || ms < 1) {
    throw new Error('statementTimeoutMs must be a positive integer')
  }
  const url = new URL(connectionString)
  const existing = url.searchParams.get('options') ?? ''
  const setting = `-c statement_timeout=${ms}`
  url.searchParams.set('options', existing.length > 0 ? `${existing} ${setting}` : setting)
  return url.toString()
}
