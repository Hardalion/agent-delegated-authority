import type {
  AsyncAtomicNonceBackend,
  NonceRecord,
  NonceStatus,
  VersionedNonceRecord,
} from 'adap'
import type { Pool } from './pool.js'

export interface PostgresNonceBackendOptions {
  readonly pool: Pool
  /** Tenant namespace for nonce keys. Default `default`. */
  readonly tenantId?: string
}

/**
 * PostgreSQL `AsyncAtomicNonceBackend`.
 *
 * Guarantees (when all gateway instances share this database):
 * - Primary key on `nonce` prevents dual insert.
 * - `UPDATE … WHERE version = $expected` is the compare half of CAS.
 * - A false return means no row was written.
 * - Rejected promises mean unknown outcome; callers must fail closed (no execute).
 *
 * Isolation: each compare-and-swap is one transaction (`BEGIN` … conditional
 * write … `COMMIT`/`ROLLBACK`) under READ COMMITTED. A false return means the
 * transaction rolled back and no row changed. Rows are never deleted.
 */
export class PostgresAtomicNonceBackend implements AsyncAtomicNonceBackend {
  private readonly pool: Pool
  private readonly tenantId: string

  constructor(options: PostgresNonceBackendOptions) {
    this.pool = options.pool
    this.tenantId = options.tenantId ?? 'default'
  }

  async read(nonce: string): Promise<VersionedNonceRecord | undefined> {
    const { rows } = await this.pool.query<{
      version: number
      status: NonceStatus
      intent_hash: string
      in_flight: boolean
    }>(
      `SELECT version, status, intent_hash, in_flight
       FROM adap_nonces
       WHERE nonce = $1 AND tenant_id = $2`,
      [nonce, this.tenantId],
    )
    const row = rows[0]
    if (!row) return undefined
    return {
      version: row.version,
      record: {
        status: row.status,
        intentHash: row.intent_hash,
        inFlight: row.in_flight,
      },
    }
  }

  async compareAndSwap(
    nonce: string,
    expectedVersion: number,
    record: NonceRecord,
  ): Promise<boolean> {
    if (expectedVersion < 0) return false
    const client = await this.pool.connect()
    try {
      await client.query('BEGIN')
      if (expectedVersion === 0) {
        const result = await client.query(
          `INSERT INTO adap_nonces (tenant_id, nonce, version, status, intent_hash, in_flight)
           VALUES ($1, $2, 1, $3, $4, $5)
           ON CONFLICT (tenant_id, nonce) DO NOTHING
           RETURNING nonce`,
          [this.tenantId, nonce, record.status, record.intentHash, record.inFlight],
        )
        if ((result.rowCount ?? 0) !== 1) {
          await client.query('ROLLBACK')
          return false
        }
        await client.query('COMMIT')
        return true
      }

      const result = await client.query(
        `UPDATE adap_nonces
         SET version = version + 1,
             status = $2,
             intent_hash = $3,
             in_flight = $4,
             updated_at = now()
         WHERE nonce = $1
           AND tenant_id = $5
           AND version = $6
         RETURNING nonce`,
        [nonce, record.status, record.intentHash, record.inFlight, this.tenantId, expectedVersion],
      )
      if ((result.rowCount ?? 0) !== 1) {
        await client.query('ROLLBACK')
        return false
      }
      await client.query('COMMIT')
      return true
    } catch (err) {
      try {
        await client.query('ROLLBACK')
      } catch {
        // ignore rollback errors
      }
      throw err
    } finally {
      client.release()
    }
  }
}
