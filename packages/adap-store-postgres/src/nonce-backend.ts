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
 * PostgreSQL `AsyncAtomicNonceBackend` keyed by `(tenant_id, actor_id, nonce)`.
 *
 * Guarantees (when all gateway instances share this database):
 * - Primary key on `(tenant_id, actor_id, nonce)` prevents dual insert.
 * - `UPDATE … WHERE version = $expected` is the compare half of CAS.
 * - A false return means no row was written.
 * - Rejected promises mean unknown outcome; callers must fail closed (no execute).
 */
export class PostgresAtomicNonceBackend implements AsyncAtomicNonceBackend {
  private readonly pool: Pool
  private readonly tenantId: string

  constructor(options: PostgresNonceBackendOptions) {
    this.pool = options.pool
    this.tenantId = options.tenantId ?? 'default'
  }

  async read(actorId: string, nonce: string): Promise<VersionedNonceRecord | undefined> {
    const { rows } = await this.pool.query<{
      version: number
      status: NonceStatus
      intent_hash: string
      in_flight: boolean
      actor_id: string
    }>(
      `SELECT version, status, intent_hash, in_flight, actor_id
       FROM adap_nonces
       WHERE nonce = $1 AND tenant_id = $2 AND actor_id = $3`,
      [nonce, this.tenantId, actorId],
    )
    const row = rows[0]
    if (!row) return undefined
    return {
      version: row.version,
      record: {
        status: row.status,
        intentHash: row.intent_hash,
        inFlight: row.in_flight,
        actorId: row.actor_id,
      },
    }
  }

  async compareAndSwap(
    actorId: string,
    nonce: string,
    expectedVersion: number,
    record: NonceRecord,
  ): Promise<boolean> {
    if (expectedVersion < 0) return false
    if (record.actorId !== actorId) return false
    const client = await this.pool.connect()
    try {
      await client.query('BEGIN')
      if (expectedVersion === 0) {
        const result = await client.query(
          `INSERT INTO adap_nonces (tenant_id, actor_id, nonce, version, status, intent_hash, in_flight)
           VALUES ($1, $2, $3, 1, $4, $5, $6)
           ON CONFLICT (tenant_id, actor_id, nonce) DO NOTHING
           RETURNING nonce`,
          [this.tenantId, actorId, nonce, record.status, record.intentHash, record.inFlight],
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
           AND actor_id = $6
           AND version = $7
         RETURNING nonce`,
        [
          nonce,
          record.status,
          record.intentHash,
          record.inFlight,
          this.tenantId,
          actorId,
          expectedVersion,
        ],
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
