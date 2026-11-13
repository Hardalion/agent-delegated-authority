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

/** Pre-migration / global-nonce tombstone marker. Never assign to a live actor. */
export const LEGACY_NONCE_ACTOR_ID = ''

/**
 * PostgreSQL `AsyncAtomicNonceBackend` keyed by `(tenant_id, actor_id, nonce)`.
 *
 * Legacy rows with `actor_id = ''` are global nonce tombstones from the
 * pre–actor-scoped schema. They remain non-replayable for every actor:
 * `read` surfaces them so the ledger fails closed, and insert CAS refuses
 * to create an actor-scoped row for the same nonce while a tombstone exists.
 *
 * Guarantees (when all gateway instances share this database):
 * - Primary key on `(tenant_id, actor_id, nonce)` prevents dual insert.
 * - Insert paths lock and inspect the legacy tombstone before writing.
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
    const scoped = await this.pool.query<{
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
    const scopedRow = scoped.rows[0]
    if (scopedRow) {
      return {
        version: scopedRow.version,
        record: {
          status: scopedRow.status,
          intentHash: scopedRow.intent_hash,
          inFlight: scopedRow.in_flight,
          actorId: scopedRow.actor_id,
        },
      }
    }

    // Legacy global tombstone: surface so the ledger rejects reuse by any actor.
    const legacy = await this.pool.query<{
      version: number
      status: NonceStatus
      intent_hash: string
      in_flight: boolean
      actor_id: string
    }>(
      `SELECT version, status, intent_hash, in_flight, actor_id
       FROM adap_nonces
       WHERE nonce = $1 AND tenant_id = $2 AND actor_id = $3`,
      [nonce, this.tenantId, LEGACY_NONCE_ACTOR_ID],
    )
    const legacyRow = legacy.rows[0]
    if (!legacyRow) return undefined
    return {
      version: legacyRow.version,
      record: {
        status: legacyRow.status,
        intentHash: legacyRow.intent_hash,
        inFlight: legacyRow.in_flight,
        actorId: LEGACY_NONCE_ACTOR_ID,
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
    // Never mutate a legacy tombstone through an actor-scoped write.
    if (actorId === LEGACY_NONCE_ACTOR_ID) return false

    const client = await this.pool.connect()
    try {
      await client.query('BEGIN')
      if (expectedVersion === 0) {
        // Serialize against concurrent inserts and legacy tombstone inspection.
        await client.query(
          `SELECT pg_advisory_xact_lock(hashtextextended($1 || E'\\x1f' || $2, 0))`,
          [this.tenantId, nonce],
        )
        const tombstone = await client.query(
          `SELECT 1 FROM adap_nonces
           WHERE tenant_id = $1 AND nonce = $2 AND actor_id = $3
           FOR UPDATE`,
          [this.tenantId, nonce, LEGACY_NONCE_ACTOR_ID],
        )
        if ((tombstone.rowCount ?? 0) > 0) {
          await client.query('ROLLBACK')
          return false
        }
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
           AND actor_id <> $8
         RETURNING nonce`,
        [
          nonce,
          record.status,
          record.intentHash,
          record.inFlight,
          this.tenantId,
          actorId,
          expectedVersion,
          LEGACY_NONCE_ACTOR_ID,
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
