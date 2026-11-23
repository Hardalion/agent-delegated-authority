import type { Pool } from './pool.js'

export type GrantRevocationStatus = 'active' | 'revoked' | 'unavailable'

/**
 * Store-backed revocation for delegation ids. A read failure is `unavailable`,
 * which the authority path treats as BLOCK.
 */
export class PostgresGrantRevocation {
  constructor(
    private readonly pool: Pool,
    private readonly tenantId = 'default',
  ) {}

  async revoke(delegationId: string): Promise<void> {
    await this.pool.query(
      `INSERT INTO adap_revoked_grants (tenant_id, delegation_id)
       VALUES ($1, $2)
       ON CONFLICT (tenant_id, delegation_id) DO NOTHING`,
      [this.tenantId, delegationId],
    )
  }

  async check(delegationId: string): Promise<GrantRevocationStatus> {
    try {
      const { rows } = await this.pool.query<{ delegation_id: string }>(
        `SELECT delegation_id
         FROM adap_revoked_grants
         WHERE tenant_id = $1 AND delegation_id = $2`,
        [this.tenantId, delegationId],
      )
      return rows.length > 0 ? 'revoked' : 'active'
    } catch {
      return 'unavailable'
    }
  }
}
